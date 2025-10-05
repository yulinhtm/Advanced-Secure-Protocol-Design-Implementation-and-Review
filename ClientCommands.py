# ClientCommands.py
"""
ClientCommands - implements /list, /tell, /file according to SOCP (secure variant).
- get_recipient_pubkey reads pubkey from local SQLite 'user.db' users.pubkey (base64url DER).
- do_tell signs content_sig = PSS-SHA256( SHA256(ciphertext_b64 || from || to || ts) )
- do_file signs manifest and each chunk (chunk_sig) over canonical JSON of chunk-info.
"""

import os
import time
import json
import base64
import hashlib
import sqlite3
import asyncio
from typing import Optional

import crypto_utils as cu

MAX_RSA_PLAINTEXT = 446  # RSA-4096 OAEP SHA-256 max plaintext bytes

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')

def _b64url_decode(s: str) -> bytes:
    padding = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)

def _now_ms() -> int:
    return int(time.time() * 1000)

class ClientCommands:
    def __init__(self, ws, user_id: str, privkey, db_path: str = "user.db"):

        self.ws = ws
        self.user_id = user_id
        self.privkey = privkey
        self.db_path = db_path

    # ---------------- helper: lookup recipient public key from local DB ----------------
    def get_recipient_pubkey_sync(self, recipient_id: str):
        """
        Synchronous retrieval helper used by async wrapper.
        Expects table `users` with column `pubkey` storing base64url DER.
        Returns cryptography RSAPublicKey.
        Raises ValueError if not found or parse fails.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT pubkey FROM users WHERE user_id = ?", (recipient_id,))
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"Pubkey for {recipient_id} not found in {self.db_path}")
                pub_b64 = row[0]
                # use crypto_utils to deserialize
                pubkey = cu.deserialize_publickey(pub_b64)
                return pubkey
        except sqlite3.Error as e:
            raise ValueError(f"DB error while fetching pubkey for {recipient_id}: {e}")

    async def get_recipient_pubkey(self, recipient_id: str):
        """
        Async wrapper; currently performs synchronous DB I/O.
        You may replace this with an async DB call or a server query.
        """
        return self.get_recipient_pubkey_sync(recipient_id)

    # ---------------- /list ----------------
    async def do_list(self):
        env = {
            "type": "LIST_REQUEST",
            "from": self.user_id,
            "to": "*",
         "ts": cu.int_ts_ms(),
            "payload": {}
        }
        await self.ws.send(json.dumps(env))
        print("[CLIENT] /list 已发送")

    # ---------------- /tell (end-to-end) ----------------
    async def do_tell(self, recipient_id: str, plaintext: str, recipient_pub=None):
        """
        Send an E2E encrypted direct message.
        recipient_pub: optional RSAPublicKey; if omitted, will look it up in DB.
        """
        if recipient_pub is None:
            recipient_pub = await self.get_recipient_pubkey(recipient_id)
        if recipient_pub is None:
            raise ValueError("recipient public key unavailable")

        # encrypt with recipient pubkey
        ciphertext = cu.rsa_oaep_encrypt(recipient_pub, plaintext.encode('utf-8'))
        ciphertext_b64 = _b64url_encode(ciphertext)
        ts = _now_ms()

        # compute content_sig: sign(SHA256(ciphertext_b64||from||to||ts))
        sig_input = (ciphertext_b64 + self.user_id + recipient_id + str(ts)).encode('utf-8')
        digest = hashlib.sha256(sig_input).digest()
        content_sig = cu.sign_payload(self.privkey, digest)

        payload = {
            "ciphertext": ciphertext_b64,
            "sender_pub": cu.serialize_publickey(self.privkey.public_key()),
            "content_sig": content_sig
        }

        env = {
            "type": "MSG_DIRECT",
            "from": self.user_id,
            "to": recipient_id,
            "ts": ts,
            "payload": payload
        }
        await self.ws.send(json.dumps(env))

    # ---------------- /file (manifest + chunk_sig) ----------------
    async def do_file(self, recipient_id: str, filepath: str, recipient_pub=None, mode: str = "dm"):
        """
        Send file in three phases:
          FILE_START: manifest + manifest_sig (canonical JSON signed)
          FILE_CHUNK: ciphertext (RSA-OAEP using recipient_pub) + chunk_sig (PSS over canonical JSON of chunk info)
          FILE_END
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(filepath)

        if recipient_pub is None:
            recipient_pub = await self.get_recipient_pubkey(recipient_id)
        if recipient_pub is None:
            raise ValueError("recipient public key unavailable")

        file_id = str(time.time_ns())
        name = os.path.basename(filepath)
        size = os.path.getsize(filepath)

        manifest = {
            "file_id": file_id,
            "name": name,
            "size": size,
            "mode": mode
        }
        manifest_bytes = cu.canonical_json(manifest).encode('utf-8')
        manifest_sig = cu.sign_payload(self.privkey, manifest_bytes)

        start_msg = {
            "type": "FILE_START",
            "from": self.user_id,
            "to": recipient_id,
            "ts": _now_ms(),
            "payload": {
                **manifest,
                "manifest_sig": manifest_sig,
                # 修正：序列化自己的 “公钥对象”
                "sender_pub": cu.serialize_publickey(self.privkey.public_key())
            }
        }
        await self.ws.send(json.dumps(start_msg))

        # send chunks
        with open(filepath, "rb") as f:
            idx = 0
            while True:
                chunk = f.read(MAX_RSA_PLAINTEXT)
                if not chunk:
                    break
                ciph = cu.rsa_oaep_encrypt(recipient_pub, chunk)
                ciph_b64 = _b64url_encode(ciph)

                # chunk_sig: sign canonical_json of {file_id, index, ciphertext}
                chunk_info = {"file_id": file_id, "index": idx, "ciphertext": ciph_b64}
                chunk_sig = cu.sign_payload(self.privkey, cu.canonical_json(chunk_info).encode('utf-8'))

                chunk_msg = {
                    "type": "FILE_CHUNK",
                    "from": self.user_id,
                    "to": recipient_id,
                    "ts": _now_ms(),
                    "payload": {
                        "file_id": file_id,
                        "index": idx,
                        "ciphertext": ciph_b64,
                        "chunk_sig": chunk_sig
                    }
                }
                await self.ws.send(json.dumps(chunk_msg))
                idx += 1

        end_msg = {
            "type": "FILE_END",
            "from": self.user_id,
            "to": recipient_id,
            "ts": _now_ms(),
            "payload": {"file_id": file_id}
        }
        await self.ws.send(json.dumps(end_msg))

    # ---------------- optional demo /all (UNSAFE) ----------------
    async def do_all_demo_broadcast(self, plaintext: str, group_id: str = "public"):
        """
        DEMO ONLY: broadcast plaintext (not secure). Prefer implementing channel keys.
        """
        ts = _now_ms()
        payload = {
            "plaintext": plaintext,
            "sender_pub": cu.serialize_publickey(self.privkey.public_key())
        }
        env = {
            "type": "MSG_PUBLIC_CHANNEL",
            "from": self.user_id,
            "to": group_id,
            "ts": ts,
            "payload": payload
        }
        await self.ws.send(json.dumps(env))

    # ---------------- low-level send ----------------
    async def send_envelope(self, env: dict, attach_transport_sig: bool = False):
        """
        If attach_transport_sig True: attach env['sig'] = sign(canonical_json(payload))
        """
        if attach_transport_sig:
            env["sig"] = cu.sign_payload(self.privkey, cu.canonical_json(env.get("payload", {})).encode('utf-8'))
        await self.ws.send(json.dumps(env))
