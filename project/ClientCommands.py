"""
Group 20:
Jiahui Wang a1822691
Yuxuan Wu a1898143
ShunChit Yu a1880719
Youqing Fu a1981355
Mo Yang a1932039
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

RSA_PLAINTEXT_LIMIT = 446  # RSA-4096 OAEP SHA-256 max plaintext bytes

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
    async def do_list(self, user_list):
        if isinstance(user_list, dict):
            for user_id, info in user_list.items():
                meta = info.get("meta", {})
                print(f"User ID: {user_id}, Meta: {meta}")
        elif isinstance(user_list, list):
            for user in user_list:
                uid = user.get("user_id")
                meta = user.get("meta", {})
                print(f"User ID: {uid}, Meta: {meta}")
        else:
            print("Unexpected list format:", user_list)
    # ---------------- /tell (end-to-end) ----------------
    async def do_tell(self, recipient_id: str, plaintext: str, recipient_pub_str=None):

        if recipient_pub_str is None:
            raise ValueError("recipient public key unavailable")
        recipient_pub = cu.deserialize_publickey(recipient_pub_str)

        # Encrypted text
        ciphertext = cu.rsa_oaep_encrypt(recipient_pub, plaintext.encode("utf-8"))
        # Use unified tools base64url
        ciphertext_b64 = cu.b64url_encode(ciphertext)

        # Sign with these values（And sent together with the payload to avoid being affected by the server changing the envelope）
        sig_from = self.user_id
        sig_to   = recipient_id
        sig_ts   = _now_ms()

        # sign( SHA256(ciphertext_b64 || sig_from || sig_to || sig_ts) )
        digest = hashlib.sha256(
            (ciphertext_b64 + sig_from + sig_to + str(sig_ts)).encode("utf-8")
        ).digest()
        content_sig = cu.sign_payload(self.privkey, digest)

        payload = {
            "ciphertext": ciphertext_b64,
            "sender_pub": cu.serialize_publickey(self.privkey.public_key()),
            "content_sig": content_sig,
            "sig_from": sig_from,
            "sig_to":   sig_to,
            "sig_ts":   sig_ts,
        }

        env = {
            "type": "MSG_DIRECT",
            "from": self.user_id,
            "to": recipient_id,
            "ts": _now_ms(),  
            "payload": payload
        }
        await self.ws.send(json.dumps(env))


    # ---------------- /file (DM + RSA) ----------------
    async def do_file(self, recipient_id: str, filepath: str, recipient_pub_str=None):

        if recipient_pub_str is None:
            raise ValueError("recipient public key unavailable")
        recipient_pub = cu.deserialize_publickey(recipient_pub_str)
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(filepath)

        # Get the receiver’s public key
        if recipient_pub is None:
            raise ValueError("recipient public key unavailable")

        file_id = str(time.time_ns())
        name    = os.path.basename(filepath)
        size    = os.path.getsize(filepath)

        # --- 1) Send FILE_START: Manifest + Signature ---
        manifest = {
            "file_id": file_id,
            "name":    name,
            "size":    size,
            "mode":    "dm-rsa",           # Annotation mode for easy debugging
            "chunk":   RSA_PLAINTEXT_LIMIT # Tell the peer how many chunks to use (plain text)
        }
        manifest_sig = cu.sign_payload(self.privkey, cu.canonical_json(manifest).encode("utf-8"))

        start_msg = {
            "type": "FILE_START",
            "from": self.user_id,
            "to":   recipient_id,
            "ts":   cu.int_ts_ms(),
            "payload": {
                **manifest,
                "manifest_sig": manifest_sig,
                "sender_pub":   cu.serialize_publickey(self.privkey.public_key()),
            }
        }
        await self.ws.send(json.dumps(start_msg))

        # --- 2) Divide into blocks according to the upper limit of RSA, send FILE_CHUNK after encryption ---
        sent = 0
        with open(filepath, "rb") as f:
            idx = 0
            while True:
                plain = f.read(RSA_PLAINTEXT_LIMIT)
                if not plain:
                    break

                ciph     = cu.rsa_oaep_encrypt(recipient_pub, plain)
                ciph_b64 = cu.b64url_encode(ciph)

                # Sign blocks: do RSASSA-PSS on canonical JSON of {file_id,index,ciphertext}
                chunk_info = {"file_id": file_id, "index": idx, "ciphertext": ciph_b64}
                chunk_sig  = cu.sign_payload(self.privkey, cu.canonical_json(chunk_info).encode("utf-8"))

                chunk_msg = {
                    "type": "FILE_CHUNK",
                    "from": self.user_id,
                    "to":   recipient_id,
                    "ts":   cu.int_ts_ms(),
                    "payload": {
                        **chunk_info,
                        "chunk_sig": chunk_sig
                    }
                }
                await self.ws.send(json.dumps(chunk_msg))
                sent += len(plain)
                idx  += 1

        # --- send FILE_END ---
        end_msg = {
            "type": "FILE_END",
            "from": self.user_id,
            "to":   recipient_id,
            "ts":   cu.int_ts_ms(),
            "payload": {"file_id": file_id}
        }
        await self.ws.send(json.dumps(end_msg))
        print(f"[/file] Sent {name} ({size} bytes) to {recipient_id} (DM-RSA)")

    async def do_all(self, text: str, group_id: str = "public"):

        ts = cu.int_ts_ms()
        from_uid = self.user_id

        # Content signature：SHA256(text || from || ts)
        dg = hashlib.sha256((text + from_uid + str(ts)).encode("utf-8")).digest()
        content_sig = cu.sign_payload(self.privkey, dg)

        payload = {
            "text":        text,
            "sender_pub":  cu.serialize_publickey(self.privkey.public_key()),
            "content_sig": content_sig,
            "sig_from":    from_uid,
            "sig_ts":      ts,
        }

        env = {
            "type":    "MSG_PUBLIC_CHANNEL",
            "from":    from_uid,
            "to":      group_id,   
            "ts":      ts,
            "payload": payload,
        }

        await self.ws.send(json.dumps(env))
        print(f"[/all] has been broadcast to {group_id}（Plain text + signature）")

    async def do_quit(self) -> None:

        try:
            env = {
                "type": "USER_LOGOUT",
                "from": self.user_id,
                "to":   "*",
                "ts":   cu.int_ts_ms(),
                "payload": {}
            }
            await self.ws.send(json.dumps(env))
        except Exception:
            pass
        try:
            await asyncio.sleep(0.1)   # Optional: Give the server processing time
        except Exception:
            pass


    # ---------------- low-level send ----------------
    async def send_envelope(self, env: dict, attach_transport_sig: bool = False):
        """
        If attach_transport_sig True: attach env['sig'] = sign(canonical_json(payload))
        """
        if attach_transport_sig:
            env["sig"] = cu.sign_payload(self.privkey, cu.canonical_json(env.get("payload", {})).encode('utf-8'))
        await self.ws.send(json.dumps(env))
