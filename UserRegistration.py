#code still not confirmed!!!!!!
import json
import uuid
import asyncio
import sqlite3
import base64
import string
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

#config(may move to other place later)
SERVER_ID = "ID12345"

# Database Model
conn = sqlite3.connect("user.db")
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    privkey_store TEXT NOT NULL,
    pake_password TEXT NOT NULL,
    meta TEXT,
    version INTEGER NOT NULL
)
""")
conn.commit()

servers = {}          # server_id -> WebSocket connection (Link wrapper)
server_addrs = {}     # server_id -> (host, port)
local_users = {}        # user_id -> WebSocket link
user_locations = {}     # user_id -> "local" | server_id

# ---------------------
# Helpers
# ---------------------
def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_nopad_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem: s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

# both function is need to later json use

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    # PBKDF2 with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(password.encode())

# checking....
async def send_error(ws, user_id, code, detail):
    error_msg = {
        "type": "ERROR",
        "from": SERVER_ID,
        "to": user_id,
        "ts": int(asyncio.get_event_loop().time() * 1000),
        "payload": {"code": code, "detail": detail},
        "sig": ""
    }
    await ws.send(json.dumps(error_msg))

def sign_payload(payload):
    # Canonical JSON sort keys, convert to bytes, sign with server RSA key
    # Placeholder: return empty string for now
    return ""
    
async def broadcast_to_servers(msg):
    # Send to all connected servers
    for server_id, ws in servers.items():
        await ws.send(json.dumps(msg))

async def handle_user_hello(ws, message, db_conn):
    user_id = message['from']
    pubkey = message['payload']['pubkey']
    enc_pubkey = message['payload'].get('enc_pubkey', pubkey)
    meta = message['payload'].get('meta', {})
    
    # 1. Check duplicate locally
    if user_id in local_users:
        await send_error(ws, user_id, "NAME_IN_USE", "User ID already registered locally")
        return
    
    # 2. Store in database (or fetch if exists)
    cur = db_conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE user_id=%s", (user_id,))
    if cur.fetchone():
        await send_error(ws, user_id, "NAME_IN_USE", "User ID already exists in database")
        return
    
    # Generate placeholder for encrypted private key & PAKE verifier
    privkey_store = "ENCRYPTED_PRIVKEY_PLACEHOLDER"
    pake_password = "PAKE_HASH_PLACEHOLDER"
    
    cur.execute(
        "INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version) VALUES (%s,%s,%s,%s,%s,%s)",
        (user_id, pubkey, privkey_store, pake_password, json.dumps(meta), 1)
    )
    db_conn.commit()
    
    # 3. Add to in-memory tables
    local_users[user_id] = ws
    user_locations[user_id] = "local"
    
    # 4. Broadcast USER_ADVERTISE to other servers
    advertise_payload = {
        "user_id": user_id,
        "server_id": SERVER_ID,  # your server UUID
        "meta": meta
    }
    advertise_message = {
        "type": "USER_ADVERTISE",
        "from": SERVER_ID,
        "to": "*",
        "ts": int(asyncio.get_event_loop().time() * 1000),
        "payload": advertise_payload,
        "sig": sign_payload(advertise_payload)  # implement server transport signature
    }
    await broadcast_to_servers(advertise_message)
    
    # 5. Send ACK to client (optional)
    ack = {"type": "ACK", "from": SERVER_ID, "to": user_id, "ts": int(asyncio.get_event_loop().time() * 1000), "payload": {"msg_ref": "USER_HELLO"}, "sig": ""}
    await ws.send(json.dumps(ack))
