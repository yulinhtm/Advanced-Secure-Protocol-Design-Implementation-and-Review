import sqlite3
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import crypto_utils

DB_FILE = "user.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL,
            privkey_store TEXT NOT NULL,
            pake_password TEXT,
            meta TEXT,
            version INTEGER
        )
    """)
    conn.commit()
    return conn

def sign_payload(privkey, payload: dict) -> str:
    data = crypto_utils.canonical_json(payload).encode("utf-8")
    signature = privkey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

async def handle_user_hello(ws, message, db_conn, privkey, server_id, user_locations, local_users, servers):
    user_id = message.get("from")
    payload = message.get("payload", {})
    pubkey = payload.get("pubkey")
    pake_password = payload.get("pake_password", "")
    meta = payload.get("meta", {})

    cur = db_conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, pubkey, "", pake_password, json.dumps(meta), 1)
        )
        db_conn.commit()

    # 加入内存表
    user_locations[user_id] = "local"
    local_users[user_id] = ws

    # 广播 USER_ADVERTISE
    adv_payload = {"user_id": user_id, "server_id": server_id, "meta": meta}
    adv_msg = {
        "type": "USER_ADVERTISE",
        "from": server_id,
        "to": "*",
        "ts": int(time.time() * 1000),
        "payload": adv_payload
    }
    adv_msg["sig"] = sign_payload(privkey, adv_payload)

    for sid, link in servers.items():
        await link.send(json.dumps(adv_msg))

    # 给客户端回 ACK
    ack_payload = {"status": "ok"}
    ack_msg = {
        "type": "ACK",
        "from": server_id,
        "to": user_id,
        "ts": int(time.time() * 1000),
        "payload": ack_payload
    }
    ack_msg["sig"] = sign_payload(privkey, ack_payload)
    await ws.send(json.dumps(ack_msg))
