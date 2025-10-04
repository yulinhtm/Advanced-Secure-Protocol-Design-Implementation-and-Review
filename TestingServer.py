import asyncio
import websockets
import json
import sqlite3
import traceback
import time
import Heartbeats_Timeouts as hb





from cryptography.hazmat.primitives import serialization


import crypto_utils as cu
from server_handlers import ServerHandlers



# ===================== 配置 =====================
HOST = "localhost"
PORT = 8765
SERVER_NAME = "server-1"


servers = {}          # server_id -> ws
server_addrs = {}     # server_id -> (host, port)
local_users = {}      # user_id  -> ws
user_locations = {}   # user_id  -> "local" | server_id
servers = {}
server_addrs = {}
last_seen_times = {}

# ===================== 数据库 =====================
DB = "user.db"

def init_db():
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL,
            privkey_store TEXT NOT NULL,
            pake_password TEXT NOT NULL,
            meta TEXT,
            version INTEGER NOT NULL,
            salt TEXT
        )
        """)
        conn.commit()

def add_user(user_id, pubkey, privkey_store, pake_password, salt, meta=None, version=1):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (user_id, pubkey, privkey_store, pake_password, salt, meta, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, pubkey, privkey_store, pake_password, salt,
              json.dumps(meta) if isinstance(meta, dict) else meta, version))
        conn.commit()

def user_exists(user_id: str, display_name: str) -> bool:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM users WHERE user_id = ? OR json_extract(meta, '$.display_name') = ?",
            (user_id, display_name)
        )
        return cur.fetchone() is not None

def check_user_password(user_id: str, password: str) -> bool:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT pake_password, salt FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    if not row:
        return False
    stored_hash, salt = row
    if not salt:
        return False
    return cu.hash_password(password, salt) == stored_hash

def get_user_pubkey(user_id: str) -> str | None:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT pubkey FROM users WHERE user_id = ?", (user_id,))
        r = cur.fetchone()
        return r[0] if r else None

# ===================== WebSocket 发送统一封装 =====================
async def ws_send(link, message_str: str):
    try:
        await link.send(message_str)
    except Exception:
        traceback.print_exc()

# ===================== 载入 Server 密钥 & SERVER_ID =====================
def load_server_keys():
    with open("ServerStorage/private_key.pem", "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=b"my-password")
    with open("ServerStorage/public_key.pem", "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

# 先初始化数据库
init_db()
# 加载密钥/ID
private_key, public_key = load_server_keys()
SERVER_ID = cu.generate_server_id(SERVER_NAME)

# 实例化 handlers（处理 /list /tell /all /file）
handlers = ServerHandlers(
    ws_send_func=ws_send,
    local_users=local_users,
    user_locations=user_locations,
    servers=servers,
    server_addrs=server_addrs,
    privkey=private_key,
    server_id=SERVER_ID
)

# ===================== ACK / ERROR 生成（带签名） =====================
def create_ack(to_user: str, msg_ref: str):
    payload = {"msg_ref": msg_ref, "status": "ok"}
    env = {
        "type": "ACK",
        "from": SERVER_ID,
        "to": to_user,
        "ts": cu.int_ts_ms(),
        "payload": payload
    }
    env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8"))
    return env

def create_error(to_user: str, code: str, detail: str):
    payload = {"code": code, "detail": detail}
    env = {
        "type": "ERROR",
        "from": SERVER_ID,
        "to": to_user,
        "ts": cu.int_ts_ms(),
        "payload": payload
    }
    env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8"))
    return env

# ===================== 连接处理 =====================
async def handle_connection(ws):
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send(json.dumps(create_error("*", "INVALID_JSON", "JSON decoding failed")))
                continue

            mtype = msg.get("type")

            # ---------------- 注册 ----------------
            if mtype == "USER_REGISTER":
                user_id = msg.get("from")
                enc_payload = msg.get("payload", {})
                if not enc_payload:
                    await ws.send(json.dumps(create_error(user_id or "*", "NO_PAYLOAD", "missing payload")))
                    continue

                try:
                    payload = cu.decrypt_payload_fields(enc_payload, private_key)
                except Exception:
                    await ws.send(json.dumps(create_error(user_id or "*", "DECRYPT_FAIL", "payload decrypt fail")))
                    continue

                display_name = payload.get("display_name")
                pubkey = payload.get("pubkey")
                privkey_store = payload.get("privkey_store")
                plain_password = payload.get("plain_password")
                salt = payload.get("salt")

                if not all([display_name, pubkey, privkey_store, plain_password, salt]):
                    await ws.send(json.dumps(create_error(user_id or "*", "MISSING_FIELDS",
                                                          "display_name/pubkey/privkey_store/plain_password/salt required")))
                    continue

                # 校验 user_id 与 username 一致性
                calc_uid = cu.generate_user_id(display_name)
                if user_id != calc_uid:
                    await ws.send(json.dumps(create_error("*", "UID_MISMATCH", "user_id not match username")))
                    continue

                if user_exists(user_id, display_name):
                    await ws.send(json.dumps(create_error(user_id, "NAME_IN_USE", "username or user_id already exists")))
                    continue

                # 入库
                hashed = cu.hash_password(plain_password, salt)
                meta = {"display_name": display_name}
                add_user(user_id, pubkey, privkey_store, hashed, salt, meta, version=1)

                # 内存登记
                local_users[user_id] = ws
                user_locations[user_id] = "local"

                # ACK
                await ws.send(json.dumps(create_ack(user_id, "USER_REGISTER")))
                print(f"[REGISTER] user {user_id} ({display_name}) registered")

            # ---------------- 登录 ----------------
            elif mtype == "USER_HELLO":
                user_id = msg.get("from")
                enc_payload = msg.get("payload", {})
                if not enc_payload:
                    await ws.send(json.dumps(create_error(user_id or "*", "NO_PAYLOAD", "missing payload")))
                    continue

                try:
                    payload = cu.decrypt_payload_fields(enc_payload, private_key)
                except Exception:
                    await ws.send(json.dumps(create_error(user_id or "*", "DECRYPT_FAIL", "payload decrypt fail")))
                    continue

                pubkey = payload.get("pubkey")
                plain_password = payload.get("plain_password")
                if not all([pubkey, plain_password]):
                    await ws.send(json.dumps(create_error(user_id or "*", "MISSING_FIELDS", "pubkey/plain_password required")))
                    continue

                if not check_user_password(user_id, plain_password):
                    await ws.send(json.dumps(create_error(user_id, "USER_NOT_FOUND", "invalid username/password")))
                    continue

                if user_id in local_users:
                    await ws.send(json.dumps(create_error(user_id, "NAME_IN_USE", "user already logged in")))
                    continue

                # 登记在线
                local_users[user_id] = ws
                user_locations[user_id] = "local"

                # ACK
                await ws.send(json.dumps(create_ack(user_id, "USER_HELLO")))
                print(f"[LOGIN] user {user_id} logged in")

            # ---------------- 命令分发 ----------------
            elif mtype == "LIST_REQUEST":
                await handlers.handle_list_request(msg, ws)

            elif mtype == "MSG_DIRECT":
                await handlers.handle_msg_direct(msg, ws)

            elif mtype == "MSG_PUBLIC_CHANNEL":
                await handlers.handle_msg_public(msg, ws)

            elif mtype and mtype.startswith("FILE_"):
                await handlers.handle_file_transfer(msg, ws)

            else:
                to_user = msg.get("from") or "*"
                await ws.send(json.dumps(create_error(to_user, "UNKNOWN_TYPE", f"unsupported type {mtype}")))
    except websockets.ConnectionClosed:
        try:
            for uid, link in list(local_users.items()):
                if link is ws:
                    local_users.pop(uid, None)
                    user_locations.pop(uid, None)
                    print(f"[DISCONNECT] user {uid} offline")
        except Exception:
            pass
    except Exception:
        traceback.print_exc()






# --- NEW: Heartbeat and Monitoring Functions in Heartbeats_Timeouts.py---

hb.servers = servers
hb.server_addrs = server_addrs
hb.last_seen_times = last_seen_times
hb.SERVER_ID = SERVER_ID
hb.private_key = private_key
hb.sign_payload = cu.sign_payload  



# ===================== 启动 =====================
async def main():
    print("Starting background tasks for heartbeat and monitoring...")

    # 启动心跳与监控
    asyncio.create_task(hb.send_heartbeats_periodically())
    asyncio.create_task(hb.monitor_connections_periodically())

    # 启动主动连接到其它服务器
    for sid, addr in server_addrs.items():
        asyncio.create_task(hb.reconnect_to_server(sid, addr))

    # 启动监听
    async with websockets.serve(handle_connection, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever


    print(f"[BOOT] Server {SERVER_ID} starting at ws://{HOST}:{PORT}")
    async with websockets.serve(handle_connection, HOST, PORT):
        print(f"[RUNNING] ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

