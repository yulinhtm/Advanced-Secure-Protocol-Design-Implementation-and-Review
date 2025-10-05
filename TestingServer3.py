import asyncio
import websockets
import json
import sqlite3
import traceback
import yaml
import time

from cryptography.hazmat.primitives import serialization

import crypto_utils as cu
from server_handlers import ServerHandlers
from typing import Dict

import Heartbeats_Timeouts as hb





# ===================== 配置 =====================
HOST = "localhost"
SERVER_PORT = "8765"
SERVER_NAME = "server-1"
SERVER_ADDRESS = "0.0.0.0"
MAX_RSA_PLAINTEXT = 446


servers = {}          # server_id -> ws
# server_id (str or int) -> (host, port)
server_addrs: Dict[str, Dict[str, str]] = {}
server_pubkeys: Dict[str, str] = {}
server_addrs = {}     # server_id -> (host, port)
local_users = {}      # user_id  -> ws
user_locations = {}   # user_id  -> "local" | server_id

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
    
def load_bootstrap_list(path="bootstrap_servers.yaml"):
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("bootstrap_servers", [])

async def bootstrap_to_introducer(introducer):
    global SERVER_ID
    host = introducer["host"]
    port = introducer["port"]
    introducer_pubkey_b64 = introducer["pubkey"]
    # Decode base64url to DER
    der_bytes = cu.base64.urlsafe_b64decode(introducer_pubkey_b64 + "==")

    # Load into real RSAPublicKey object
    introducer_pubkey = serialization.load_der_public_key(der_bytes)
    print(f"Trying introducer {host}:{port} ...")

    uri = f"ws://{host}:{port}"
    pubkey_str = cu.serialize_publickey(public_key)

    try:
        async with websockets.connect(uri) as ws:
            payload_fields = {
                "host": SERVER_ADDRESS,
                "port": SERVER_PORT,
                "pubkey": pubkey_str
            }

            encrypted_payload = cu.encrypt_payload_fields(payload_fields, introducer_pubkey, MAX_RSA_PLAINTEXT)
            canonical_bytes = json.dumps(encrypted_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            sig = cu.sign_payload(private_key, canonical_bytes)

            hello_msg = {
                "type": "SERVER_HELLO_JOIN",
                "from": SERVER_ID,
                "to": f"{host}:{port}",
                "ts": int(time.time() * 1000),
                "payload": encrypted_payload,
                "sig": sig
            }

            await ws.send(json.dumps(hello_msg))
            
            response_raw = await ws.recv()
            try:
                response = json.loads(response_raw)     # convert to dict
            except json.JSONDecodeError:
                print("Invalid JSON received:", response_raw)
                return False
            
            payload_encrypted = response.get("payload", {})

            if not payload_encrypted:
                print("No payload for introducer")
                return False
            
            payload = {}
            try:
                payload = cu.decrypt_payload_fields(payload_encrypted, private_key)
                
            except Exception as e:
                print("Decrypt failed")
                print("Decrypt failed!")
                print("Exception type:", type(e).__name__)
                print("Exception message:", str(e))
                print("Traceback:")
                traceback.print_exc()
                return False
            
            payload_extracted, sig_extracted = cu.extract_payload_and_signature(response)

            if cu.verify_json_signature(introducer_pubkey, payload_extracted, sig_extracted):
                print("Signature is valid\n")
                if response.get("type") == "SERVER_WELCOME":
                    print("Valid response from introducer:", response.get("type"))
                    assigned_id = payload.get("assigned_id")
                    server_list = payload.get("clients", [])
                    SERVER_ID = assigned_id
                    for client in server_list:
                        # Ensure client is a dictionary
                        if isinstance(client, dict):
                            user_id = client.get("user_id")
                            host = client.get("host")
                            port = client.get("port")
                            pubkey = client.get("pubkey")

                            # Only store if user_id, host, and port exist
                            if user_id and host and port:
                                server_addrs[user_id] = {
                                    "host": host,
                                    "port": port
                                }
                                if pubkey:
                                    server_pubkeys[user_id] = pubkey
                    
                    Success = await broadcast_server_announce( private_key, pubkey_str)
                    
                elif response.get("type") == "ERROR":
                    print("Introducer returned an error:", response.get("message"))
                    return False
            else:
                print("Signature is INVALID")


            await ws.close(code=1000, reason="Server shutting down")
            return Success

    except Exception as e:
        print(f"Failed to connect to introducer {host}:{port}: {e}")
        return False


async def bootstrap_from_yaml(yaml_path="bootstrap_servers.yaml"):
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)

    bootstrap_list = config.get("bootstrap_servers", [])

    for introducer in bootstrap_list:
        success = await bootstrap_to_introducer(introducer)
        if success:
            print("Connect to a introducers succesfully and able to broadcast to other server successfully")
            return True

    print("Failed to connect to all introducers.")
    return False

async def broadcast_server_announce( private_key, pubkey_str):
    Success = True
    for server_id, info in server_addrs.items():
        try:
            host = info.get("host")  # safer access
            port = info.get("port")
            uri = f"ws://{host}:{int(port)}"
            async with websockets.connect(uri) as ws:
                payload_fields = {
                    "host": SERVER_ADDRESS,  # your server's IP
                    "port": SERVER_PORT,  # your server's WS port
                    "pubkey": pubkey_str
                }

                # Encrypt payload if needed
                encrypted_payload = cu.encrypt_payload_fields(payload_fields, server_pubkeys[server_id], MAX_RSA_PLAINTEXT)
                
                # Prepare signature
                canonical_bytes = json.dumps(encrypted_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
                sig = cu.sign_payload(private_key, canonical_bytes)

                announce_msg = {
                    "type": "SERVER_ANNOUNCE",
                    "from": SERVER_ID,
                    "to": server_id,
                    "ts": int(time.time() * 1000),
                    "payload": encrypted_payload,
                    "sig": sig
                }

                await ws.send(json.dumps(announce_msg))
                print(f"SERVER_ANNOUNCE sent to {server_id} at {host}:{port}")
                
                response_raw = await ws.recv()
                try:
                    response = json.loads(response_raw)     # convert to dict
                except json.JSONDecodeError:
                    print("Invalid JSON received:", response_raw)
                    Success = False
                
                payload_extracted, sig_extracted = cu.extract_payload_and_signature(response)

                if cu.verify_json_signature(server_pubkeys[server_id], payload_extracted, sig_extracted):
                    print("Signature is valid\n")
                    if response.get("type") == "ACK":
                        print("Server responded with ACK")
                        print("Server response:", payload_extracted) 
                        servers[server_id] = ws
                    else:
                        print("Server response:", payload_extracted)
                        Success = False
                else:
                    print("Signature is INVALID")
                    Success = False

        except Exception as e:
            print(f"Failed to send SERVER_ANNOUNCE to {server_id} at {host}:{port}: {e}")
            Success = False
    return Success
    

def get_display_name(user_id: str) -> str:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT json_extract(meta, '$.display_name') FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    return row[0] if row and row[0] else user_id


# ===================== WebSocket 发送统一封装 =====================
async def ws_send(link, message_str: str):
    try:
        await link.send(message_str)
    except Exception:
        traceback.print_exc()

# ===================== 载入 Server 密钥 & SERVER_ID =====================
def load_server_keys():
    with open("ServerStorage/private_key.der", "rb") as f:
        priv = serialization.load_der_private_key(f.read(), password=b"my-password")
    with open("ServerStorage/public_key.der", "rb") as f:
        pub = serialization.load_der_public_key(f.read())
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
    server_id=SERVER_ID,
    resolve_username=get_display_name,
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

                 # --- NEW: 收到任何 frame 就刷新对方的 last_seen ---
                from_id = msg.get("from")
                if from_id:
                    try:
                        hb.mark_peer_seen(from_id)
                    except Exception:
                        # 防守：如果 hb 未注入或函数不可用，不要让整个 handler 崩溃
                        pass
            # -------------------------------------------------------

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

            elif mtype == "SERVER_ANNOUNCE":
                announcing_server_id = msg.get("from")
                payload_encrypted = msg.get("payload", {})

                if not payload_encrypted:
                    error_message = cu.create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                payload = {}
                try:
                    payload = cu.decrypt_payload_fields(payload_encrypted, private_key)
                except Exception as e:
                    error_message = cu.create_error_message(private_key, "DECRYPT_FAIL", "Decryption failed", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                announced_host = payload.get("host")
                announced_port = payload.get("port")
                announced_pubkey = payload.get("pubkey")

                payload_extracted, sig_extracted = cu.extract_payload_and_signature(msg)
                if cu.verify_json_signature(announced_pubkey, payload_extracted, sig_extracted):
                    print(f"SERVER_ANNOUNCE from {announcing_server_id} signature is valid")
                else:
                    print(f"SERVER_ANNOUNCE from {announcing_server_id} signature is INVALID")
                    error_message = cu.create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                
                if announcing_server_id in servers:
                    print(f"Server ID {announcing_server_id} already exists.")
                    error_message = cu.create_error_message(private_key, "NAME_IN_USE", "Same server id alraedy exist", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    print(f"Server ID {announcing_server_id} is new.")

                # Update server_addrs and server_pubkeys for easy access
                server_addrs[announcing_server_id] = {
                    "host": announced_host,
                    "port": announced_port
                }
                server_pubkeys[announcing_server_id] = announced_pubkey
                servers[announcing_server_id] = ws
                
                # ACK
                ack_msg = cu.create_ack_message(private_key, "SERVER_ANNOUNCE", SERVER_ID, announcing_server_id)
                await ws.send(json.dumps(ack_msg))

                print(f"Server {announcing_server_id} registered/updated successfully")

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
async def main():

    hb.servers = servers
    hb.server_addrs = server_addrs
    hb.last_seen_times = {}    # 初始空字典
    hb.SERVER_ID = None  

    print("Starting server...")

    # 使用 async with 启动 websockets 服务器（监听所有网卡）
    async with websockets.serve(handle_connection, SERVER_ADDRESS, int(SERVER_PORT)):
        print(f"Server running on ws://{SERVER_ADDRESS}:{SERVER_PORT}")

        # 启动背景任务（心跳与连接监控）
        asyncio.create_task(hb.send_heartbeats_periodically())
        asyncio.create_task(hb.monitor_connections_periodically())

        # 给 background tasks 一点时间稳定（可选）
        await asyncio.sleep(0.5)

        # 尝试从 bootstrap 文件连接 introducers；用 try/except 防止文件不存在导致退出
        try:
            success = await bootstrap_from_yaml()
        except FileNotFoundError:
            print("bootstrap_servers.yaml not found; skipping bootstrap")
            success = False
        except Exception as e:
            print("bootstrap_from_yaml error:", repr(e))
            success = False

        print("Bootstrap success:", success)

        # 永远运行直到进程被终止
        await asyncio.Future()









# ===================== 启动 =====================

    success = await (bootstrap_from_yaml())
    print("Success or Not:", success)
    async with websockets.serve(handle_connection, SERVER_ADDRESS, int(SERVER_PORT)):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
