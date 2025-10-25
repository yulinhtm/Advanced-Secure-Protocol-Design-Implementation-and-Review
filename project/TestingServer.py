import asyncio
import websockets
import json
import sqlite3
import traceback
import yaml
import time

# top of file
import argparse, os

from cryptography.hazmat.primitives import serialization

import crypto_utils as cu
from server_handlers import ServerHandlers
from typing import Dict

# ===================== 配置 =====================
HOST = "localhost"
SERVER_PORT = "8765"
SERVER_NAME = "server-1"
SERVER_ADDRESS = "127.0.0.1"
MAX_RSA_PLAINTEXT = 446


servers = {}          # server_id -> ws
# server_id (str or int) -> (host, port)
server_addrs: Dict[str, Dict[str, str]] = {}
server_pubkeys: Dict[str, str] = {}
server_addrs = {}     # server_id -> (host, port)
server_users = {}
local_users = {}      # user_id  -> ws
user_locations = {}   # user_id  -> "local" | server_id


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.getenv("SRV_HOST", "localhost"))     # listen host
    p.add_argument("--addr", default=os.getenv("SRV_ADDR", "127.0.0.1"))     # advertised address
    p.add_argument("--port", type=int, default=int(os.getenv("SRV_PORT", "8765")))
    p.add_argument("--name", default=os.getenv("SRV_NAME", "server-1"))
    p.add_argument("--bootstrap", default=os.getenv("BOOTSTRAP_YAML", "bootstrap_servers.yaml"))
    p.add_argument("--password", default=os.getenv("Fake"))
    return p.parse_args()

args = parse_args()

HOST = args.host
SERVER_ADDRESS = args.addr
SERVER_PORT = str(args.port)      # keep type consistent with your code
SERVER_NAME = args.name
BOOTSTRAP_YAML = args.bootstrap
SERVER_PASSWORD = args.password

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
                    print("server_list")
                    print(server_list)
                    for client in server_list:
                        # Ensure client is a dictionary
                        print("client")
                        print(client)
                        if isinstance(client, dict):
                            user_id = client.get("user_id")
                            host = client.get("host")
                            port = client.get("port")
                            pubkey = client.get("pubkey")
                            print("user_id")
                            print(user_id) 
                            print(host) 
                            print(port) 
                            print(pubkey)

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

async def broadcast_server_announce(private_key, pubkey_str):
    Success = True
    print("Now checking existing server")
    print(server_addrs)
    for server_id, info in server_addrs.items():
        try:
            host = info.get("host")
            port = int(info.get("port"))
            uri = f"ws://{host}:{port}"
            print("Sending message to other server " + uri)

            # ① 不要用 async with；手动建立长连接
            ws = await websockets.connect(
                uri,
                ping_interval=15,   # 保活
                ping_timeout=10,
                close_timeout=5
            )

            # （可选）把这条“拨出的长连接”存起来以便复用
            servers[server_id] = ws

            payload_fields = {
                "host": SERVER_ADDRESS,
                "port": SERVER_PORT,
                "pubkey": pubkey_str
            }
            target_pubkey = cu.deserialize_publickey(server_pubkeys[server_id])
            encrypted_payload = cu.encrypt_payload_fields(payload_fields, target_pubkey, MAX_RSA_PLAINTEXT)
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

            # ② 在这条“拨出的连接”上收 ACK（注意：不要和别的协程同时在同一 ws 上 recv）
            response_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            response = json.loads(response_raw)
            payload_extracted, sig_extracted = cu.extract_payload_and_signature(response)

            if cu.verify_json_signature(target_pubkey, payload_extracted, sig_extracted):
                print("Signature is valid\n")
                if response.get("type") == "ACK":
                    print("Server responded with ACK")
                    print("Server response:", payload_extracted)
                    # 已经存过 servers[server_id] = ws，可继续复用
                else:
                    print("Server response:", payload_extracted)
                    Success = False
            else:
                print("Signature is INVALID")
                Success = False

            # ③ 不要在这里关闭 ws；要复用就留着
            # 如果你不想复用，在这里主动关闭也行：await ws.close()

        except Exception as e:
            print(f"Failed to send SERVER_ANNOUNCE to {server_id} at {host}:{port}: {e}")
            Success = False
            # 失败就清理掉失效连接
            if servers.get(server_id) is not None:
                try:
                    await servers[server_id].close()
                except Exception:
                    pass
                servers.pop(server_id, None)

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
def load_server_keys(password):
    with open("ServerStorage/private_key.der", "rb") as f:
        password_bytes = password.encode("utf-8") if password is not None else None
        priv = serialization.load_der_private_key(f.read(), password=password_bytes)
    with open("ServerStorage/public_key.der", "rb") as f:
        pub = serialization.load_der_public_key(f.read())
    return priv, pub

# 先初始化数据库
init_db()
# 加载密钥/ID
private_key, public_key = load_server_keys(SERVER_PASSWORD)
SERVER_PASSWORD = None
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


# ===================== 广播：某用户上线 =====================
async def broadcast_user_online(meta: str, user_id: str, pubkey):
    payload = {
        "meta": meta,
        "user_id": user_id,
        "pubkey": pubkey,
        "when": cu.int_ts_ms(),
    }
    env = {
        "type": "USER_ONLINE",
        "from": SERVER_ID,
        "to": "*",
        "ts": cu.int_ts_ms(),
        "payload": payload,
    }
    env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8"))
    for uid, cli_ws in list(local_users.items()):
        try:
            if uid != user_id:
                await ws_send(cli_ws, json.dumps(env))
        except Exception:
            pass

    print("Have already broadcast user online")

# ===================== 广播：某用户下线（只广播用户名）=====================
async def broadcast_user_offline_username(user_id: str):
    payload = {
        "user_id": user_id,
        "when": cu.int_ts_ms(),
    }
    env = {
        "type": "USER_OFFLINE",
        "from": SERVER_ID,
        "to": "*",
        "ts": cu.int_ts_ms(),
        "payload": payload,
    }
    env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8"))
    for uid, cli_ws in list(local_users.items()):
        try:
            if uid != user_id:
                await ws_send(cli_ws, json.dumps(env))
        except Exception:
            pass



async def sending_existing_user(ws):
    all_users = {}

    # Collect from server_users
    print(server_users)
    for user_id, info in server_users.items():
        all_users[user_id] = {
            "pubkey": info["pubkey"],
            "meta": info["meta"]
        }
    print(all_users)

    # Collect from local_users (meta and pubkey from DB)
    for user_id in local_users:
        display_name = get_display_name(user_id)      # your DB function
        meta = {"display_name": display_name}
        pubkey = get_user_pubkey(user_id)  # your DB function
        all_users[user_id] = {
            "pubkey": pubkey,
            "meta": meta
        }

    ack_msg = cu.create_ack_list_message(private_key, "USE_HELLO",all_users,  SERVER_ID)
    await ws.send(json.dumps(ack_msg))
    print("Have already sent existing user")

async def user_advertise(the_user_id, meta, pubkey_str):
    for to_server_id, ws in servers.items():

        payload_fields = {
            "user_id": the_user_id, 
            "server_id": SERVER_ID, 
            "meta": meta,
            "pubkey":pubkey_str
        }

        canonical_bytes = json.dumps(payload_fields, sort_keys=True, separators=(',', ':')).encode("utf-8")
        sig = cu.sign_payload(private_key, canonical_bytes)

        advertise_msg = {
            "type": "USER_ADVERTISE",
            "from": SERVER_ID,
            "to": to_server_id,
            "ts": int(time.time() * 1000),
            "payload": payload_fields,
            "sig": sig
        }
        print("Json compleyte, now send...")
        info = server_addrs.get(to_server_id)
        host = info.get("host")
        port = info.get("port")
        uri = f"ws://{host}:{port}"
        async with websockets.connect(uri) as ws:
            await ws.send(json.dumps(advertise_msg))

    print("End sending")
            
async def user_remove(the_user_id):
    for to_server_id, ws in servers.items():
        payload_fields = {
            "user_id": the_user_id, 
            "server_id": SERVER_ID, 
        }

        canonical_bytes = json.dumps(payload_fields, sort_keys=True, separators=(',', ':')).encode("utf-8")
        sig = cu.sign_payload(private_key, canonical_bytes)

        advertise_msg = {
            "type": "USER_REMOVE",
            "from": SERVER_ID,
            "to": to_server_id,
            "ts": int(time.time() * 1000),
            "payload": payload_fields,
            "sig": sig
        }
        print("Json compleyte, now send...")
        info = server_addrs.get(to_server_id)
        host = info.get("host")
        port = info.get("port")
        uri = f"ws://{host}:{port}"
        async with websockets.connect(uri) as ws:
            await ws.send(json.dumps(advertise_msg))
        

# ===================== 连接处理 =====================
async def handle_connection(ws):
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
                print(msg)
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
                await sending_existing_user(ws)
                await broadcast_user_online(meta, user_id, pubkey)
                await user_advertise(user_id, meta, pubkey)
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
                announced_pubkey_str = payload.get("pubkey")

                payload_extracted, sig_extracted = cu.extract_payload_and_signature(msg)
                announced_pubkey = cu.deserialize_publickey(announced_pubkey_str)
                if cu.verify_json_signature(announced_pubkey, payload_extracted, sig_extracted):
                    print(f"SERVER_ANNOUNCE from {announcing_server_id} signature is valid")
                else:
                    print(f"SERVER_ANNOUNCE from {announcing_server_id} signature is INVALID")
                    error_message = cu.create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                
                if announcing_server_id in server_users:
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
                server_pubkeys[announcing_server_id] = announced_pubkey_str
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
                await sending_existing_user(ws)
                display_name = get_display_name(user_id)      # your DB function
                meta = {"display_name": display_name}
                pubkey_str = get_user_pubkey(user_id)
                await broadcast_user_online(meta, user_id, pubkey_str)
                await user_advertise(user_id, meta, pubkey)
                print(f"[LOGIN] user {user_id} logged in")


            elif mtype == "USER_ADVERTISE":
                print("Message fromother server advertising user...")
                advertising_server_id = msg.get("from")
                payload = msg.get("payload", {})
                pubkey_str = server_pubkeys.get(advertising_server_id)

                if pubkey_str is not None:
                    print("Found pubkey:", pubkey_str)
                else:
                    print("Server ID not found")
                    error_message = cu.create_error_message(private_key, "SERVER_NOT_REG", "Unknown server request", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                if not payload:
                    error_message = cu.create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                announced_user_id = payload.get("user_id")
                announced_server_id = payload.get("server_id")
                announced_meta = payload.get("meta")
                announced_user_pubkey = payload.get("pubkey")

                new_pubkey = cu.deserialize_publickey(pubkey_str)
                payload_extracted, sig_extracted = cu.extract_payload_and_signature(msg)
                if cu.verify_json_signature(new_pubkey, payload_extracted, sig_extracted):
                    print(f"SERVER_ANNOUNCE from {advertising_server_id} signature is valid")
                else:
                    print(f"SERVER_ANNOUNCE from {advertising_server_id} signature is INVALID")
                    error_message = cu.create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                
                if announced_user_id in servers:
                    print(f"Server ID {announced_user_id} already exists.")
                    error_message = cu.create_error_message(private_key, "NAME_IN_USE", "This user already exist in network", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    print(f"Server ID {advertising_server_id} is new.")
                    
                server_users[announced_user_id] = {
                    "meta": announced_meta,
                    "pubkey": announced_user_pubkey
                }
                print(server_users)
                user_locations[announced_user_id] = announced_server_id
                
                # ACK
                await broadcast_user_online(announced_meta, announced_user_id, announced_user_pubkey)
                ack_msg = cu.create_ack_message(private_key, "USER_ADVERTISE", SERVER_ID, advertising_server_id)
                await ws.send(json.dumps(ack_msg))

                print(f"{announced_user_id} add in  successfully")
                
            elif mtype == "USER_REMOVE":
                advertising_server_id = msg.get("from")
                payload = msg.get("payload", {})
                pubkey_str = server_pubkeys.get(advertising_server_id)
                if pubkey_str is not None:
                    print("Found pubkey:", pubkey_str)
                else:
                    print("Server ID not found")
                    error_message = cu.create_error_message(private_key, "SERVER_NOT_REG", "Unknown server request", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                if not payload:
                    error_message = cu.create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue


                remove_user_id = payload.get("user_id")
                remove_server_id = payload.get("server_id")

                new_pubkey = cu.deserialize_publickey(pubkey_str)
                payload_extracted, sig_extracted = cu.extract_payload_and_signature(msg)
                if cu.verify_json_signature(new_pubkey, payload_extracted, sig_extracted):
                    print(f"SERVER_ANNOUNCE from {advertising_server_id} signature is valid")
                else:
                    print(f"SERVER_ANNOUNCE from {advertising_server_id} signature is INVALID")
                    error_message = cu.create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                    
                    
                if remove_user_id in server_users:
                    # Remove from server_users
                    del server_users[remove_user_id]
                    
                    # Remove from user_locations if it exists there
                    if remove_user_id in user_locations:
                        del user_locations[remove_user_id]
                    
                    print(f"User {remove_user_id} removed successfully.")
                else:
                    print(f"User {remove_user_id} does not exist in server_users.")
                    error_message = cu.create_error_message(private_key, "USER_NOT_EXIST", "There is no such user in the network", SERVER_ID, advertising_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                
                # ACK
                await broadcast_user_offline_username(remove_user_id)
                ack_msg = cu.create_ack_message(private_key, "USER_REMOVE", SERVER_ID, advertising_server_id)
                await ws.send(json.dumps(ack_msg))

                print(f"{remove_user_id} remove in  successfully")
                
            elif mtype == "SERVER_DELIVER":
                from_server = msg.get("from")
                payload = msg.get("payload", {}) or {}

                try:
                    pubkey_str = server_pubkeys.get(from_server)
                    if pubkey_str:
                        from_server_pub = cu.deserialize_publickey(pubkey_str)
                        payload_extracted, sig_extracted = cu.extract_payload_and_signature(msg)
                        if not cu.verify_json_signature(from_server_pub, payload_extracted, sig_extracted):
                            err = cu.create_error_message(private_key, "INVALID_SIG",
                                                        "server deliver signature invalid",
                                                        SERVER_ID, from_server)
                            await ws.send(json.dumps(err))
                            continue
                except Exception:
                    err = cu.create_error_message(private_key, "INVALID_SIG",
                                                "server deliver signature invalid",
                                                SERVER_ID, from_server)
                    await ws.send(json.dumps(err))
                    continue

                target_uid = payload.get("user_id") or payload.get("sig_to")
                if not target_uid or target_uid not in local_users:
                    err = cu.create_error_message(private_key, "USER_NOT_FOUND",
                                                f"{target_uid} not on this server",
                                                SERVER_ID, from_server)
                    await ws.send(json.dumps(err))
                    continue

                deliver_type = payload.get("mtype", "USER_DELIVER")

                deliver_env = {
                    "type": deliver_type,
                    "from": SERVER_ID,
                    "to":   target_uid,
                    "ts":   cu.int_ts_ms(),
                    "payload": payload,
                }
                deliver_env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8"))

                try:
                    await ws_send(local_users[target_uid], json.dumps(deliver_env))
                except Exception:
                    traceback.print_exc()
            
            elif mtype == "USER_LOGOUT":
                uid = msg.get("from")
                if not uid or uid not in local_users or local_users[uid] is not ws:
                    err = create_error(uid or "*", "USER_NOT_FOUND", "not logged in or ws mismatch")
                    await ws.send(json.dumps(err))
                    continue

                local_users.pop(uid, None)
                user_locations.pop(uid, None)

                await broadcast_user_offline_username(uid)

                try:
                    await user_remove(uid)
                except Exception:
                    traceback.print_exc()

                print(f"[LOGOUT] user {uid} logged out")
                continue



            # ---------------- 命令分发 ----------------
            elif mtype == "LIST_REQUEST":
                await handlers.handle_list_request(msg, ws)

            elif mtype == "MSG_DIRECT":
                await handlers.handle_msg_direct(msg, ws, server_addrs)

            elif mtype == "MSG_PUBLIC_CHANNEL":
                await handlers.handle_msg_public(msg, ws, server_addrs)

            elif mtype and mtype.startswith("FILE_"):
                await handlers.handle_file_transfer(msg, ws, server_addrs)

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

# ===================== 启动 =====================
async def main():
    success = await (bootstrap_from_yaml())
    print("Success or Not:", success)
    async with websockets.serve(handle_connection, SERVER_ADDRESS, int(SERVER_PORT)):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
