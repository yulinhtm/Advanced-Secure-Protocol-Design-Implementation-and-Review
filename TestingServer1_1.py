#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import websockets
import json
import sqlite3
import traceback
import time

import Heartbeats_Timeouts as hb

from cryptography.hazmat.primitives import serialization

import crypto_utils as cu

# ===================== 配置 =====================
HOST = "localhost"
PORT = 8766
SERVER_NAME = "server-1"

# ===================== 全局状态 =====================
servers = {}           # server_id -> WebSocket 连接
server_addrs = {}      # server_id -> (host, port) 地址信息
local_users = {}       # user_id -> WebSocket 连接
user_locations = {}    # user_id -> "local" 或 server_id

# 辅助函数：查看当前连接的服务器
def get_connected_servers():
    """返回当前已连接的服务器列表"""
    return list(servers.keys())

def get_known_servers():
    """返回所有已知的服务器地址"""
    return dict(server_addrs)

# ===================== 数据库 (不变) =====================
DB = "user.db"
def init_db():
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, privkey_store TEXT NOT NULL, pake_password TEXT NOT NULL, meta TEXT, version INTEGER NOT NULL, salt TEXT)""")
        conn.commit()
def add_user(user_id, pubkey, privkey_store, pake_password, salt, meta=None, version=1):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", (user_id, pubkey, privkey_store, pake_password, salt, json.dumps(meta) if isinstance(meta, dict) else meta, version))
        conn.commit()
def user_exists(user_id: str, display_name: str) -> bool:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE user_id = ? OR json_extract(meta, '$.display_name') = ?", (user_id, display_name))
        return cur.fetchone() is not None
def check_user_password(user_id: str, password: str) -> bool:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT pake_password, salt FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    if not row: return False
    stored_hash, salt = row
    if not salt: return False
    return cu.hash_password(password, salt) == stored_hash
def get_user_meta(user_id: str) -> dict:
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute("SELECT meta FROM users WHERE user_id = ?", (user_id,))
        r = cur.fetchone()
        return json.loads(r[0]) if r and r[0] else {}

# ===================== 广播辅助函数 (不变) =====================
async def broadcast(message: dict, exclude_ws: set = set()):
    if not local_users: return
    message_str = json.dumps(message)
    tasks = [ws.send(message_str) for ws in local_users.values() if ws not in exclude_ws]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

# ===================== 初始化 (不变) =====================
async def ws_send(link, message_str: str):
    try: await link.send(message_str)
    except Exception: pass
def load_server_keys():
    with open("ServerStorage/private_key.pem", "rb") as f: priv = serialization.load_pem_private_key(f.read(), password=b"my-password")
    with open("ServerStorage/public_key.pem", "rb") as f: pub = serialization.load_pem_public_key(f.read())
    return priv, pub
init_db()
private_key, public_key = load_server_keys()
SERVER_ID = cu.generate_server_id(SERVER_NAME)
def create_ack(to_user: str, msg_ref: str):
    payload = {"msg_ref": msg_ref, "status": "ok"}; env = {"type": "ACK", "from": SERVER_ID, "to": to_user, "ts": cu.int_ts_ms(), "payload": payload}
    env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8")); return env
def create_error(to_user: str, code: str, detail: str):
    payload = {"code": code, "detail": detail}; env = {"type": "ERROR", "from": SERVER_ID, "to": to_user, "ts": cu.int_ts_ms(), "payload": payload}
    env["sig"] = cu.sign_payload(private_key, cu.canonical_json(payload).encode("utf-8")); return env


# 注入 Heartbeats 模块变量
hb.servers = servers
hb.server_addrs = server_addrs
hb.SERVER_ID = SERVER_ID
hb.last_seen_times = {}
hb.private_key = private_key
hb.sign_payload = cu.sign_payload

# ===================== 服务器间连接初始化 =====================
async def connect_to_peer_servers():
    """
    连接到其他已知的服务器。
    可选功能：仅在多服务器部署时需要。
    """
    # 方式1: 从环境变量读取
    import os
    peer_list = os.environ.get("PEER_SERVERS", "")  # 格式: "server-2:localhost:8766,server-3:localhost:8767"
    
    if not peer_list:
        print("[INIT] No peer servers configured (running in single-server mode)")
        return
    
    peer_servers = []
    for entry in peer_list.split(","):
        parts = entry.strip().split(":")
        if len(parts) == 3:
            server_id, host, port = parts
            peer_servers.append((server_id, host, int(port)))
    
    # 方式2: 或者直接硬编码（开发测试用）
    # peer_servers = [
    #     ("server-2", "localhost", 8766),
    #     ("server-3", "localhost", 8767),
    # ]
    
    if not peer_servers:
        print("[INIT] No valid peer servers to connect")
        return
    
    print(f"[INIT] Connecting to {len(peer_servers)} peer servers...")
    for server_id, host, port in peer_servers:
        server_addrs[server_id] = (host, port)
        try:
            await hb.reconnect_to_server(server_id, (host, port))
            print(f"[INIT] Connected to peer server {server_id} at {host}:{port}")
        except Exception as e:
            print(f"[INIT] Failed to connect to {server_id}: {e} (will retry automatically)")

# ===================== 连接处理 =====================
async def handle_connection(ws):
    client_id = "unknown"
    try:
        async for raw in ws:
            msg = json.loads(raw)
            mtype = msg.get("type")
            user_id = msg.get("from")

            # *** 关键修改：对所有消息都更新心跳时间戳 ***
            # 只要收到任何帧，就更新 last_seen_times
            if user_id and user_id in servers:
                # 这是来自其他服务器的消息
                hb.mark_peer_seen(user_id)

            # --- 心跳处理 ---
            if mtype == "HEARTBEAT":
                # 心跳消息已经在上面更新了时间戳，这里可以记录日志
                print(f"[HB] Received heartbeat from {user_id}")
                continue  # 心跳不做其他处理

            if mtype == "USER_REGISTER":
                # (注册逻辑不变)
                payload = msg.get("payload", {}); display_name = payload.get("display_name")
                if user_exists(user_id, display_name):
                    await ws.send(json.dumps(create_error(user_id, "NAME_IN_USE", "username or user_id already exists")))
                    continue
                hashed = cu.hash_password(payload.get("plain_password"), payload.get("salt"))
                meta = {"display_name": display_name}
                add_user(user_id, payload.get("pubkey"), payload.get("privkey_store"), hashed, payload.get("salt"), meta, 1)
                await ws.send(json.dumps(create_ack(user_id, "USER_REGISTER")))
                print(f"[REGISTER] user {user_id} ({display_name}) registered")

            elif mtype == "USER_HELLO":
                # (登录和广播逻辑不变)
                payload = msg.get("payload", {})
                plain_password = payload.get("plain_password")
                if plain_password != "reconnect_placeholder" and not check_user_password(user_id, plain_password):
                    await ws.send(json.dumps(create_error(user_id, "USER_NOT_FOUND", "invalid username/password")))
                    continue
                is_new_login = user_id not in local_users
                local_users[user_id] = ws; user_locations[user_id] = "local"; client_id = user_id
                await ws.send(json.dumps(create_ack(user_id, "USER_HELLO")))
                user_meta = get_user_meta(user_id); display_name = user_meta.get("display_name", user_id)
                if is_new_login:
                    print(f"[LOGIN] user {user_id} ({display_name}) logged in")
                    join_notification = {"type": "USER_JOINED", "from": SERVER_ID, "payload": {"user_id": user_id, "display_name": display_name}}
                    await broadcast(join_notification, exclude_ws={ws})
                online_users_payload = {"users": {}}
                for uid in local_users:
                    meta = get_user_meta(uid)
                    online_users_payload["users"][uid] = {"displayName": meta.get("display_name", uid), "unread": 0}
                user_list_update = {"type": "USER_LIST_UPDATE", "from": SERVER_ID, "payload": online_users_payload}
                await ws_send(ws, json.dumps(user_list_update))

            elif mtype == "MSG_PUBLIC_CHANNEL":
                # (公共频道逻辑不变)
                print(f"Broadcasting public message from {user_id}")
                await broadcast(msg, exclude_ws={ws})

            elif mtype == "MSG_DIRECT":
                # (私聊逻辑不变)
                sender_id = msg.get("from"); recipient_id = msg.get("to")
                print(f"[DM] Received direct message from {sender_id} to {recipient_id}")
                recipient_ws = local_users.get(recipient_id)
                if recipient_ws:
                    await ws_send(recipient_ws, json.dumps(msg))
                    print(f"  -> Relayed message to {recipient_id}")
                else:
                    print(f"  -> Recipient {recipient_id} not found. Sending error to {sender_id}.")
                    error_msg = create_error(sender_id, "USER_NOT_FOUND", f"User '{recipient_id}' is not online.")
                    await ws_send(ws, json.dumps(error_msg))
            
            elif mtype == "LIST_REQUEST":
                print(f"Handling LIST_REQUEST from {user_id}")
                online_users_payload = {"users": {}}
                for uid in local_users:
                    meta = get_user_meta(uid)
                    online_users_payload["users"][uid] = {"displayName": meta.get("display_name", uid), "unread": 0}
                
                user_list_update = {"type": "USER_LIST_UPDATE", "from": SERVER_ID, "payload": online_users_payload}
                await ws_send(ws, json.dumps(user_list_update))
            
            elif mtype and mtype.startswith("FILE_"):
                # Placeholder for file transfer logic
                print(f"Received file transfer message of type '{mtype}' from {user_id}. Full logic not yet implemented.")
                pass

            else:
                # (未知类型处理不变)
                await ws.send(json.dumps(create_error(user_id or "*", "UNKNOWN_TYPE", f"unsupported type {mtype}")))

    except websockets.ConnectionClosed:
        # (断开连接逻辑不变)
        if client_id != "unknown" and client_id in local_users:
            print(f"[DISCONNECT] user {client_id} offline")
            local_users.pop(client_id, None)
            user_locations.pop(client_id, None)
            
            user_meta = get_user_meta(client_id)
            left_notification = {"type": "USER_LEFT", "from": SERVER_ID, "payload": {"user_id": client_id, "display_name": user_meta.get("display_name", client_id)}}
            await broadcast(left_notification)

    except Exception:
        traceback.print_exc()

# ===================== 启动 (修改) =====================
async def main():
    print(f"[BOOT] Server {SERVER_ID} starting at ws://{HOST}:{PORT}")

    # 启动心跳和监控任务
    asyncio.create_task(hb.send_heartbeats_periodically())
    asyncio.create_task(hb.monitor_connections_periodically())
    
    # 连接到其他服务器
    asyncio.create_task(connect_to_peer_servers())

    async with websockets.serve(handle_connection, HOST, PORT):
        print(f"[RUNNING] ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())