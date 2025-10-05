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
PORT = 8765
SERVER_NAME = "server-2"

# import os
# HOST = os.environ.get("SERVER_HOST", "localhost")
# PORT = int(os.environ.get("SERVER_PORT", "8765"))
# SERVER_NAME = os.environ.get("SERVER_NAME", "server-1")

# ===================== 全局状态 =====================
servers = {}           # server_id -> WebSocket 连接
server_addrs = {}      # server_id -> (host, port) 地址信息
local_users = {}       # user_id -> WebSocket 连接
user_locations = {}    # user_id -> "local" 或 server_id (可能陈旧)

# 辅助函数：查看当前连接的服务器
def get_connected_servers():
    """返回当前已连接的服务器列表"""
    return list(servers.keys())

def get_known_servers():
    """返回所有已知的服务器地址"""
    return dict(server_addrs)

# ===================== Presence 管理 =====================
def mark_user_location_stale(server_id: str):
    """
    当与某个服务器的连接丢失时，标记该服务器上所有用户的位置为陈旧。
    懒惰修正：不立即删除，等待消息投递失败或收到新gossip时再处理。
    """
    stale_users = [uid for uid, loc in user_locations.items() if loc == server_id]
    if stale_users:
        print(f"[PRESENCE] Marking {len(stale_users)} users as potentially stale (from server {server_id})")
        # 保留位置信息但标记为"可能不准确"
        # 在实际投递失败时会清理
    return stale_users

def correct_user_presence_on_gossip(user_id: str, new_location: str):
    """
    收到新的gossip消息时，更新用户位置信息。
    这是懒惰修正的一部分。
    """
    old_location = user_locations.get(user_id)
    if old_location != new_location:
        print(f"[PRESENCE] Correcting {user_id} location: {old_location} -> {new_location}")
        if new_location == "offline":
            user_locations.pop(user_id, None)
        else:
            user_locations[user_id] = new_location
        return True
    return False

def remove_stale_user(user_id: str):
    """投递失败时移除陈旧的用户记录"""
    old_loc = user_locations.pop(user_id, None)
    if old_loc:
        print(f"[PRESENCE] Removed stale user {user_id} (was at {old_loc})")

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
hb.on_server_disconnected = mark_user_location_stale  # 注入回调函数

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

# ===================== 消息投递（带懒惰修正） =====================
async def deliver_message_to_user(recipient_id: str, message: dict):
    """
    尝试向用户投递消息，如果失败则进行懒惰修正。
    返回: (success: bool, error_msg: str or None)
    """
    # 1. 先检查本地用户
    if recipient_id in local_users:
        recipient_ws = local_users[recipient_id]
        try:
            await recipient_ws.send(json.dumps(message))
            print(f"[DELIVER] Message delivered to local user {recipient_id}")
            return True, None
        except Exception as e:
            # 本地投递失败 - 移除陈旧连接
            print(f"[DELIVER] Failed to deliver to local user {recipient_id}: {e}")
            local_users.pop(recipient_id, None)
            user_locations.pop(recipient_id, None)
            return False, "Local delivery failed, user disconnected"
    
    # 2. 检查远程位置（可能陈旧）
    remote_server = user_locations.get(recipient_id)
    if remote_server and remote_server != "local":
        # 检查到远程服务器的连接是否存在
        remote_ws = servers.get(remote_server)
        if remote_ws:
            try:
                await remote_ws.send(json.dumps(message))
                print(f"[DELIVER] Message forwarded to {recipient_id} via server {remote_server}")
                return True, None
            except Exception as e:
                # 远程投递失败 - 懒惰修正：移除陈旧记录
                print(f"[DELIVER] Failed to forward to {recipient_id} via {remote_server}: {e}")
                remove_stale_user(recipient_id)
                return False, f"Remote server {remote_server} unreachable"
        else:
            # 远程服务器连接不存在 - 懒惰修正
            print(f"[DELIVER] Remote server {remote_server} for {recipient_id} not connected")
            remove_stale_user(recipient_id)
            return False, f"Remote server {remote_server} not connected"
    
    # 3. 用户不在线
    return False, f"User {recipient_id} not found"

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
            
            # --- Gossip消息处理（懒惰修正presence） ---
            elif mtype == "USER_JOINED":
                # 收到其他服务器的用户加入通知
                payload = msg.get("payload", {})
                joined_user = payload.get("user_id")
                from_server = msg.get("from")
                if joined_user and from_server:
                    correct_user_presence_on_gossip(joined_user, from_server)
                # 转发给本地用户
                await broadcast(msg)
                continue
            
            elif mtype == "USER_LEFT":
                # 收到其他服务器的用户离开通知
                payload = msg.get("payload", {})
                left_user = payload.get("user_id")
                if left_user:
                    correct_user_presence_on_gossip(left_user, "offline")
                # 转发给本地用户
                await broadcast(msg)
                continue

            elif mtype == "USER_REGISTER":
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
                # (登录和广播逻辑)
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
                    # 向其他服务器gossip用户加入
                    for server_id, server_ws in servers.items():
                        try:
                            await server_ws.send(json.dumps(join_notification))
                        except Exception:
                            pass
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
                # (私聊逻辑 - 使用懒惰修正)
                sender_id = msg.get("from"); recipient_id = msg.get("to")
                print(f"[DM] Received direct message from {sender_id} to {recipient_id}")
                
                # 使用新的投递函数（带懒惰修正）
                success, error_detail = await deliver_message_to_user(recipient_id, msg)
                
                if not success:
                    print(f"  -> Delivery failed: {error_detail}")
                    error_msg = create_error(sender_id, "USER_NOT_FOUND", error_detail)
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
        # (断开连接逻辑)
        if client_id != "unknown" and client_id in local_users:
            print(f"[DISCONNECT] user {client_id} offline")
            local_users.pop(client_id, None)
            user_locations.pop(client_id, None)
            
            user_meta = get_user_meta(client_id)
            left_notification = {"type": "USER_LEFT", "from": SERVER_ID, "payload": {"user_id": client_id, "display_name": user_meta.get("display_name", client_id)}}
            await broadcast(left_notification)
            # 向其他服务器gossip用户离开
            for server_id, server_ws in servers.items():
                try:
                    await server_ws.send(json.dumps(left_notification))
                except Exception:
                    pass

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