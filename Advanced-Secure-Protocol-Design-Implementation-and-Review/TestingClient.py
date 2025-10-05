import asyncio
import websockets
import json
import base64
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu
from ClientCommands import ClientCommands

SERVER_URL = "ws://localhost:8765"
MAX_RSA_PLAINTEXT = 446  # RSA-4096 + OAEP(SHA-256) 的明文上限

# ===== 工具：加载服务器公钥（用于注册/登录加密；没有也能跑） =====
def load_server_pubkey():
    try:
        with open("ClientStorage/server_public_key.pem", "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except Exception:
        return None

# ===== 工具：强口令提示（用你 cu.is_strong_password） =====
def get_strong_password():
    while True:
        pwd = input("Enter your password: ")
        if cu.is_strong_password(pwd):
            return pwd
        print("Weak password! Must be 12+ chars with uppercase, lowercase, number, and symbol.")

# ===== 工具：保存密钥对（沿用你旧逻辑的文件命名） =====
def save_keypair_for_user(username: str, priv: rsa.RSAPrivateKey, pub: rsa.RSAPublicKey, password: str):
    os.makedirs("ClientStorage", exist_ok=True)
    safe = hashlib.sha256(username.encode()).hexdigest()

    # 私钥按密码加密（沿用旧逻辑的简单加密；你也可用 cu.encrypt_private_key）
    enc = serialization.BestAvailableEncryption(password.encode("utf-8")) if password else serialization.NoEncryption()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    with open(f"ClientStorage/{safe}_private_key.pem", "wb") as f:
        f.write(priv_pem)

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"ClientStorage/{safe}_public_key.pem", "wb") as f:
        f.write(pub_pem)

# ===== 工具：尝试从本地载入密钥对，不存在则返回 (None, None) =====
def try_load_keypair(username: str, password: str):
    safe = hashlib.sha256(username.encode()).hexdigest()
    try:
        with open(f"ClientStorage/{safe}_private_key.pem", "rb") as f:
            priv_pem = f.read()
        with open(f"ClientStorage/{safe}_public_key.pem", "rb") as f:
            pub_pem = f.read()
        priv = serialization.load_pem_private_key(priv_pem, password=password.encode("utf-8") if password else None)
        pub = serialization.load_pem_public_key(pub_pem)
        return priv, pub
    except Exception:
        return None, None

# ===== 工具：按需加密 payload 字段（能加就加，不能就明文） =====
def maybe_encrypt_payload(fields: dict, server_pubkey) -> dict:
    if server_pubkey is None:
        return fields
    return cu.encrypt_payload_fields(fields, server_pubkey, MAX_RSA_PLAINTEXT)

# ====== 注册 ======
async def register(ws, username, password, server_pubkey):
    user_id = cu.generate_user_id(username)
    priv, pub = cu.generate_rsa_keypair()
    pubkey_str = cu.serialize_publickey(pub)
    salt = cu.random_salt()
    priv_store = cu.encrypt_private_key(priv, password, salt)

    payload = {
        "client": "cli-v1",
        "display_name": username,
        "pubkey": pubkey_str,
        "privkey_store": priv_store,
        "plain_password": password,
        "salt": salt,
    }
    enc = maybe_encrypt_payload(payload, server_pubkey)

    await ws.send(json.dumps({
        "type": "USER_REGISTER",
        "from": user_id,
        "to": "*",
        "ts": cu.int_ts_ms(),
        "payload": enc
    }))

    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        resp = json.loads(raw)
        print("[SERVER]", resp)
        if resp.get("type") == "ACK":
            save_keypair_for_user(username, priv, pub, password)
            return True, priv
        return False, None
    except asyncio.TimeoutError:
        print("[WARN] No response for registration.")
        return False, None




# ====== 登录 ======
async def login(ws, username: str, password: str, server_pubkey):
    user_id = cu.generate_user_id(username) 
    # 尝试加载已有密钥；没有就新生成
    priv, pub = try_load_keypair(username, password)
    if not priv or not pub:
        try:
            priv, pub = cu.generate_rsa_keypair()
        except AttributeError:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            pub = priv.public_key()

    pubkey_str = cu.serialize_publickey(pub)
    payload_fields = {"client": "cli-v1", "pubkey": pubkey_str, "plain_password": password}
    enc_payload = maybe_encrypt_payload(payload_fields, server_pubkey)

    login_msg = {
        "type": "USER_HELLO",
        "from": user_id,
        "to": "*",
        "ts": cu.int_ts_ms(),
        "payload": enc_payload
    }
    await ws.send(json.dumps(login_msg))

    # 等一次首包（ACK/ERROR）打印后 → 若 ACK，进入命令循环；若 ERROR，返回菜单
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        resp = json.loads(raw)
        print("[SERVER]", resp)
        if resp.get("type") != "ACK":
            return False, None
    except asyncio.TimeoutError:
        print("[WARN] No response for login.")

    return True, priv

# ====== 交互循环 ======
async def run_shell(ws, username: str, private_key):
    user_id = cu.generate_user_id(username)
    try:
        commands = ClientCommands(ws, user_id, private_key, db_path="user.db")
    except TypeError:
        commands = ClientCommands(ws=ws, user_id=user_id, username=username)

    print("Ready. Commands: /list , /tell <user_id> <message> , /all <message> , /file <user_id> <path> , /quit")

    async def listen_server():
        try:
            async for raw in ws:
                try:
                    m = json.loads(raw)
                except Exception:
                    print("[SERVER] <Invalid JSON>")
                    continue
                print("[SERVER]", m)
        except websockets.ConnectionClosed:
            print("[SERVER CLOSED]")

    async def user_input():
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, input, "> ")
            if line.strip() == "/quit":
                break
            elif line.strip() == "/list":
                await commands.do_list()
            elif line.startswith("/tell "):
                try:
                    _, uid, text = line.split(" ", 2)
                    await commands.do_tell(uid, text)
                except ValueError:
                    print("用法: /tell <user_id> <message>")
            elif line.startswith("/file "):
                try:
                    _, uid, path = line.split(" ", 2)
                    await commands.do_file(uid, path)
                except ValueError:
                    print("用法: /file <user_id> <path>")
            elif line.startswith("/all "):
                await commands.do_all(line[5:])
            else:
                print("未知命令：/list , /tell <user_id> <message> , /file <user_id> <path> , /all <message> , /quit")

    await asyncio.gather(listen_server(), user_input())

# ====== 菜单主函数  ======
async def main():
    server_pubkey = load_server_pubkey()
    if server_pubkey is None:
        print("[WARN] ClientStorage/server_public_key.pem not found. Registration/Login payload will be sent in plaintext.")

    while True:
        print("Menu:\nLogin: 2\nRegister: 1")
        choice = input().strip().lower()

        if choice == "1":
            username = input("Username: ")
            password = get_strong_password()
            async with websockets.connect(SERVER_URL) as ws:
                ok, priv = await register(ws, username, password, server_pubkey)
                if not ok:
                    continue
                print("[INFO] Registration success. You are already online; entering shell…")
                await run_shell(ws, username, private_key=priv)
            continue

        elif choice == "2":
            username = input("Username: ")
            password = input("Enter your password: ")
            async with websockets.connect(SERVER_URL) as ws:
                ok, priv = await login(ws, username, password, server_pubkey)
                if ok:
                    await run_shell(ws, username, private_key=priv)
            continue

        else:
            print("Unknown input, enter 1 / 2")


if __name__ == "__main__":
    asyncio.run(main())

