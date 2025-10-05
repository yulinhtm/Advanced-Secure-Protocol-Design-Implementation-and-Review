import sqlite3
import base64
import json
import uuid
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

DB_FILE = "user.db"
STORAGE_DIR = "ClientStorage"

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

def generate_user_id(username: str) -> str:
    # 改为 UUIDv4（随机）
    return str(uuid.uuid4())

def generate_key_pair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return priv, priv.public_key()

def store_user(conn, user_id, privkey, pubkey, pake_password, meta):
    # 私钥存储（PEM base64）
    priv_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    priv_b64 = base64.urlsafe_b64encode(priv_pem).decode("utf-8").rstrip("=")

    # 公钥 DER → base64url
    pub_der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.urlsafe_b64encode(pub_der).decode("utf-8").rstrip("=")

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, pub_b64, priv_b64, pake_password, json.dumps(meta), 1)
    )
    conn.commit()

    # 本地保存
    os.makedirs(STORAGE_DIR, exist_ok=True)
    with open(os.path.join(STORAGE_DIR, f"{user_id}.priv"), "w") as f:
        f.write(priv_b64)
    with open(os.path.join(STORAGE_DIR, f"{user_id}.pub"), "w") as f:
        f.write(pub_b64)

if __name__ == "__main__":
    conn = init_db()
    username = input("Enter username: ")
    password = input("Enter password: ")

    user_id = generate_user_id(username)
    priv, pub = generate_key_pair()
    meta = {"username": username}

    store_user(conn, user_id, priv, pub, password, meta)
    print(f"[OK] User {username} ({user_id}) created.")
