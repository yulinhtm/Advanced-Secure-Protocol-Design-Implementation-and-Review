from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import uuid
import json
import asyncio
import websockets
import traceback
import sqlite3
# import function that in crypto_utils.py
from crypto_utils import *

servers = {}          # server_id -> WebSocket connection (Link wrapper)
server_addrs = {}     # server_id -> (host, port)
local_users = {}        # user_id -> WebSocket link
user_locations = {}     # user_id -> "local" | server_id

#config
Server_Name = "server-1"

SERVER_ID = generate_user_id(Server_Name)

# Database Model
conn = sqlite3.connect("user.db")
cur = conn.cursor()
# Create table if it doesn't exist
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
conn.close()

# for database
def add_user(user_id, pubkey, privkey_store, pake_password, salt, meta=None, version=1):
    conn = sqlite3.connect("user.db")
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (user_id, pubkey, privkey_store, pake_password, salt, meta, version)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        pubkey,
        privkey_store,
        pake_password,
        salt,
        json.dumps(meta) if meta else None,
        version
    ))
    conn.commit()
    conn.close()
    
def user_exists(user_id: str, display_name: str) -> bool:
    # Open a fresh connection for this check
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM users WHERE user_id = ? OR json_extract(meta, '$.display_name') = ?",
            (user_id, display_name)
        )
        return cur.fetchone() is not None
    
def check_user_password(user_id: str, password: str) -> bool:
    conn = sqlite3.connect("user.db")
    cur = conn.cursor()
    
    # Fetch stored hashed password and salt directly
    cur.execute("SELECT pake_password, salt FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return False  # User not found
    
    stored_hashed, salt = row
    if not salt:
        return False  # No salt stored
    
    # Hash input password with stored salt and compare
    input_hashed = hash_password(password, salt)
    return input_hashed == stored_hashed

# event handler
# In TestingServer.py

def get_user_pubkey(user_id: str) -> str | None:
    """Fetches a user's public key from the database."""
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT pubkey FROM users WHERE user_id = ?", (user_id,))
        result = cur.fetchone()
        return result[0] if result else None

async def handle_connection(ws):
    print("ws is:", ws)
    try:
        async for message in ws:
            try:
                msg = json.loads(message)
            except json.JSONDecodeError:
                error_message = create_error_message(private_key, "INVALID_JSON", "JSON decoding failed", SERVER_ID)
                await ws.send(json.dumps(error_message))
                continue

            print("Received:", msg)
            msg_type = msg.get("type")

            # processing the recived data
            if msg_type == "USER_REGISTER":
                user_id = msg.get("from")
                payload_encrypted = msg.get("payload", {})

                if not payload_encrypted:
                    error_message = create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                
                payload = {}
                try:
                    payload = decrypt_payload_fields(payload_encrypted, private_key)
                    
                except Exception as e:
                    error_message = create_error_message(private_key, "DECRYPT_FAIL", "Decryption failed", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue

                pubkey = payload.get("pubkey")
                display_name = payload.get("display_name")
                privkey_store = payload.get("privkey_store")
                plain_password = payload.get("plain_password")
                salt = payload.get("salt")
                
                if not all([pubkey, display_name, privkey_store, plain_password, salt]):
                    error_message = create_error_message(private_key, "MISSING_FIELDS", "Missing required fields in payload", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                
                if user_exists( user_id, display_name):
                    error_message = create_error_message(private_key, "NAME_IN_USE", "This username have been taken", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    meta = json.dumps({"display_name": display_name})
                    hashed = hash_password(plain_password, salt)
                    add_user(user_id, pubkey, privkey_store, hashed, salt, meta, 1)

                # store in memory
                local_users[user_id] = ws
                user_locations[user_id] = "local"

                # ACK
                ack_msg = create_ack_message(private_key, msg_ref="USER_REGISTER", server_id=SERVER_ID, to_user=user_id)
                await ws.send(json.dumps(ack_msg))
                print(f"User {user_id} registered successfully!")
                
            elif msg_type == "USER_HELLO":
                user_id = msg.get("from")
                payload_encrypted = msg.get("payload", {})

                if not payload_encrypted:
                    error_message = create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                
                payload = {}
                try:
                    payload = decrypt_payload_fields(payload_encrypted, private_key)
                    
                except Exception as e:
                    error_message = create_error_message(private_key, "DECRYPT_FAIL", "Decryption failed", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue

                pubkey = payload.get("pubkey")
                plain_password = payload.get("plain_password")
                
                if not all([pubkey, plain_password]):
                    error_message = create_error_message(private_key, "MISSING_FIELDS", "Missing required fields in payload", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                
                if not check_user_password(user_id, plain_password):
                    error_message = create_error_message(private_key, "USER_NOT_FOUND", "Invalid username or/and password!", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue

                if user_id in local_users:
                    # User already logged in
                    error_message = create_error_message(private_key, "NAME_IN_USE", "This username have been logged in", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    local_users[user_id] = ws
                    user_locations[user_id] = "local"

                # ACK
                ack_msg = create_ack_message(private_key, msg_ref="USER_HELLO", server_id=SERVER_ID, to_user=user_id)
                await ws.send(json.dumps(ack_msg))
                print(f"User {user_id} log in successfully!")
                

    except websockets.ConnectionClosed:
        print("Client disconnected")
    except Exception as e:
        print("Server error:")
        traceback.print_exc()


async def main():
    async with websockets.serve(handle_connection, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever


# Load private key from PEM file
with open("ServerStorage/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b'my-password'  # the password you used when encrypting
    )

# Load public key from PEM file
with open("ServerStorage/public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )
SERVER_ID = generate_user_id(Server_Name)
asyncio.run(main())
