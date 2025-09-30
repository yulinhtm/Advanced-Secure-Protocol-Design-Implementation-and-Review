# Temporarily store the public key of the logged-in user
local_users = {}        # user_id -> WebSocket link
user_locations = {}     # user_id -> "local" | server_id
user_pubkeys = {}       # new add: user_id -> pubkey string
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

#  avoid repeating code.
async def broadcast_user_list():
    """Builds and sends the current user list to all connected clients."""
    online_users_list = []
    for uid in local_users:
        if uid in user_pubkeys:
            online_users_list.append({"user_id": uid, "pubkey": user_pubkeys[uid]})
    
    update_message = {
        "type": "USER_LIST_UPDATE",
        "payload": {"users": online_users_list}
    }
    
    if local_users: # Only broadcast if there are users left
        # The list comprehension creates a list of all send tasks
        tasks = [ws_conn.send(json.dumps(update_message)) for ws_conn in local_users.values()]
        # asyncio.gather runs all tasks concurrently
        await asyncio.gather(*tasks)



async def handle_connection(ws):
    user_id = None  # To keep track of the user for this connection
    try:
        async for message in ws:
            msg = json.loads(message)
            msg_type = msg.get("type")

            if msg_type == "USER_REGISTER":
                pass

            elif msg_type == "USER_HELLO":
                
                user_id_from_msg = msg.get("from")
                payload = decrypt_payload_fields(msg.get("payload", {}), private_key)
                password = payload.get("plain_password")

                if user_exists(user_id_from_msg, "") and check_user_password(user_id_from_msg, password):
                    user_id = user_id_from_msg # Assign user_id for this session
                    local_users[user_id] = ws
                    
                    ack_msg = create_ack_message(private_key, "Login OK", SERVER_ID, to_user=user_id)
                    await ws.send(json.dumps(ack_msg))
                    print(f"User {user_id} logged in successfully!")

                    # Store the user's public key for E2EE messaging
                    pubkey_from_payload = payload.get("pubkey")
                    user_pubkeys[user_id] = pubkey_from_payload
                    
                    # 3. Broadcast the updated user list to everyone
                    await broadcast_user_list()
                    print(f"Broadcasted user list update after {user_id} joined.")
                
                else:
                    # Login failed
                    error_msg = create_error_message(private_key, "AUTH_FAILED", "Invalid credentials", SERVER_ID, to_user=user_id_from_msg)
                    await ws.send(json.dumps(error_msg))

            elif msg_type == "MSG_DIRECT":
                recipient_id = msg.get("to")
                sender_id = msg.get("from")
                if recipient_id in local_users:
                    recipient_ws = local_users[recipient_id]
                    print(f"Routing message from {sender_id} to {recipient_id}")
                    await recipient_ws.send(json.dumps(msg))
                else:
                    print(f"Recipient {recipient_id} not found locally. Message dropped.")

    except websockets.ConnectionClosed:
        print(f"Client disconnected: {ws.remote_address}")
        if user_id in local_users:
            del local_users[user_id]
        if user_id in user_pubkeys:
            del user_pubkeys[user_id]
        
        if user_id:
            print(f"Cleaned up session for disconnected user {user_id}.")
            # Broadcast user list update after a user disconnects
            await broadcast_user_list()
            print("Broadcasted user list update after user disconnected.")

    except Exception as e:
        print(f"Server error: {e}")
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
