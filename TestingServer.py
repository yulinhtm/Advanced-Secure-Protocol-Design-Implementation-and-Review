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
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    privkey_store TEXT NOT NULL,
    pake_password TEXT NOT NULL,
    meta TEXT,
    version INTEGER NOT NULL
)
""")
conn.commit()
conn.close()

# for database
def add_user(user_id, pubkey, privkey_store, pake_password, meta=None, version=1):
    conn = sqlite3.connect("user.db")
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, pubkey, privkey_store, pake_password, json.dumps(meta) if meta else None, version))
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
    print(f"New connection from: {ws.remote_address}")
    user_id = None # Will be set after successful HELLO
    
    try:
        # The first message from a client MUST be USER_HELLO
        message_raw = await ws.recv()
        msg = json.loads(message_raw)
        
        if msg.get("type") == "USER_HELLO":
            user_id_from_msg = msg.get("from")
            payload = msg.get("payload", {})
            pubkey_from_msg_b64 = payload.get("pubkey")

            if not all([user_id_from_msg, pubkey_from_msg_b64]):
                await ws.send(json.dumps(create_error_message(private_key, "BAD_REQUEST", "USER_HELLO missing from or payload fields", SERVER_ID)))
                await ws.close()
                return

            # Check if user is already logged in
            if user_id_from_msg in local_users:
                await ws.send(json.dumps(create_error_message(private_key, "NAME_IN_USE", "User is already logged in", SERVER_ID, to_user=user_id_from_msg)))
                await ws.close()
                return

            # Verify user against the database
            pubkey_from_db_b64 = get_user_pubkey(user_id_from_msg)

            if pubkey_from_db_b64 and pubkey_from_db_b64 == pubkey_from_msg_b64:
                # User authenticated successfully!
                user_id = user_id_from_msg # Assign user_id to this connection session
                local_users[user_id] = ws
                user_locations[user_id] = "local"
                
                print(f"User '{user_id}' authenticated and connected.")
                # Send ACK to client
                ack_msg = create_ack_message(private_key, msg_ref="USER_HELLO", server_id=SERVER_ID, to_user=user_id)
                await ws.send(json.dumps(ack_msg))

                # TODO: Broadcast USER_ADVERTISE to other servers here
                print(f"TODO: Broadcast USER_ADVERTISE for {user_id}")

                # --- Enter main message loop ---
                async for message in ws:
                    print(f"Received message from '{user_id}': {message}")
                    # TODO: Handle MSG_DIRECT, MSG_PUBLIC_CHANNEL, etc.
            
            else:
                # Authentication failed
                print(f"Authentication failed for user_id {user_id_from_msg}.")
                await ws.send(json.dumps(create_error_message(private_key, "USER_NOT_FOUND", "User ID or public key mismatch", SERVER_ID, to_user=user_id_from_msg)))
                await ws.close()
                return
        else:
            # First message was not USER_HELLO
            print("Protocol error: First message was not USER_HELLO.")
            await ws.send(json.dumps(create_error_message(private_key, "PROTOCOL_ERROR", "First message must be USER_HELLO", SERVER_ID)))
            await ws.close()

    except websockets.ConnectionClosed:
        print(f"Client disconnected: {user_id if user_id else 'unauthenticated user'}")
    except Exception as e:
        print(f"An error occurred in handle_connection: {e}")
        traceback.print_exc()
    finally:
        # Cleanup on disconnect
        if user_id and user_id in local_users:
            del local_users[user_id]
            del user_locations[user_id]
            print(f"Cleaned up session for user '{user_id}'.")
            # TODO: Broadcast USER_REMOVE to other servers here
            print(f"TODO: Broadcast USER_REMOVE for {user_id}")
                


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

