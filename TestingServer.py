from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import uuid
import json
import asyncio
import websockets
import traceback
import sqlite3
import yaml
import time  # NEW: For timestamps and sleep functionality
# import function that in crypto_utils.py
from crypto_utils import *

# --- MODIFIED: Added state for server-to-server connections ---
servers = {}          # server_id -> WebSocket connection
server_addrs = {}     # server_id -> (host, port)
last_seen_times = {}  # NEW: server_id -> timestamp_ms

# --- Original state variables (unchanged) ---
local_users = {}        # user_id -> WebSocket link
user_locations = {}     # user_id -> "local" | server_id

# --- Config (unchanged) ---
Server_Name = "server-1"
SERVER_ID = generate_user_id(Server_Name)

# --- Database Model (unchanged) ---
conn = sqlite3.connect("user.db")
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
conn.close()

# --- Database functions (unchanged) ---
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
    
    if not row: return False
    stored_hashed, salt = row
    if not salt: return False
    input_hashed = hash_password(password, salt)
    return input_hashed == stored_hashed

def get_user_pubkey(user_id: str) -> str | None:
    """Fetches a user's public key from the database."""
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT pubkey FROM users WHERE user_id = ?", (user_id,))
        result = cur.fetchone()
        return result[0] if result else None

def load_bootstrap_list(path="bootstrap_servers.yaml"):
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("bootstrap_servers", [])


# --- NEW: Heartbeat and Monitoring Functions ---

async def send_heartbeats_periodically():
    """Periodically sends HEARTBEAT messages to all connected servers."""
    while True:
        await asyncio.sleep(15) # Send every 15 seconds
        print(f"[{time.ctime()}] Sending heartbeats to {len(servers)} servers...")
        # Use list(servers.items()) to avoid "dictionary changed size during iteration" error
        for server_id, ws in list(servers.items()):
            try:
                heartbeat_msg = {
                    "type": "HEARTBEAT",
                    "from": SERVER_ID,
                    "to": server_id,
                    "ts": int(time.time() * 1000),
                    "payload": {},
                }
                heartbeat_msg["sig"] = sign_payload(heartbeat_msg["payload"], private_key)
                await ws.send(json.dumps(heartbeat_msg))
            except websockets.ConnectionClosed:
                print(f"Failed to send heartbeat to {server_id}, connection is already closed.")
                # The monitoring task will handle the final cleanup and reconnect logic
            except Exception as e:
                print(f"Error sending heartbeat to {server_id}: {e}")

async def monitor_connections_periodically():
    """Monitors server connections and handles timeouts."""
    while True:
        await asyncio.sleep(10) # Check every 10 seconds
        current_time_ms = int(time.time() * 1000)
        
        # Use list(servers.keys()) to avoid "dictionary changed size during iteration" error
        for server_id in list(servers.keys()):
            last_seen = last_seen_times.get(server_id)
            if last_seen and (current_time_ms - last_seen) > 45000: # 45-second timeout
                print(f"Connection to server {server_id} timed out. Closing connection.")
                
                ws = servers.pop(server_id, None)
                last_seen_times.pop(server_id, None)
                
                if ws and ws.open:
                    await ws.close()
                
                # IMPORTANT: Here you would add logic to attempt reconnection to server_id
                # e.g., asyncio.create_task(reconnect_to_server(server_id))
                print(f"TODO: Implement reconnection logic for {server_id}")

# --- End of New Functions ---


async def handle_connection(ws):
    print(f"New connection received from: {ws.remote_address}")
    try:
        async for message in ws:
            try:
                msg = json.loads(message)
            except json.JSONDecodeError:
                error_message = create_error_message(private_key, "INVALID_JSON", "JSON decoding failed", SERVER_ID)
                await ws.send(json.dumps(error_message))
                continue

            print("Received:", msg)
            
            # --- MODIFIED: Update last_seen_time on any message from a known server ---
            sender_id = msg.get("from")
            if sender_id in servers:
                last_seen_times[sender_id] = int(time.time() * 1000)
                # print(f"Updated last_seen for {sender_id}") # You can uncomment this for verbose logging
            # --- End of Modification ---

            msg_type = msg.get("type")

            # --- Original USER_REGISTER and USER_HELLO logic is PRESERVED here ---
            if msg_type == "USER_REGISTER":
                user_id = msg.get("from")
                payload_encrypted = msg.get("payload", {})

                if not payload_encrypted:
                    error_message = create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                
                try:
                    payload = decrypt_payload_fields(payload_encrypted, private_key)
                except Exception as e:
                    error_message = create_error_message(private_key, "DECRYPT_FAIL", f"Decryption failed: {e}", SERVER_ID)
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
                
                if user_exists(user_id, display_name):
                    error_message = create_error_message(private_key, "NAME_IN_USE", "This username has been taken", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    meta = {"display_name": display_name} # Don't double-dump json here
                    hashed = hash_password(plain_password, salt)
                    add_user(user_id, pubkey, privkey_store, hashed, salt, meta, 1)

                local_users[user_id] = ws
                user_locations[user_id] = "local"

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
                
                try:
                    payload = decrypt_payload_fields(payload_encrypted, private_key)
                except Exception as e:
                    error_message = create_error_message(private_key, "DECRYPT_FAIL", f"Decryption failed: {e}", SERVER_ID)
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
                    error_message = create_error_message(private_key, "NAME_IN_USE", "This username has been logged in", SERVER_ID)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    local_users[user_id] = ws
                    user_locations[user_id] = "local"

                ack_msg = create_ack_message(private_key, msg_ref="USER_HELLO", server_id=SERVER_ID, to_user=user_id)
                await ws.send(json.dumps(ack_msg))
                print(f"User {user_id} logged in successfully!")

            # --- NEW: Handling for HEARTBEAT and Server Handshakes ---
            elif msg_type == "HEARTBEAT":
                print(f"Received HEARTBEAT from {sender_id}")
                # No action needed, last_seen_time was already updated.

            elif msg_type == "SERVER_HELLO_JOIN": # Simplified handshake for now
                server_id = msg.get("from")
                if server_id not in servers:
                    servers[server_id] = ws
                    last_seen_times[server_id] = int(time.time() * 1000)
                    print(f"Server {server_id} connected.")
                    # TODO: Send SERVER_WELCOME message back as per protocol
                else:
                    # Server is already known, update its WebSocket object if needed
                    servers[server_id] = ws
                    last_seen_times[server_id] = int(time.time() * 1000)
                    print(f"Server {server_id} re-connected.")


    except websockets.ConnectionClosed:
        # TODO: Add logic to remove disconnected users/servers from state
        print(f"Connection closed from: {ws.remote_address}")
    except Exception as e:
        print("Server error in handle_connection:")
        traceback.print_exc()


async def main():
    # --- MODIFIED: Start the background tasks when the server starts ---
    print("Starting background tasks for heartbeat and monitoring...")
    heartbeat_task = asyncio.create_task(send_heartbeats_periodically())
    monitor_task = asyncio.create_task(monitor_connections_periodically())

    async with websockets.serve(handle_connection, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever


# --- Main execution block (unchanged) ---
private_key, public_key = load_rsa_keys_from_files("ServerStorage/private_key.der", "ServerStorage/public_key.der", 'my-password')
SERVER_ID = generate_user_id(Server_Name)
asyncio.run(main())