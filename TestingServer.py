from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import uuid
import json
import asyncio
import websockets
import traceback
import sqlite3
import yaml
import time
from typing import Dict, Tuple
# import function that in crypto_utils.py
from crypto_utils import *

servers = {}          # server_id -> WebSocket connection (Link wrapper)
# server_id (str or int) -> (host, port)
server_addrs: Dict[str, Tuple[str, int]] = {}
server_pubkeys: Dict[str, str] = {}
local_users = {}        # user_id -> WebSocket link
user_locations = {}     # user_id -> "local" | server_id

#config
SERVER_PORT = 8765
Server_Name = "server-1"

SERVER_ID = generate_user_id(Server_Name)
SERVER_ADDRESS = "127.0.0.1"
MAX_RSA_PLAINTEXT = 446  # for RSA-4096 OAEP SHA-256

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
    
def load_bootstrap_list(path="bootstrap_servers.yaml"):
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("bootstrap_servers", [])

async def bootstrap_to_introducer(introducer):
    host = introducer["host"]
    port = introducer["port"]
    introducer_pubkey_b64 = introducer["pubkey"]
    # Decode base64url to DER
    der_bytes = base64.urlsafe_b64decode(introducer_pubkey_b64 + "==")

    # Load into real RSAPublicKey object
    introducer_pubkey = serialization.load_der_public_key(der_bytes)
    print(f"Trying introducer {host}:{port} ...")

    uri = f"ws://{host}:{port}"
    pubkey_str = serialize_publickey(private_key)

    try:
        async with websockets.connect(uri) as ws:
            payload_fields = {
                "host": SERVER_ID,
                "port": SERVER_PORT,
                "pubkey": pubkey_str
            }

            encrypted_payload = encrypt_payload_fields(payload_fields, introducer_pubkey, MAX_RSA_PLAINTEXT)
            canonical_bytes = json.dumps(encrypted_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            sig = sign_payload(private_key, canonical_bytes)

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
                payload = decrypt_payload_fields(payload_encrypted, private_key)
                
            except Exception as e:
                print("Decrypt failed")
                return False
            
            payload_extracted, sig_extracted = extract_payload_and_signature(response)

            if verify_json_signature(introducer_pubkey, payload_extracted, sig_extracted):
                print("Signature is valid\n")
                if response.get("type") == "SERVER_WELCOME":
                    print("Valid response from introducer:", response.get("type"))
                    assigned_id = payload.get("assigned_id")
                    server_list = payload.get("clients", [])
                    SERVER_ID = assigned_id

                    for client in server_list:
                        user_id = client["user_id"]
                        server_addrs[user_id] = (client["host"], client["port"])
                        server_pubkeys[user_id] = client["pubkey"]
                        
                    Success = broadcast_server_announce( private_key, pubkey_str)
                    
                elif response.get("type") == "ERROR":
                    print("Introducer returned an error:", response.get("message"))
                    return False
            else:
                print("Signature is INVALID")


            return Success

    except Exception as e:
        print(f"Failed to connect to introducer {host}:{port}: {e}")
        return False


async def bootstrap_from_yaml(yaml_path="bootstrap_servers.yaml"):
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)

    bootstrap_list = config.get("bootstrap_servers", [])

    for introducer in bootstrap_list:
        assigned_id, server_list = await bootstrap_to_introducer(introducer)
        if assigned_id is not None:
            return assigned_id, server_list

    print("Failed to connect to all introducers.")
    return None, None

async def broadcast_server_announce( private_key, pubkey_str):
    Success = True
    for server_id, (host, port) in server_addrs.items():
        try:
            uri = f"ws://{host}:{port}"
            async with websockets.connect(uri) as ws:
                payload_fields = {
                    "host": SERVER_ADDRESS,  # your server's IP
                    "port": SERVER_PORT,  # your server's WS port
                    "pubkey": pubkey_str
                }

                # Encrypt payload if needed
                encrypted_payload = encrypt_payload_fields(payload_fields, server_pubkeys[server_id], MAX_RSA_PLAINTEXT)
                
                # Prepare signature
                canonical_bytes = json.dumps(encrypted_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
                sig = sign_payload(private_key, canonical_bytes)

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
                
                payload_extracted, sig_extracted = extract_payload_and_signature(response)

                if verify_json_signature(server_pubkeys[server_id], payload_extracted, sig_extracted):
                    print("Signature is valid\n")
                    if response.get("type") == "ACK":
                        print("Server responded with ACK")
                        print("Server response:", payload_extracted) 
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
                
            elif msg_type == "SERVER_ANNOUNCE":
                announcing_server_id = msg.get("from")
                payload_encrypted = msg.get("payload", {})

                if not payload_encrypted:
                    error_message = create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                payload = {}
                try:
                    payload = decrypt_payload_fields(payload_encrypted, private_key)
                except Exception as e:
                    error_message = create_error_message(private_key, "DECRYPT_FAIL", "Decryption failed", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue

                announced_host = payload.get("host")
                announced_port = payload.get("port")
                announced_pubkey = payload.get("pubkey")

                payload_extracted, sig_extracted = extract_payload_and_signature(msg)
                if verify_json_signature(announced_pubkey, payload_extracted, sig_extracted):
                    print(f"SERVER_ANNOUNCE from {announcing_server_id} signature is valid")
                else:
                    print(f"SERVER_ANNOUNCE from {announcing_server_id} signature is INVALID")
                    error_message = create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                
                if announcing_server_id in servers:
                    print(f"Server ID {announcing_server_id} already exists.")
                    error_message = create_error_message(private_key, "NAME_IN_USE", "Same server id alraedy exist", SERVER_ID, announcing_server_id)
                    await ws.send(json.dumps(error_message))
                    continue
                else:
                    print(f"Server ID {announcing_server_id} is new.")

                # Update server_addrs and server_pubkeys for easy access
                server_addrs[announcing_server_id] = (announced_host, announced_port)
                server_pubkeys[announcing_server_id] = announced_pubkey
                servers[announcing_server_id] = ws
                
                # ACK
                ack_msg = create_ack_message(private_key, "SERVER_ANNOUNCE", SERVER_ID, announcing_server_id)
                await ws.send(json.dumps(ack_msg))

                print(f"Server {announcing_server_id} registered/updated successfully")                

    except websockets.ConnectionClosed:
        print("Client disconnected")
    except Exception as e:
        print("Server error:")
        traceback.print_exc()


async def main():
    assigned_id, server_list = asyncio.run(bootstrap_from_yaml())
    print("Final assigned ID:", assigned_id)
    print("Final server list:", server_list)
    async with websockets.serve(handle_connection, SERVER_ADDRESS, 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever


private_key, public_key = load_rsa_keys_from_files("ServerStorage/private_key.der", "ServerStorage/public_key.der", 'my-password')

SERVER_ID = generate_user_id(Server_Name)
asyncio.run(main())
