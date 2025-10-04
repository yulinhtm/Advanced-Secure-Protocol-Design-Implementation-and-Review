import asyncio
import websockets
import json
import uuid
import time
# import function that in crypto_utils.py
from crypto_utils import *

#config
Server_Name = "introducer-1"

SERVER_ID = generate_user_id(Server_Name)
MAX_RSA_PLAINTEXT = 446  # for RSA-4096 OAEP SHA-256
SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 5001

# Keep track of registered servers
servers = {}
clients = {}

def generate_server_id():
    return str(uuid.uuid4())


# Handle incoming connections
async def handle_connection(ws):
    async for message in ws:
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            error_message = create_error_message(private_key, "INVALID_JSON", "JSON decoding failed", SERVER_ID)
            await ws.send(json.dumps(error_message))
            continue

        print("Received:", msg)
        msg_type = msg.get("type")
        if msg_type == "SERVER_HELLO_JOIN":
            new_server_id = msg.get("from")
            payload_encrypted = msg.get("payload", {})

            if not payload_encrypted:
                error_message = create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID, new_server_id)
                await ws.send(json.dumps(error_message))
                continue
            
            payload = {}
            try:
                payload = decrypt_payload_fields(payload_encrypted, private_key)
                
            except Exception as e:
                error_message = create_error_message(private_key, "DECRYPT_FAIL", "Decryption failed", SERVER_ID, new_server_id)
                await ws.send(json.dumps(error_message))
                continue

            new_host = payload.get("host")
            new_port = payload.get("port")
            new_pubkey = payload.get("pubkey")
            payload_extracted, sig_extracted = extract_payload_and_signature(msg)
            if verify_json_signature(new_pubkey, payload_extracted, sig_extracted):
                print("Signature is valid\n")  
            else:
                print("Signature is INVALID")
                error_message = create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, new_server_id)
                await ws.send(json.dumps(error_message))
                continue
                

            while new_server_id in servers:
                print(f"Server ID {new_server_id} already exists. Assigning another ID.")
                new_server_id = generate_server_id()

            print(f"Server {new_server_id} registered successfully.")
                
            # Register the new server
            servers[new_server_id] = {
                "host": new_host,
                "port": new_port,
                "pubkey": new_pubkey
            }
            
            clients = [
                {
                    "user_id": user_id,
                    "host": info["host"],
                    "port": info["port"],
                    "pubkey": info["pubkey"]
                }
                for user_id, info in servers.items()
            ]
            
            payload_fields = {
                "assigned_id": new_server_id,
                "clients": clients
            }

            encrypted_payload = encrypt_payload_fields(payload_fields, new_pubkey, MAX_RSA_PLAINTEXT)
            canonical_bytes = json.dumps(encrypted_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            sig = sign_payload(private_key, canonical_bytes)

            # Prepare SERVER_WELCOME
            welcome_msg = {
                "type": "SERVER_WELCOME",
                "from": SERVER_ID,
                "to": new_server_id,
                "ts": int(time.time() * 1000),
                "payload": payload_fields,
                "sig": sig
            }

            await ws.send(json.dumps(welcome_msg))

# Start introducer server
async def main():
    async with websockets.serve(handle_connection, SERVER_ADDRESS, SERVER_PORT):
        print("Introducer running on ws://localhost:5001")
        await asyncio.Future()  # run forever

private_key, public_key = load_rsa_keys_from_files("IntroducerStorage/private_key.der", "IntroducerStorage/public_key.der", 'my-password')
    
asyncio.run(main())
