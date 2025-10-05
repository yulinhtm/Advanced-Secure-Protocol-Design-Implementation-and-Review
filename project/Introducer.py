import asyncio
import websockets
import json
import uuid
import time
import crypto_utils as cu

# top of file
import argparse, os

#config
Server_Name = "introducer-1"

SERVER_ID = cu.generate_user_id(Server_Name)
MAX_RSA_PLAINTEXT = 446  # for RSA-4096 OAEP SHA-256
SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = "5001"

# Keep track of registered servers
servers = {}

def generate_server_id():
    return str(uuid.uuid4())

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.getenv("INTRO_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("INTRO_PORT", "5001")))
    return p.parse_args()

args = parse_args()
SERVER_ADDRESS = args.host
SERVER_PORT = str(args.port)  # keep as str if the rest of your code expects str


# Handle incoming connections
async def handle_connection(ws):
    async for message in ws:
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            error_message = cu.create_error_message(private_key, "INVALID_JSON", "JSON decoding failed", SERVER_ID)
            await ws.send(json.dumps(error_message))
            continue

        print("Received:", msg)
        msg_type = msg.get("type")
        if msg_type == "SERVER_HELLO_JOIN":
            new_server_id = msg.get("from")
            payload_encrypted = msg.get("payload", {})

            if not payload_encrypted:
                error_message = cu.create_error_message(private_key, "NO_PAYLOAD", "There is no payload in message", SERVER_ID, new_server_id)
                await ws.send(json.dumps(error_message))
                continue
            
            payload = {}
            try:
                payload = cu.decrypt_payload_fields(payload_encrypted, private_key)
                
            except Exception as e:
                error_message = cu.create_error_message(private_key, "DECRYPT_FAIL", "Decryption failed", SERVER_ID, new_server_id)
                await ws.send(json.dumps(error_message))
                continue

            new_host = payload.get("host")
            new_port = payload.get("port")
            new_pubkey_str = payload.get("pubkey")
            new_pubkey = cu.deserialize_publickey(new_pubkey_str)
            payload_extracted, sig_extracted = cu.extract_payload_and_signature(msg)
            if cu.verify_json_signature(new_pubkey, payload_extracted, sig_extracted):
                print("Signature is valid\n")  
            else:
                print("Signature is INVALID")
                error_message = cu.create_error_message(private_key, "INVALID_SIG", "Invalid signiture", SERVER_ID, new_server_id)
                await ws.send(json.dumps(error_message))
                continue
                

            while new_server_id in servers:
                print(f"Server ID {new_server_id} already exists. Assigning another ID.")
                new_server_id = generate_server_id()

            print(f"Server {new_server_id} registered successfully.")
                
            clients = [
                {
                    "user_id": user_id,
                    "host": info["host"],
                    "port": info["port"],
                    "pubkey": info["pubkey"]
                }
                for user_id, info in servers.items()
            ]
            
            # Register the new server
            servers[new_server_id] = {
                "host": new_host,
                "port": new_port,
                "pubkey": new_pubkey_str
            }
            
            
            payload_fields = {
                "assigned_id": str(new_server_id),
                "clients": clients
            }

            encrypted_payload = cu.encrypt_payload_fields(payload_fields, new_pubkey, MAX_RSA_PLAINTEXT)
            canonical_bytes = json.dumps(encrypted_payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
            sig = cu.sign_payload(private_key, canonical_bytes)

            # Prepare SERVER_WELCOME
            welcome_msg = {
                "type": "SERVER_WELCOME",
                "from": SERVER_ID,
                "to": new_server_id,
                "ts": int(time.time() * 1000),
                "payload": encrypted_payload,
                "sig": sig
            }

            print("Sent Ack")
            await ws.send(json.dumps(welcome_msg))

# Start introducer server
async def main():
    async with websockets.serve(handle_connection, SERVER_ADDRESS, int(SERVER_PORT)):
        print("Introducer running on ws://localhost:5001")
        await asyncio.Future()  # run forever

private_key, public_key = cu.load_rsa_keys_from_files("IntroducerStorage/introducer_private_key.der", "IntroducerStorage/introducer_public_key.der", 'my-password')
    
asyncio.run(main())