import asyncio
import websockets
import json
import uuid
from datetime import datetime
# import function that in crypto_utils.py
from crypto_utils import *

#config
Server_Name = "introducer-1"

SERVER_ID = generate_user_id(Server_Name)

# Keep track of registered servers
servers = {}

# Helper to generate unique server_id
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

        msg_type = msg.get("type")
        if msg_type == "SERVER_HELLO_JOIN":
            new_host = msg["payload"]["host"]
            new_port = msg["payload"]["port"]
            new_pubkey = msg["payload"]["pubkey"]

            # Assign server_id
            assigned_id = generate_server_id()

            # Register the server
            servers[assigned_id] = {
                "host": new_host,
                "port": new_port,
                "pubkey": new_pubkey
            }

            # Prepare SERVER_WELCOME
            welcome_msg = {
                "type": "SERVER_WELCOME",
                "from": "introducer",
                "to": assigned_id,
                "ts": int(datetime.utcnow().timestamp() * 1000),
                "payload": {
                    "assigned_id": assigned_id,
                    "clients": list(servers.values())
                },
                "sig": ""  # TODO: Sign with introducer key
            }

            await ws.send(json.dumps(welcome_msg))

# Start introducer server
async def main():
    async with websockets.serve(handle_connection, "localhost", 8765):
        print("Introducer running on ws://localhost:8765")
        await asyncio.Future()  # run forever

# Load private key from PEM file
with open("IntroducerStorage/private_key.der", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b'my-password'  # the password you used when encrypting(can change to user input later)
    )

# Load public key from PEM file
with open("IntroducerStorage/public_key.der", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )
    
asyncio.run(main())
