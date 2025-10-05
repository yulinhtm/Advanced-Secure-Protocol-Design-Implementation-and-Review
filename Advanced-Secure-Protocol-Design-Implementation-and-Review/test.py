from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import asyncio
import websockets
import json, base64
import uuid
import hashlib
import os
# import function that in crypto_utils.py
from crypto_utils import *

#--hard code variable
SERVER_URL = "ws://localhost:8765"
Server_Name = "server-1"
MAX_RSA_PLAINTEXT = 446  # for RSA-4096 OAEP SHA-256
    

#--heshing the password before sending
def hash_password(password: str, salt: str) -> str:
    # simple hash for demo, in production use PBKDF2, scrypt, bcrypt
    return hashlib.sha256((password + salt).encode()).hexdigest()

def generate_salt(length: int = 16) -> str:
    salt_bytes = os.urandom(length)  # random bytes
    salt_str = base64.urlsafe_b64encode(salt_bytes).decode('utf-8')  # convert to string
    return salt_str

def store_salt(username: str, salt: str):
    local_storage = {
        "salt": salt,        # already a string
    }
    with open(f"{username}_client.json", "w") as f:
        json.dump(local_storage, f, indent=4)

async def register(ws, username: str, password: str):
    user_id = generate_user_id(username)
    private_key, public_key = generate_rsa_keypair();     # we need key if it is a new user
    pubkey_str = serialize_publickey(private_key)
    priv_blob = serialize_privatekey(private_key, password)
    salt = generate_salt()
    hashed = hash_password(password, salt)
    payload_fields = {
        "client": "cli-v1",
        "display_name": username,
        "pubkey": pubkey_str,
        "privkey_store": priv_blob,
        "pake_password": hashed
    }

    # Encrypt each field separately
    encrypted_payload = {}
    for key, value in payload_fields.items():
        if key == "client":
            # Keep the client field as-is, don't encrypt
            encrypted_payload[key] = value
            continue
        field_bytes = value.encode("utf-8")
        if len(field_bytes) > MAX_RSA_PLAINTEXT:
            # Split into chunks
            chunks = [field_bytes[i:i+MAX_RSA_PLAINTEXT] for i in range(0, len(field_bytes), MAX_RSA_PLAINTEXT)]
            encrypted_chunks = []
            for chunk in chunks:
                encrypted_chunk = rsa_oaep_encrypt(server_pubkey, chunk)
                encrypted_chunks.append(base64.urlsafe_b64encode(encrypted_chunk).decode("utf-8"))
            # Store as a list of encrypted chunks
            encrypted_payload[key] = encrypted_chunks
        else:
            # Encrypt normally
            encrypted_bytes = rsa_oaep_encrypt(server_pubkey, field_bytes)
            encrypted_payload[key] = base64.urlsafe_b64encode(encrypted_bytes).decode("utf-8")

    # Build the final registration message
    reg_msg = {
        "type": "USER_REGISTER",
        "from": user_id,
        "to": SERVER_ID,
        "ts": 1700000003000,
        "payload": encrypted_payload,
        "sig": ""
    }
    print(reg_msg)
async def main():
    print("Menu:\nLogin: Enter2\nRegister: Enter1")
    value = input()
    if value == "1":
        username = input("Username: ")
        password = input("Password: ")
        async with websockets.connect(SERVER_URL) as ws:
            print("Registering user...")
            user_id = await register(ws, username, password)
        
        
    else:
        print("Error!, wrong input")

# Load server's public key
with open("ClientStorage/server_public_key.pem", "rb") as f:
    server_pubkey = serialization.load_pem_public_key(f.read())
    
SERVER_ID = generate_user_id(Server_Name)
asyncio.run(main())

