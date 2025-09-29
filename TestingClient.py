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

def generate_salt(length: int = 16) -> str:
    salt_bytes = os.urandom(length)  # random bytes
    salt_str = base64.urlsafe_b64encode(salt_bytes).decode('utf-8')  # convert to string
    return salt_str

def store_salt(username: str, salt: str):
    local_storage = {
        "salt": salt,        # already a string
    }
    with open(f"ClientStorage/{username}_client.json", "w") as f:
        json.dump(local_storage, f, indent=4)
        
def get_strong_password():
    while True:
        password = input("Enter your password: ")
        if is_strong_password(password):
            return password
        print("Weak password! Must be 12+ chars with uppercase, lowercase, number, and symbol.")

async def register(ws, username: str, password: str):
    user_id = generate_user_id(username)
    private_key, public_key = generate_rsa_keypair()     # we need key if it is a new user
    pubkey_str = serialize_publickey(private_key)
    priv_blob = serialize_privatekey(private_key, password)
    salt = generate_salt()
    payload_fields = {
        "client": "cli-v1",
        "display_name": username,
        "pubkey": pubkey_str,
        "privkey_store": priv_blob,
        "plain_password": password,
        "salt": salt
    }

    # Encrypt each field separately
    encrypted_payload = {}
    encrypted_payload = encrypt_payload_fields(payload_fields, server_pubkey, MAX_RSA_PLAINTEXT)

    # Build the final registration message
    reg_msg = {
        "type": "USER_REGISTER",
        "from": user_id,
        "to": SERVER_ID,
        "ts": 1700000003000,
        "payload": encrypted_payload,
        "sig": ""
    }
    await ws.send(json.dumps(reg_msg))
    
    response_raw = await ws.recv()
    try:
        response = json.loads(response_raw)     # convert to dict
    except json.JSONDecodeError:
        print("Invalid JSON received:", response_raw)
        return
    
    payload_extracted, sig_extracted = extract_payload_and_signature(response)
    registerSuccess = False

    if verify_json_signature(server_pubkey, payload_extracted, sig_extracted):
        print("Signature is valid\n")
        if payload_extracted.get("type") == "ACK":
            print("Server responded with ACK")
            registerSuccess = True
            safe_filename = hashlib.sha256(username.encode()).hexdigest()
            save_rsa_keys_to_files(private_key, public_key, "ClientStorage/"+safe_filename+"_private_key.pem", "ClientStorage/"+safe_filename+"_public_key.pem", password)
        else:
            print("Server response:", payload_extracted)  
    else:
        print("Signature is INVALID")
    
    return registerSuccess

async def login(ws, username: str, password: str):
    user_id = generate_user_id(username)
    heshed_username = hashlib.sha256(username.encode()).hexdigest()
    private_key, public_key = load_rsa_keys_from_files("ClientStorage/"+heshed_username+"_private_key.pem", "ClientStorage/"+heshed_username+"_public_key.pem", password)
    newClient = False
    if not private_key or not public_key:
        private_key, public_key = generate_rsa_keypair()
        newClient = True
    pubkey_str = serialize_publickey(private_key)
    payload_fields = {
        "client": "cli-v1",
        "pubkey": pubkey_str,    
        "plain_password": password
    }
    encrypted_payload = encrypt_payload_fields(payload_fields, server_pubkey, MAX_RSA_PLAINTEXT)

    login_msg = {
        "type": "USER_HELLO",
        "from": user_id,
        "to": SERVER_ID,
        "ts":1700000003000,
        "payload": encrypted_payload,
        "sig": ""
    }
    await ws.send(json.dumps(login_msg))
    
    response_raw = await ws.recv()
    try:
        response = json.loads(response_raw)     # convert to dict
    except json.JSONDecodeError:
        print("Invalid JSON received:", response_raw)
        return
    
    payload_extracted, sig_extracted = extract_payload_and_signature(response)
    loginSuccess = False

    if verify_json_signature(server_pubkey, payload_extracted, sig_extracted):
        print("Signature is valid\n")
        if response.get("type") == "ACK":
            print("Server responded with ACK")
            loginSuccess = True
            if newClient:
                safe_filename = hashlib.sha256(username.encode()).hexdigest()
                save_rsa_keys_to_files(private_key, public_key, "ClientStorage/"+safe_filename+"_private_key.pem", "ClientStorage/"+safe_filename+"_public_key.pem", password)
        else:
            print("Server response:", payload_extracted)  
    else:
        print("Signature is INVALID")
        
    return loginSuccess

async def main():
    print("Menu:\nLogin: Enter2\nRegister: Enter1")
    value = input()
    if value == "1":
        username = input("Username: ")
        password = get_strong_password()
        async with websockets.connect(SERVER_URL) as ws:
            print("Registering user...")
            registerSuccess = await register(ws, username, password)
        
    elif value == "2":
        async with websockets.connect(SERVER_URL) as ws:
            username = input("Username: ")
            password = input("Enter your password: ")
            print("Logging in...")
            await login(ws, username, password)
        
    else:
        print("Error!, wrong input")

# Load server's public key
with open("ClientStorage/server_public_key.pem", "rb") as f:
    server_pubkey = serialization.load_pem_public_key(f.read())
    
SERVER_ID = generate_user_id(Server_Name)
asyncio.run(main())




