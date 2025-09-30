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
ONLINE_USERS = {} # user_id -> pubkey_string
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
        if response.get("type") == "ACK":
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

# In TestingClient.py, replace the user_input_sender and message_receiver functions

async def message_receiver(ws, my_private_key):
    """Handles all messages received from the server."""
    my_user_id = generate_user_id(username) # Assuming username is in the outer scope
    async for message_raw in ws:
        msg = json.loads(message_raw)
        msg_type = msg.get("type")

        if msg_type == "USER_LIST_UPDATE":
            # This part was correct, no changes needed.
            user_list = msg.get("payload", {}).get("users", [])
            ONLINE_USERS.clear()
            for user in user_list:
                ONLINE_USERS[user['user_id']] = user['pubkey']
            print("\n--- Online Users Updated ---")
            for uid in ONLINE_USERS:
                if uid != my_user_id:
                    print(f"- {uid}")
            print("--------------------------")
        
        elif msg_type == "MSG_DIRECT":
            payload = msg.get("payload", {})
            sender_id = msg.get("from")
            print(f"\n<--- Received DM from {sender_id}")

            try:
                ciphertext_b64 = payload.get("ciphertext")
                sender_pubkey_pem_str = payload.get("sender_pub")
                content_sig_b64 = payload.get("content_sig")
                ts = msg.get("ts")
                
                # --- NEW: Verify the content_sig ---
                sender_pubkey = serialization.load_pem_public_key(sender_pubkey_pem_str.encode())
                # The signature covers specific concatenated fields, as per the protocol
                data_to_verify = f"{ciphertext_b64}{sender_id}{my_user_id}{ts}".encode('utf-8')
                signature_bytes = base64.urlsafe_b64decode(content_sig_b64)

                try:
                    sender_pubkey.verify(
                        signature_bytes,
                        data_to_verify,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    print("Signature is VALID.")
                    
                    # --- Decrypt only if signature is valid ---
                    encrypted_bytes = base64.urlsafe_b64decode(ciphertext_b64)
                    decrypted_bytes = rsa_oaep_decrypt(my_private_key, encrypted_bytes)
                    print(f"[{sender_id} says]: {decrypted_bytes.decode()}")

                except InvalidSignature:
                    print("!!! WARNING: INVALID SIGNATURE. Message from sender may be forged. Discarding.")

            except Exception as e:
                print(f"Error processing received message: {e}")

async def user_input_sender(ws, my_user_id, my_private_key):
    """Handles user input and sends messages."""
    while True:
        command = await asyncio.get_event_loop().run_in_executor(
            None, input, "\nEnter command (tell <user_id> <message>):\n"
        )
        parts = command.split(" ", 2)
        if len(parts) == 3 and parts[0] == "tell":
            recipient_id = parts[1]
            message_text = parts[2]

            if recipient_id in ONLINE_USERS:
                try:
                    recipient_pubkey_pem = ONLINE_USERS[recipient_id]
                    recipient_pubkey = serialization.load_pem_public_key(recipient_pubkey_pem.encode())
                    
                    encrypted_bytes = rsa_oaep_encrypt(recipient_pubkey, message_text.encode())
                    ciphertext_b64 = base64.urlsafe_b64encode(encrypted_bytes).decode()
                    
                    ts = int(asyncio.get_event_loop().time() * 1000)
                    my_pubkey_pem = my_private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()

                    # --- NEW: Create the content_sig ---
                    data_to_sign = f"{ciphertext_b64}{my_user_id}{recipient_id}{ts}".encode('utf-8')
                    signature_bytes = my_private_key.sign(
                        data_to_sign,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    content_sig_b64 = base64.urlsafe_b64encode(signature_bytes).decode()

                    dm_msg = {
                        "type": "MSG_DIRECT", "from": my_user_id, "to": recipient_id, "ts": ts,
                        "payload": {
                            "ciphertext": ciphertext_b64,
                            "sender_pub": my_pubkey_pem,
                            "content_sig": content_sig_b64 # Now includes the real signature
                        }
                    }
                    await ws.send(json.dumps(dm_msg))
                    print(f"---> Message sent to {recipient_id}")
                except Exception as e:
                    print(f"Error sending message: {e}")
            else:
                print(f"Error: User '{recipient_id}' not found in online list.")

async def main():
    global username # Make username available to other functions
    print("Menu:\nLogin: Enter 2\nRegister: Enter 1")
    value = input()
    # ... Your existing registration logic (value == "1") can remain unchanged ...

    if value == "2":
        async with websockets.connect(SERVER_URL) as ws:
            username = input("Username: ")
            password = input("Enter your password: ")
            print("Logging in...")
            
            # Use your existing login function
            login_successful = await login(ws, username, password)
            
            if login_successful:
                print("\nLogin successful! You are now in the chat room.")
                
                # Get the private key after login
                heshed_username = hashlib.sha256(username.encode()).hexdigest()
                my_private_key, _ = load_rsa_keys_from_files(
                    "ClientStorage/"+heshed_username+"_private_key.pem",
                    "ClientStorage/"+heshed_username+"_public_key.pem",
                    password
                )
                my_user_id = generate_user_id(username)

                # Run message receiver and user input tasks concurrently
                receiver_task = asyncio.create_task(message_receiver(ws, my_private_key))
                sender_task = asyncio.create_task(user_input_sender(ws, my_user_id, my_private_key))
                await asyncio.gather(receiver_task, sender_task)

# Load server's public key
with open("ClientStorage/server_public_key.pem", "rb") as f:
    server_pubkey = serialization.load_pem_public_key(f.read())
    
SERVER_ID = generate_user_id(Server_Name)
asyncio.run(main())




