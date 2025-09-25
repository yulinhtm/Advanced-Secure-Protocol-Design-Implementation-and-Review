import asyncio
import websockets
import json, base 64
import uuid
import hashlib

# hard code variable
SERVER_URL = "ws://localhost:8765"

# for creating uuid for user
def generate_user_id(username: str) -> str:
    # deterministic UUID based on username (UUID5)
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

#--check
def hash_password(password: str, salt: str) -> str:
    # simple hash for demo, in production use PBKDF2, scrypt, bcrypt
    return hashlib.sha256((password + salt).encode()).hexdigest()

async def register(ws, username: str, pubkey: str):
    user_id = generate_user_id(username)
    msg = {
        "type": "USER_HELLO",
        "from": user_id,
        "to": "server-1",
        "payload": {
            "client": "cli-v1",
            "pubkey": pubkey
        },
        "sig": ""
    }
    await ws.send(json.dumps(msg))
    response = await ws.recv()
    print("Register response:", response)
    return user_id

async def login(ws, username: str, password: str):
    user_id = generate_user_id(username)
    # For demonstration, we just hash password with user_id as salt
    hashed = hash_password(password, user_id)
    login_msg = {
        "type": "USER_LOGIN",
        "from": user_id,
        "to": "server-1",
        "payload": {
            "password_hash": hashed
        },
        "sig": ""
    }
    await ws.send(json.dumps(login_msg))
    response = await ws.recv()
    print("Login response:", response)

async def main():
    print("Menu:\nLogin: Enter1\nRegister: Enter2\n")
    value = input()
    if value == 1:
        username = input("Username: ")
        password = input("Password: ")
        pubkey = "FAKEPUBKEY"  # In real life, generate RSA-4096 key
        async with websockets.connect(SERVER_URL) as ws:
            print("Registering user...")
            user_id = await register(ws, username, pubkey)
        
    elif value == 2:
        async with websockets.connect(SERVER_URL) as ws:
            print("Logging in...")
            await login(ws, username, password)
        
    else:
        print("Error!")


asyncio.run(main())


