from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import asyncio
import websockets
import json, base64
import uuid
import hashlib

def generate_user_id(username: str) -> str:
    # deterministic UUID based on username (UUID5)
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

server_id = generate_user_id("server-1")
print(server_id)