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

# Generate RSA-4096 key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# Extract public key
public_key = private_key.public_key()

# Serialize public key to DER (binary)
der_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Convert to base64url without padding (BASE64URL format)
pub_b64url = base64.urlsafe_b64encode(der_bytes).rstrip(b'=').decode('ascii')

print("BASE64URL(RSA-4096-PUB):")
print(pub_b64url)
print("Hi")

