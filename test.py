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

private_key, public_key = load_rsa_keys_from_files("IntroducerStorage/introducer_private_key.der", "IntroducerStorage/introducer_public_key.der", 'my-password')

# Serialize to PEM
pem_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Convert to a single line Base64 string
pem_str = pem_bytes.decode("utf-8")
# Remove headers/footers and newlines
pem_clean = "".join(pem_str.strip().splitlines()[1:-1])

print("BASE64URL(RSA-4096-PUB):")
print(pem_clean)

