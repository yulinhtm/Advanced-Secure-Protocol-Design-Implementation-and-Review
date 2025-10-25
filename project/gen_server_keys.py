from crypto_utils import generate_rsa_keypair
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("ServerStorage", exist_ok=True)
os.makedirs("ClientStorage", exist_ok=True)

priv, pub = generate_rsa_keypair()

# Save using DER format (SOCP compliant)

with open("ServerStorage/private_key.der", "wb") as f:
    f.write(priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"my-password")
    ))

with open("ServerStorage/public_key.der", "wb") as f:
    f.write(pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Synchronize the public key to the client (DER is also acceptable)

with open("ServerStorage/public_key.der", "rb") as f:
    pub_bytes = f.read()
with open("ClientStorage/server_public_key.der", "wb") as f:
    f.write(pub_bytes)

print(" Server privite key (DER) has been generated，public key has synchronised to ClientStorage/")
