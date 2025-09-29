#code still not confirmed!!!!!!
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Helper functions ----------
def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(password.encode())

# ---------- 1. Generate RSA-4096 key pair ----------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()

# Serialize public key (PEM or DER -> base64url)
pubkey_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pubkey_b64 = b64url_nopad(pubkey_bytes)

# ---------- 2. Encrypt private key locally ----------
# Serialize private key in DER format
priv_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # raw bytes
)

password = "MyStrongPassword123!"
salt = os.urandom(16)  # random salt
key = derive_key(password, salt)

aes = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aes.encrypt(nonce, priv_bytes, None)

# Store encrypted private key as base64url blob
privkey_store = b64url_nopad(salt + nonce + ciphertext)

# ---------- 3. Generate PAKE verifier ----------
# Simple salted SHA256 hash (for example only)
pake_verifier = b64url_nopad(hashlib.sha256(salt + password.encode()).digest())

# ---------- 4. Prepare JSON payload for registration ----------
user_id = "user-uuid-v4-here"  # generate UUID v4
meta = json.dumps({"display_name": "Alice", "pronouns": "she/her", "age": 30})

registration_payload = {
    "user_id": user_id,
    "pubkey": pubkey_b64,
    "privkey_store": privkey_store,
    "pake_password": pake_verifier,
    "meta": meta,
    "version": 1
}

print(json.dumps(registration_payload, indent=2))
