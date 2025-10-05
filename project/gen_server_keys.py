from crypto_utils import generate_rsa_keypair
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("ServerStorage", exist_ok=True)
os.makedirs("ClientStorage", exist_ok=True)

priv, pub = generate_rsa_keypair()

# 使用 DER 格式保存（符合 SOCP）
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

# 同步公钥给客户端（DER 也行）
with open("ServerStorage/public_key.der", "rb") as f:
    pub_bytes = f.read()
with open("ClientStorage/server_public_key.der", "wb") as f:
    f.write(pub_bytes)

print("✅ Server 密钥对 (DER) 已生成，公钥已同步到 ClientStorage/")
