from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 1️⃣ Generate RSA-4096 key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# 2️⃣ Extract public key
public_key = private_key.public_key()

# 3️⃣ Serialize private key to PEM (unencrypted for now)
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'my-password')
)

# 4️⃣ Serialize public key to PEM
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 5️⃣ Save to files (optional)
with open("private_key.pem", "wb") as f:
    f.write(pem_private)

with open("public_key.pem", "wb") as f:
    f.write(pem_public)

print("RSA-4096 key pair generated successfully!")
