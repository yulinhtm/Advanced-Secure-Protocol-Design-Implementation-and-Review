from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#Generate RSA-4096 key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

#Extract public key
public_key = private_key.public_key()

# Serialize private key to DER (encrypted)
der_private = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'my-password')
)

# Serialize public key to DER
der_public = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save to files (optional)
with open("private_key.der", "wb") as f:
    f.write(der_private)

with open("public_key.der", "wb") as f:
    f.write(der_public)

print("RSA-4096 key pair generated successfully!")
