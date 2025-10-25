"""
Group 20:
Jiahui Wang a1822691
Yuxuan Wu a1898143
ShunChit Yu a1880719
Youqing Fu a1981355
Mo Yang a1932039
"""

# Gen introducer keys.py
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("IntroducerStorage", exist_ok=True)

priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
pub  = priv.public_key()

with open("IntroducerStorage/introducer_private_key.der","wb") as f:
    f.write(priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"my-password")
    ))

with open("IntroducerStorage/introducer_public_key.der","wb") as f:
    f.write(pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print(" Introducer key (DER) has been generated to IntroducerStorage/")
