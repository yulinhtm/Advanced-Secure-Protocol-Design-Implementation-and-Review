# gen_server_keys.py
from crypto_utils import generate_rsa_keypair, save_rsa_keys_to_files
import os

# 确保目录存在
os.makedirs("ServerStorage", exist_ok=True)
os.makedirs("ClientStorage", exist_ok=True)

# 生成 RSA-4096 密钥对
priv, pub = generate_rsa_keypair()

# 保存到 ServerStorage 下，服务端会从这里加载
save_rsa_keys_to_files(priv, pub,
                       "ServerStorage/private_key.pem",
                       "ServerStorage/public_key.pem",
                       password="my-password")   # 注意 TestingServer 默认就是这个密码

# 同时复制一份公钥给客户端
with open("ServerStorage/public_key.pem", "rb") as f:
    pub_bytes = f.read()
with open("ClientStorage/server_public_key.pem", "wb") as f:
    f.write(pub_bytes)

print("Server 密钥对生成完成，公钥已同步到 ClientStorage/")
