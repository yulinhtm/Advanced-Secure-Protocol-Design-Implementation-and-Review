import base64
import json
import uuid
import re
import time
import hashlib
import string
import os
from typing import Dict, Any, Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ========== RSA 基础 ==========

def generate_rsa_keypair(bits: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ========== 签名/验签 ==========

def sign_payload(privkey: rsa.RSAPrivateKey, data: bytes) -> str:
    signature = privkey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")


def verify_signature(pubkey: rsa.RSAPublicKey, data: bytes, sig_b64: str) -> bool:
    try:
        pad = '=' * (-len(sig_b64) % 4)
        sig = base64.urlsafe_b64decode(sig_b64 + pad)
        pubkey.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def sign_json(privkey: rsa.RSAPrivateKey, payload: Dict[str, Any]) -> str:
    return sign_payload(privkey, canonical_json(payload).encode("utf-8"))


def verify_json_signature(pubkey: rsa.RSAPublicKey, payload: Dict[str, Any], sig_b64: str) -> bool:
    data = canonical_json(payload).encode("utf-8")
    return verify_signature(pubkey, data, sig_b64)


# ========== 公钥序列化 ==========

def serialize_publickey(pubkey: rsa.RSAPublicKey) -> str:
    pub_der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(pub_der).decode("utf-8").rstrip("=")


def deserialize_publickey(pubkey_b64: str) -> rsa.RSAPublicKey:
    pad = '=' * (-len(pubkey_b64) % 4)
    der = base64.urlsafe_b64decode(pubkey_b64 + pad)
    return serialization.load_der_public_key(der)


# ========== JSON 规范化 ==========

def canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def extract_payload_and_signature(envelope: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    return envelope.get("payload", {}), envelope.get("sig", "")


# ========== RSA Key 存取 ==========

def save_rsa_keys_to_files(priv: rsa.RSAPrivateKey, pub: rsa.RSAPublicKey,
                           priv_path: str, pub_path: str, password: Optional[str] = None):
    enc = serialization.BestAvailableEncryption(password.encode("utf-8")) if password else serialization.NoEncryption()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)


def load_rsa_keys_from_files(priv_path: str, pub_path: str, password: Optional[str] = None):
    try:
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(
                f.read(),
                password=password.encode("utf-8") if password else None
            )
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub
    except Exception:
        return None, None


# ========== 密码哈希 ==========

def hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100_000,
        dklen=32
    )
    return base64.urlsafe_b64encode(dk).decode('utf-8').rstrip('=')


# ========== Payload 加/解密 ==========

def encrypt_payload_fields(fields: Dict[str, Any], server_pubkey: rsa.RSAPublicKey, max_len: int = 446) -> Dict[str, Any]:
    out = {}
    for k, v in fields.items():
        s = str(v).encode("utf-8")
        if len(s) <= max_len:
            ct = rsa_oaep_encrypt(server_pubkey, s)
            out[k] = base64.urlsafe_b64encode(ct).decode("utf-8").rstrip("=")
        else:
            out[k] = v
    return out


def decrypt_payload_fields(enc_payload: Dict[str, Any], server_privkey: rsa.RSAPrivateKey) -> Dict[str, Any]:
    out = {}
    for k, v in enc_payload.items():
        if isinstance(v, str):
            try:
                pad = '=' * (-len(v) % 4)
                raw = base64.urlsafe_b64decode(v + pad)
                plain = rsa_oaep_decrypt(server_privkey, raw).decode('utf-8')
                out[k] = plain
                continue
            except Exception:
                pass
        out[k] = v
    return out

# ====================== 验证密码是否强壮 ======================

def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in string.punctuation for c in password):
        return False
    return True


# ====================== UUID5 生成 ======================

# 固定命名空间：请在全项目保持一致；不要随机生成
NAMESPACE_USERID  = uuid.UUID("7b8f9f20-6d2a-47c1-9c58-1a5b9f2f3c0e")
NAMESPACE_SERVER  = uuid.UUID("9c6d5b90-aaaa-4b1b-88d2-ff1122334455")

def _normalize_username(name: str) -> str:
    """
    统一用户名：去首尾空格、压缩连续空白、转小写。
    确保 'Alice' 与 ' alice  ' 生成同一 user_id。
    """
    return re.sub(r"\s+", " ", name.strip().lower())

def generate_user_id(username: str) -> str:
    """
    基于命名空间 + 规范化用户名的 UUID5。确定性且跨机器一致。
    """
    norm = _normalize_username(username)
    return str(uuid.uuid5(NAMESPACE_USERID, norm))

def generate_server_id(server_name: str) -> str:
    """
    基于命名空间 + server_name 的 UUID5。
    这样同一个 server_name 始终生成相同的 Server ID。
    """
    norm = server_name.strip().lower()
    return str(uuid.uuid5(NAMESPACE_SERVER, norm))


# === base64url helpers ===
def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# === serialize_publickey 保持返回 str；客户端不要 .decode() ===
def serialize_publickey(pubkey: rsa.RSAPublicKey) -> str:
    pub_der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64url_encode(pub_der)


# === salt + 私钥加密（客户端 register 用） ===
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def random_salt(n: int = 16) -> str:
    return b64url_encode(os.urandom(n))

def _derive_password(password: str, salt_b64: str) -> bytes:
    salt = b64url_decode(salt_b64)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(password.encode("utf-8"))

def encrypt_private_key(priv: rsa.RSAPrivateKey, password: str, salt_b64: str) -> str:
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(_derive_password(password, salt_b64))
    )
    return b64url_encode(pem)


# --- AES-GCM helpers ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct, encryptor.tag

def aes_gcm_decrypt(key: bytes, iv: bytes, tag: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    return pt

def b64url_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ====================== 工具函数 ======================    

def int_ts_ms() -> int:
    return int(time.time() * 1000)

