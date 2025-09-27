import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from typing import Tuple, Dict
import uuid

def verify_json_signature(public_key: rsa.RSAPublicKey, payload: dict, signature_b64url: str) -> bool:
    # Canonicalize the JSON payload (sorted keys, no whitespace variations)
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    # Decode signature from base64url
    signature_bytes = base64.urlsafe_b64decode(signature_b64url)
    
    try:
        public_key.verify(
            signature_bytes,
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    
def extract_payload_and_signature(message: dict) -> Tuple[Dict, str]:
    payload = message.get("payload", {})
    signature_b64url = message.get("sig", "")
    return payload, signature_b64url

def sign_payload(private_key: rsa.RSAPrivateKey, payload_bytes: bytes) -> str:
    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Encode signature as base64url for JSON transport
    signature_b64url = base64.urlsafe_b64encode(signature).decode('utf-8')
    return signature_b64url

def generate_user_id(username: str) -> str:
    # deterministic UUID based on username (UUID5)
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

#--for creating key(both private and public)
def generate_rsa_keypair():
    # Generate RSA-4096 private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    
    # Extract public key
    public_key = private_key.public_key()
    
    return private_key, public_key

#--for changing the password into string and private key to blob
def serialize_publickey(private_key: rsa.RSAPrivateKey) -> str:
    # Extract public key from private key → base64url UTF-8 string
    pubkey_str = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode("utf-8")
    return pubkey_str

def serialize_privatekey(private_key: rsa.RSAPrivateKey, password: str):
    # Password must be bytes
    password_bytes = password.encode("utf-8")

    # Private key → PEM, encrypted with password
    privkey_pem_encrypted = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )

    # Base64 encode so it's safe for JSON or DB storage
    priv_blob_str = base64.urlsafe_b64encode(privkey_pem_encrypted).decode("utf-8")
    return priv_blob_str


#--for encrypting using desired key
def rsa_oaep_encrypt(public_key, data: bytes) -> bytes:

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

#--for decrypting using desired key
def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, encrypted_data: bytes) -> bytes:

    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def sign_payload(private_key: rsa.RSAPrivateKey, payload_bytes: bytes) -> str:
    
    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.urlsafe_b64encode(signature).decode("utf-8")

def create_error_message(private_key: rsa.RSAPrivateKey, code: str, reason: str, server_id: str, to_user: str = "no_user_id") -> dict:

    # Build payload
    payload = {
        "code": code,
        "reason": reason
    }
    
    # Canonicalize payload
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
    
    # Sign the payload
    signature_b64url = sign_payload(private_key, canonical_bytes)
    
    # Construct message
    message = {
        "type": "ERROR",
        "from": server_id,
        "to": to_user,
        "payload": payload,
        "sig": signature_b64url
    }
    return message

def create_ack_message(private_key: rsa.RSAPrivateKey, msg_ref: str, server_id: str, to_user: str) -> dict:
    # Build payload
    payload = {
        "msg_ref": msg_ref
    }
    
    # Canonicalize payload
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
    
    # Sign the payload
    signature_b64url = sign_payload(private_key, canonical_bytes)
    
    # Construct message
    message = {
        "type": "ACK",
        "from": server_id,
        "to": to_user,
        "payload": payload,
        "sig": signature_b64url
    }
    
    return message