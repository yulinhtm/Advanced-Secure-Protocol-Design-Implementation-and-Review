import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from typing import Tuple, Dict

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


# ---  Generate a test user key pair ---
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()

# --- Payload you want to sign ---
payload = {
    "code": "INVALID_JSON",
    "reason": "JSON decoding failed"
}

# ---  Canonicalize payload (sorted keys, no whitespace variations) ---
canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

# --- Sign the canonical payload with RSA ---
signature_b64url = sign_payload(private_key, canonical_bytes)

# ---  Create the final JSON envelope ---
message = {
    "type": "ERROR",
    "payload": payload,
    "sig": signature_b64url
}

# ---  Send via websocket ---
# await ws.send(json.dumps(message))
print(json.dumps(message, indent=2))
payload_extracted, sig_extracted = extract_payload_and_signature(message)

if verify_json_signature(public_key, payload_extracted, sig_extracted):
    print("Signature is valid")
else:
    print("Signature is INVALID")
