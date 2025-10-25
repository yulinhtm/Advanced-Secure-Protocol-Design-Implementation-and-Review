"""
Group 20:
Jiahui Wang a1822691
Yuxuan Wu a1898143
ShunChit Yu a1880719
Youqing Fu a1981355
Mo Yang a1932039
"""

import asyncio
import websockets
import json
import base64
import hashlib
import os

import argparse, os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu
from ClientCommands import ClientCommands

SERVER_URL = "ws://localhost:8765"
MAX_RSA_PLAINTEXT = 446  # Plaintext upper limit for RSA-4096 + OAEP(SHA-256)

user_list = {}
SERVER_ID = cu.generate_user_id("server-1")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.getenv("CLI_SERVER_URL", "ws://localhost:8765"))
    return p.parse_args()

args = parse_args()
SERVER_URL = args.url


# ===== Tool: Load server public key (used for registration/login encryption; it can run without it) =====

def load_server_pubkey():
    try:
        with open("ClientStorage/server_public_key.der", "rb") as f:
            return serialization.load_der_public_key(f.read())
    except Exception:
        return None

# ===== Tool: Strong Password Hint (use your cu.is_strong_password) =====

def get_strong_password():
    while True:
        pwd = input("Enter your password: ")
        if cu.is_strong_password(pwd):
            return pwd
        print("Weak password! Must be 12+ chars with uppercase, lowercase, number, and symbol.")

# ===== Tools: Saving Key Pairs =====

def save_keypair_for_user(username: str, priv: rsa.RSAPrivateKey, pub: rsa.RSAPublicKey, password: str):
    os.makedirs("ClientStorage", exist_ok=True)
    safe = hashlib.sha256(username.encode()).hexdigest()

    # Private key encrypted by password

    enc = serialization.BestAvailableEncryption(password.encode("utf-8")) if password else serialization.NoEncryption()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    with open(f"ClientStorage/{safe}_private_key.der", "wb") as f:
        f.write(priv_pem)

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"ClientStorage/{safe}_public_key.der", "wb") as f:
        f.write(pub_pem)

# ===== Tool: Try to load the key pair locally, if it does not exist, return (None, None) =====

def try_load_keypair(username: str, password: str):
    safe = hashlib.sha256(username.encode()).hexdigest()
    try:
        with open(f"ClientStorage/{safe}_private_key.der", "rb") as f:
            priv_pem = f.read()
        with open(f"ClientStorage/{safe}_public_key.der", "rb") as f:
            pub_pem = f.read()
        priv = serialization.load_der_private_key(priv_pem, password=password.encode("utf-8") if password else None)
        pub = serialization.load_der_public_key(pub_pem)
        return priv, pub
    except Exception:
        return None, None

# ===== Tool: Encrypt the payload field on demand (add it if you can, just plain text if you can’t) =====

def maybe_encrypt_payload(fields: dict, server_pubkey) -> dict:
    if server_pubkey is None:
        return fields
    return cu.encrypt_payload_fields(fields, server_pubkey, MAX_RSA_PLAINTEXT)

# ====== Register ======

async def register(ws, username, password, server_pubkey):
    global SERVER_ID, user_list 
    user_id = cu.generate_user_id(username)
    priv, pub = cu.generate_rsa_keypair()
    pubkey_str = cu.serialize_publickey(pub)
    salt = cu.random_salt()
    priv_store = cu.encrypt_private_key(priv, password, salt)

    payload = {
        "client": "cli-v1",
        "display_name": username,
        "pubkey": pubkey_str,
        "privkey_store": priv_store,
        "plain_password": password,
        "salt": salt,
    }
    enc = maybe_encrypt_payload(payload, server_pubkey)

    await ws.send(json.dumps({
        "type": "USER_REGISTER",
        "from": user_id,
        "to": SERVER_ID,
        "ts": cu.int_ts_ms(),
        "payload": enc
    }))

    raw = await asyncio.wait_for(ws.recv(), timeout=10)
    try:
        response = json.loads(raw)     # convert to dict

    except json.JSONDecodeError:
        print("Invalid JSON received:", raw)
        return False, None
    payload_extracted, sig_extracted = cu.extract_payload_and_signature(response)
    if cu.verify_json_signature(server_pubkey, payload_extracted, sig_extracted):
        print("Signature is valid\n")
        if response.get("type") == "ACK":
            print("Server responded with ACK")
            SERVER_ID = response.get("from")
            user_list = response.get("payload")
            safe_filename = hashlib.sha256(username.encode()).hexdigest()
            cu.save_rsa_keys_to_files(priv, pub, "ClientStorage/"+safe_filename+"_private_key.der", "ClientStorage/"+safe_filename+"_public_key.der", password)
        else:
            print("Server response:", payload_extracted)  
            return False, None  
    else:
        print("Signature is INVALID")
        return False, None

    return True, priv



# ====== Login ======

async def login(ws, username: str, password: str, server_pubkey):
    global SERVER_ID, user_list 
    user_id = cu.generate_user_id(username)
    # Try to load an existing key; if not, generate a new one

    priv, pub = try_load_keypair(username, password)
    newClient = False
    if not priv or not pub:
        priv, pub = cu.generate_rsa_keypair()
        newClient = True

    pubkey_str = cu.serialize_publickey(pub)
    payload_fields = {"client": "cli-v1", "pubkey": pubkey_str, "plain_password": password}
    enc_payload = maybe_encrypt_payload(payload_fields, server_pubkey)

    login_msg = {
        "type": "USER_HELLO",
        "from": user_id,
        "to": SERVER_ID,
        "ts": cu.int_ts_ms(),
        "payload": enc_payload
    }
    await ws.send(json.dumps(login_msg))

    # Wait for the first packet (ACK/ERROR) to be printed → If ACK, enter the command loop; if ERROR, return to the menu

    raw = await asyncio.wait_for(ws.recv(), timeout=10)
    try:
        response = json.loads(raw)     # convert to dict

    except json.JSONDecodeError:
        print("Invalid JSON received:", raw)
        return False, None
    payload_extracted, sig_extracted = cu.extract_payload_and_signature(response)
    if cu.verify_json_signature(server_pubkey, payload_extracted, sig_extracted):
        print("Signature is valid\n")
        if response.get("type") == "ACK":
            print("Server responded with ACK")
            SERVER_ID = response.get("from")
            user_list = response.get("payload")
            if newClient:
                safe_filename = hashlib.sha256(username.encode()).hexdigest()
                cu.save_rsa_keys_to_files(priv, pub, "ClientStorage/"+safe_filename+"_private_key.der", "ClientStorage/"+safe_filename+"_public_key.der", password)
        else:
            print("Server response:", payload_extracted)  
            return False, None
    else:
        print("Signature is INVALID")
        return False, None

    return True, priv

# ====== Interactive loop ======

async def run_shell(ws, username: str, private_key, server_pubkey):
    user_id = cu.generate_user_id(username)
    try:
        commands = ClientCommands(ws, user_id, private_key, db_path="user.db")
    except TypeError:
        commands = ClientCommands(ws=ws, user_id=user_id, username=username)

    print("Ready. Commands: /list , /tell <user_id> <message> , /all <message> , /file <user_id> <path> , /quit")
    incoming_files = {}  # file_id -> {"sender_pub","name","size","fh","received","dir"}

    os.makedirs("Downloads", exist_ok=True)
    async def listen_server():
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    print("[SERVER] <Invalid JSON>")
                    continue

                t = msg.get("type")
                payload = msg.get("payload", {})

                # /list response

                if t == "LIST_RESPONSE":
                    users = payload.get("users", [])
                    if users:
                        print(f"[/list] Online user（{len(users)}）：")
                        for u in users:
                            print(" -", u)
                    else:
                        print("[/list] There are currently no visible online.")
                    continue


                # —— Online broadcast: compatible with USER_ONLINE /USER_ADVERTISE —— 

                if t in ("USER_ONLINE", "USER_ADVERTISE"):
                    p = payload or {}

                    # 1) Verify the signature first: the server public key shall prevail (the same applies to Introducer/other server broadcasts)

                    try:
                        # You already have server_pubkey (load_server_pubkey())

                        ok = cu.verify_json_signature(server_pubkey, p, msg.get("sig", ""))
                        if not ok:
                            print("[notice] USER_ONLINE Signature verification failed, discarded.")
                            continue
                    except Exception as e:
                        print("[notice] USER_ONLINE Signature verification error：", e)
                        continue

                    # 2) Parse fields

                    meta = p.get("meta") or {}
                    name = meta.get("display_name") or meta.get("username") or p.get("display_name") or p.get("username")
                    uid  = p.get("user_id")
                    pk64 = p.get("pubkey")  # base64url(DER) string


                    # 3) Update the local directory cache (global user_list: user_id -> {pubkey:str, meta:dict})

                    if uid and pk64:
                        user_list[uid] = {
                            "pubkey": pk64,   # Note: The string is stored here first; then cu.deserialize_publickey() is used when actually using it.

                            "meta":   meta 
                        }

                    # 4) Friendly reminder

                    if name or uid:
                        if name and uid:
                            print(f"[notice] User online：{name}（{uid}）")
                        elif name:
                            print(f"[notice] User online：{name}")
                        else:
                            print(f"[notice] User online：{uid}")
                    else:
                        print(f"[notice] A user has logged in.")
                    continue

                # —— Offline broadcast: compatible with USER_OFFLINE /USER_REMOVE (only username is required, if not, it will fall back to user_id) ——

                if t in ("USER_OFFLINE", "USER_REMOVE"):
                    p = payload or {}
                    meta = p.get("meta") or {}
                    # Compatible field names: priority username /display_name

                    name = p.get("username") or meta.get("username") or p.get("display_name") or meta.get("display_name")
                    uid  = p.get("user_id")

                    # Verify server signature (if there is no signature or signature verification fails, this broadcast will be ignored)

                    if not cu.verify_json_signature(server_pubkey, p, msg.get("sig", "")):
                        continue

                    # Remove from local user_list

                    if uid and uid in user_list:
                        # If the name is recorded locally, use the local one (more stable)

                        name = user_list.get(uid, name)
                        user_list.pop(uid, None)

                    # Friendly reminder

                    if uid:
                        print(f"[notice] User offline：{uid}")
                    else:
                        print(f"[notice] A user has offline.")
                    continue


                # Public channel (/all): AES-GCM ciphertext

                if t == "MSG_PUBLIC_CHANNEL":
                    p = payload or {}

                    try:
                        import hashlib
                        text     = p.get("text", "")
                        sig_from = p.get("sig_from")           
                        sig_ts   = p.get("sig_ts")             
                        spub     = cu.deserialize_publickey(p["sender_pub"])
                        dg = hashlib.sha256((text + sig_from + str(sig_ts)).encode("utf-8")).digest()
                        if not cu.verify_signature(spub, dg, p.get("content_sig", "")):
                            print("[ALL] Signature verification failed, message discarded.")
                            continue
                    except Exception as e:
                        print("[ALL] Signature verification erro：", e)
                        continue

                    name = p.get("sender") or "someone"     
                    print(f"[ALL] {name}: {p.get('text','')}")
                    continue


                # Private chat (/tell): RSA-OAEP ciphertext (no iv/tag)

                if t in ("USER_DELIVER", "SERVER_DELIVER") \
                and "ciphertext" in payload and "iv" not in payload and "tag" not in payload:

                    ct_b64       = payload.get("ciphertext")
                    sender_pub64 = payload.get("sender_pub")
                    content_sig  = payload.get("content_sig")

                    # Prioritize using the fields that come with the signature in the payload.

                    s_from = payload.get("sig_from") or payload.get("sender") or msg.get("from")
                    s_to   = payload.get("user_id") or payload.get("sig_to")   or msg.get("to")
                    s_ts   = payload.get("sig_ts")   or msg.get("ts")

                    if not (ct_b64 and sender_pub64 and content_sig and s_from and s_to and s_ts is not None):
                        print("[DM] The received message fields are incomplete.：", msg);  continue

                    try:
                        sender_pub = cu.deserialize_publickey(sender_pub64)
                        import hashlib
                        dg = hashlib.sha256((ct_b64 + s_from + s_to + str(s_ts)).encode("utf-8")).digest()
                        if not cu.verify_signature(sender_pub, dg, content_sig):
                            print("[DM] Signature verification failed, message discarded.");  continue

                        pt = cu.rsa_oaep_decrypt(private_key, cu.b64url_decode(ct_b64)).decode("utf-8")
                        print(f"[DM] {s_from} → {s_to}: {pt}")

                    except Exception as e:
                        print("[DM] Decryption/Signature Verification Anomaly：", e)
                    continue


                # File start

                if t == "FILE_START":
                    p = payload
                    try:
                        sender_pub = cu.deserialize_publickey(p["sender_pub"])

                        # Verify manifest signature (only for manifest original fields)

                        manifest_for_sig = {
                            "file_id": p["file_id"],
                            "name":    p["name"],
                            "size":    p["size"],
                            "mode":    p.get("mode", "dm-rsa"),
                            "chunk":   p.get("chunk", 446),
                        }
                        ok = cu.verify_signature(
                            sender_pub,
                            cu.canonical_json(manifest_for_sig).encode("utf-8"),
                            p["manifest_sig"]
                        )
                        if not ok:
                            print("[FILE] manifest Signature invalid, discarded.");  continue

                        out_name = f"{p['file_id']}_{p['name']}"
                        out_dir  = "Downloads"
                        out_path = os.path.join("Downloads", out_name)
                        os.makedirs(out_dir, exist_ok=True)
                        fh = open(out_path, "wb")

                        incoming_files[p["file_id"]] = {
                            "sender_pub": sender_pub,
                            "name":       p["name"],
                            "size":       p["size"],
                            "fh":         fh,
                            "received":   0,
                            "dir":        "Downloads",
                        }
                        print(f"[FILE] Begin receiving {p['name']} -> {out_path}")
                    except Exception as e:
                        print("[FILE] FILE_START error：", e)
                    continue
                # FILE_CHUNK (RSA)

                if t == "FILE_CHUNK":
                    p = payload
                    fid = p.get("file_id")
                    st  = incoming_files.get(fid)
                    if not st:
                        print("[FILE] Unknown file_id, ignore block.");  continue
                    try:
                        # A priori block signature: {file id,index,ciphertext}

                        chunk_info = {"file_id": fid, "index": p["index"], "ciphertext": p["ciphertext"]}
                        ok = cu.verify_signature(
                            st["sender_pub"],
                            cu.canonical_json(chunk_info).encode("utf-8"),
                            p["chunk_sig"]
                        )
                        if not ok:
                            print("[FILE] chunk_sig invalid, discard this chunk.");  continue

                        # Decrypt & Write

                        ct  = cu.b64url_decode(p["ciphertext"])
                        pt  = cu.rsa_oaep_decrypt(private_key, ct)  # private_key is passed in by run_shell()

                        st["fh"].write(pt)
                        st["received"] += len(pt)

                        if st["size"]:
                            prog = st["received"] * 100.0 / st["size"]
                            print(f"[FILE] {st['name']} progress：{prog:.1f}%")
                    except Exception as e:
                        print("[FILE] FILE_CHUNK error：", e)
                    continue
                # File end

                if t == "FILE_END":
                    fid = payload.get("file_id")
                    st  = incoming_files.pop(fid, None)
                    if not st:
                        print("[FILE] unknow file_id（END）。");  continue
                    try:
                        st["fh"].close()
                        print(f"[FILE] Receiving completed：{st['name']}（total {st['received']} / {st['size']} bytes）")
                    except Exception as e:
                        print("[FILE] FILE_END error：", e)
                    continue

                
                # ACK/ERROR concise output

                if t in ("ACK", "ERROR"):
                    print(f"[SERVER] {t}: {payload}")
                    continue

                # reveal all the details

                print("[SERVER]", msg)

        except websockets.ConnectionClosed:
            print("[SERVER CLOSED]")


    async def user_input():
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, input, "> ")
            if line.strip() == "/quit":
                await commands.do_quit()
                print("Succesfully quit")
                os._exit(0)
                break
            elif line.strip() == "/list":
                await commands.do_list(user_list)
            elif line.startswith("/tell "):
                try:
                    _, uid, text = line.split(" ", 2)
                    await commands.do_tell(uid, text, user_list[uid]["pubkey"])
                except ValueError:
                    print("usage: /tell <user_id> <message>")
            elif line.startswith("/file "):
                try:
                    _, uid, path = line.split(" ", 2)
                    await commands.do_file(uid, path, user_list[uid]["pubkey"])
                except ValueError:
                    print("usage: /file <user_id> <path>")
            elif line.startswith("/all "):
                await commands.do_all(line[5:])
            else:
                print("unknow command：/list , /tell <user_id> <message> , /file <user_id> <path> , /all <message> , /quit")

    await asyncio.gather(listen_server(), user_input())

# ====== Menu main function ======

async def main():
    server_pubkey = load_server_pubkey()
    if server_pubkey is None:
        print("[WARN] ClientStorage/server_public_key.der not found. Registration/Login payload will be sent in plaintext.")

    while True:
        print("Menu:\nLogin: 2\nRegister: 1")
        choice = input().strip().lower()

        if choice == "1":
            username = input("Username: ")
            password = get_strong_password()
            async with websockets.connect(SERVER_URL) as ws:
                ok, priv = await register(ws, username, password, server_pubkey)
                if not ok:
                    continue
                print("[INFO] Registration success. You are already online; entering shell…")
                await run_shell(ws, username, priv, server_pubkey)
            continue

        elif choice == "2":
            username = input("Username: ")
            password = input("Enter your password: ")
            async with websockets.connect(SERVER_URL) as ws:
                ok, priv = await login(ws, username, password, server_pubkey)
                if ok:
                    await run_shell(ws, username, priv, server_pubkey)
            continue

        else:
            print("Unknown input, enter 1 / 2")


if __name__ == "__main__":
    asyncio.run(main())
