# manage_users.py
import sqlite3
import getpass
from crypto_utils import *

DB_PATH = "user.db"

def add_user_to_db(user_id, pubkey_str, privkey_blob, pake_hash, display_name):
    """Adds a new user record to the database."""
    meta = {"display_name": display_name}
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, pubkey_str, privkey_blob, pake_hash, json.dumps(meta), 1))
        conn.commit()
        print(f"Successfully added user '{display_name}' with ID: {user_id}")
    except sqlite3.IntegrityError:
        print(f"Error: User with display name '{display_name}' or similar User ID already exists.")
    finally:
        conn.close()

def main():
    print("--- Create New SOCP User ---")
    username = input("Enter a new username: ")
    
    # Generate User ID
    user_id = generate_user_id(username)

    # Get a strong password
    while True:
        password = getpass.getpass("Enter a strong password (will not be shown): ")
        if is_strong_password(password):
            break
        print("Weak password! Must be 12+ chars with uppercase, lowercase, number, and symbol.")

    # Generate RSA Keys
    private_key, public_key = generate_rsa_keypair()
    print("Generated RSA-4096 key pair.")

    # Serialize keys for storage
    pubkey_str = base64.urlsafe_b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode('utf-8')
    
    priv_blob = serialize_privatekey(private_key, password) # Encrypts private key with password

    # Note: pake_password is a placeholder in this context as we are not implementing PAKE.
    # We will store a simple hash as required by the DB schema.
    pake_placeholder_hash = hashlib.sha256(password.encode()).hexdigest()

    # Save user to DB
    add_user_to_db(user_id, pubkey_str, priv_blob, pake_placeholder_hash, username)

    # Save keys locally for the client to use
    client_storage_dir = "ClientStorage"
    if not os.path.exists(client_storage_dir):
        os.makedirs(client_storage_dir)
        
    private_key_path = os.path.join(client_storage_dir, f"{username}_private_key.pem")
    public_key_path = os.path.join(client_storage_dir, f"{username}_public_key.pem")

    # We save the private key encrypted with the user's password
    save_rsa_keys_to_files(private_key, public_key, private_key_path, public_key_path, password)
    print(f"Private and public keys saved to {client_storage_dir}/")
    print("\nUser creation process complete.")


if __name__ == "__main__":
    main()