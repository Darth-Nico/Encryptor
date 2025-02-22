import os
import base64
import shutil
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

CONF_DIR = "Conf"
os.makedirs(CONF_DIR, exist_ok=True)

HASH_FILE = os.path.join(CONF_DIR, "Secret_Hash.conf")
SALT_FILE = os.path.join(CONF_DIR, "Secret_Salt.conf")
KEY_FILE = os.path.join(CONF_DIR, "Secret_Key.key")

master_password = input("🔑 Kies een Master Wachtwoord: ").strip()
if len(master_password) < 8:
    print("❌ Wachtwoord moet minimaal 8 tekens lang zijn!")
    exit(1)

salt = os.urandom(64)
key = Fernet.generate_key()
cipher = Fernet(key)

ph = PasswordHasher()
hashed_password = ph.hash(master_password + salt.hex())

encrypted_hash = cipher.encrypt(hashed_password.encode())

with open(SALT_FILE, "wb") as f:
    f.write(salt)

with open(KEY_FILE, "wb") as f:
    f.write(key)

with open(HASH_FILE, "wb") as f:
    f.write(encrypted_hash)

print("✅ Master wachtwoord opgeslagen en beveiligd!")

script_path = os.path.abspath(__file__)
print(f"🗑️ Script wordt verwijderd: {script_path}")
os.remove(script_path)
