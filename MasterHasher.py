import os
import base64
import shutil
import sys
import subprocess
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

CONF_DIR = "Conf"
os.makedirs(CONF_DIR, exist_ok=True)

HASH_FILE = os.path.join(CONF_DIR, "Secret_Hash.conf")
SALT_FILE = os.path.join(CONF_DIR, "Secret_Salt.conf")
KEY_FILE = os.path.join(CONF_DIR, "Secret_Key.key")

master_password = input("Voer je master wachtwoord in: ")

salt = os.urandom(64)

ph = PasswordHasher()
hashed_password = ph.hash(master_password + salt.hex())

key = Fernet.generate_key()
cipher = Fernet(key)

encrypted_hash = cipher.encrypt(hashed_password.encode())

with open(SALT_FILE, "wb") as f:
    f.write(salt)

with open(KEY_FILE, "wb") as f:
    f.write(key)

with open(HASH_FILE, "wb") as f:
    f.write(encrypted_hash)

print("\nWachtwoord geconfigureerd en bestanden opgeslagen in 'Conf'!")

def self_delete():
    script_name = os.path.basename(__file__)
    exe_name = script_name.replace(".py", ".exe")

    files_to_delete = [script_name, exe_name]

    for file in files_to_delete:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"Verwijderd: {file}")
            except PermissionError:
                print(f"Geen toegang tot {file}, schakel over naar Windows-opdracht...")
                delete_cmd = f'cmd /c timeout 2 & del "{file}"'
                subprocess.Popen(delete_cmd, shell=True)
                print(f"{file} wordt binnen enkele seconden verwijderd...")

self_delete()
