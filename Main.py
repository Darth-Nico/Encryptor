import os
import base64
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONF_DIR = "Conf"
ENC_DIR = "Enc"
os.makedirs(ENC_DIR, exist_ok=True)

HASH_FILE = os.path.join(CONF_DIR, "Secret_Hash.conf")
SALT_FILE = os.path.join(CONF_DIR, "Secret_Salt.conf")
KEY_FILE = os.path.join(CONF_DIR, "Secret_Key.key")

if not all(os.path.exists(f) for f in [HASH_FILE, SALT_FILE, KEY_FILE]):
    print("❌ Error: Configuratiebestanden ontbreken. Voer eerst MasterHasher.py uit.")
    exit(1)

master_password = input("🔑 Voer je master wachtwoord in: ")

with open(SALT_FILE, "rb") as f:
    salt = f.read()

with open(KEY_FILE, "rb") as f:
    key = f.read()

with open(HASH_FILE, "rb") as f:
    encrypted_hash = f.read()

from cryptography.fernet import Fernet
cipher = Fernet(key)
decrypted_hash = cipher.decrypt(encrypted_hash).decode()

ph = PasswordHasher()
try:
    ph.verify(decrypted_hash, master_password + salt.hex())
    print("\n✅ Toegang verleend: Wachtwoord correct!\n")

except:
    print("❌ Toegang geweigerd: Wachtwoord incorrect!")
    exit(1)

import hashlib
aes_key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, 100000, dklen=32)

def encrypt_file(file_path):
    if not os.path.exists(file_path):
        print("❌ Fout: Bestand bestaat niet!")
        return
    
    print("\n⚠️ WAARSCHUWING: Dit bestand wordt versleuteld! Toegang vereist het masterwachtwoord!\n")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        data = f.read()

    padding_length = 16 - (len(data) % 16)
    data += bytes([padding_length]) * padding_length

    encrypted_data = encryptor.update(data) + encryptor.finalize()

    file_name = os.path.basename(file_path)
    encrypted_file_path = os.path.join(ENC_DIR, file_name + ".enc")

    with open(encrypted_file_path, "wb") as f:
        f.write(iv + encrypted_data)

    print(f"✅ Bestand versleuteld: {encrypted_file_path}")

    os.remove(file_path)
    print(f"🗑️ Origineel bestand verwijderd: {file_path}")

def decrypt_file(file_name):
    encrypted_file_path = os.path.join(ENC_DIR, file_name + ".enc")

    if not os.path.exists(encrypted_file_path):
        print("❌ Fout: Versleuteld bestand bestaat niet!")
        return

    with open(encrypted_file_path, "rb") as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    original_file_path = os.path.join(os.getcwd(), file_name)
    with open(original_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ Bestand ontsleuteld: {original_file_path}")

    os.remove(encrypted_file_path)
    print(f"🗑️ Versleuteld bestand verwijderd: {encrypted_file_path}")

def menu():
    while True:
        print("\n🔐 MENU:")
        print("1️⃣  Versleutel een bestand")
        print("2️⃣  Ontsleutel een bestand")
        print("3️⃣  Afsluiten")

        keuze = input("\nKies een optie (1/2/3): ")

        if keuze == "1":
            bestand = input("Voer het pad in van het bestand dat je wilt versleutelen: ")
            encrypt_file(bestand)

        elif keuze == "2":
            bestand = input("Voer de naam in van het versleutelde bestand (zonder '.enc'): ")
            decrypt_file(bestand)

        elif keuze == "3":
            print("👋 Afsluiten...")
            exit(0)

        else:
            print("❌ Ongeldige keuze, probeer opnieuw!")

menu()
