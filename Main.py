import os
import base64
import string
import random
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import re
import subprocess

CONF_DIR = "Conf"
ENC_DIR = "Enc"
os.makedirs(CONF_DIR, exist_ok=True)
os.makedirs(ENC_DIR, exist_ok=True)

# Maak de mappen onzichtbaar op Windows
if os.name == "nt":
    subprocess.call(["attrib", "+h", CONF_DIR])
    subprocess.call(["attrib", "+h", ENC_DIR])

HASH_FILE = os.path.join(CONF_DIR, "Secret_Hash.conf")
SALT_FILE = os.path.join(CONF_DIR, "Secret_Salt.conf")
KEY_FILE = os.path.join(CONF_DIR, "Secret_Key.key")

if not all(os.path.exists(f) for f in [HASH_FILE, SALT_FILE, KEY_FILE]):
    print("Error: Configuratiebestanden ontbreken. Voer eerst MasterHasher.py uit.")
    exit(1)

master_password = input("Voer je master wachtwoord in: ")

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
    print("\nToegang verleend: Wachtwoord correct!\n")
except:
    print("Toegang geweigerd: Wachtwoord incorrect!")
    exit(1)

aes_key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, 100000, dklen=32)

def encrypt_file(file_path):
    if not os.path.exists(file_path):
        print("Fout: Bestand bestaat niet!")
        return
    
    print("\nWAARSCHUWING: Dit bestand wordt versleuteld! Toegang vereist het masterwachtwoord!\n")

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

    print(f"Bestand versleuteld: {encrypted_file_path}")

    os.remove(file_path)
    print(f"Origineel bestand verwijderd: {file_path}")

def decrypt_file(file_name):
    encrypted_file_path = os.path.join(ENC_DIR, file_name + ".enc")

    if not os.path.exists(encrypted_file_path):
        print("Fout: Versleuteld bestand bestaat niet!")
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

    print(f"Bestand ontsleuteld: {original_file_path}")

    os.remove(encrypted_file_path)
    print(f"Versleuteld bestand verwijderd: {encrypted_file_path}")

def generate_password(length, use_uppercase, use_numbers, use_special_chars):
    all_chars = string.ascii_lowercase
    if use_uppercase:
        all_chars += string.ascii_uppercase
    if use_numbers:
        all_chars += string.digits
    if use_special_chars:
        all_chars += string.punctuation

    password = ''.join(random.choice(all_chars) for _ in range(length))
    return password

def check_password_strength(password):
    length_check = len(password) >= 8
    upper_check = any(c.isupper() for c in password)
    number_check = any(c.isdigit() for c in password)
    special_check = any(c in string.punctuation for c in password)
    
    strength = 0
    if length_check:
        strength += 1
    if upper_check:
        strength += 1
    if number_check:
        strength += 1
    if special_check:
        strength += 1
    
    if strength == 4:
        return "Zeer sterk", "n.v.t."
    elif strength == 3:
        return "Sterk", get_password_tips(strength)
    elif strength == 2:
        return "Gemiddeld", get_password_tips(strength)
    else:
        return "Zwak", get_password_tips(strength)

def get_password_tips(strength):
    tips = []
    if strength < 4:
        tips.append("- Voeg een speciale teken toe (zoals @, #, $, %).")
    if strength < 3:
        tips.append("- Voeg een cijfer toe.")
    if strength < 2:
        tips.append("- Voeg een hoofdletter toe.")
    if strength < 1:
        tips.append("- Maak het wachtwoord langer dan 8 tekens.")
    return tips

def menu():
    while True:
        print("\nMENU:")
        print("1  Versleutel een bestand")
        print("2  Ontsleutel een bestand")
        print("3  Genereer een wachtwoord")
        print("4  Controleer wachtwoordsterkte")
        print("5  Afsluiten")

        keuze = input("\nKies een optie (1/2/3/4/5): ")

        if keuze == "1":
            bestand = input("Voer het pad in van het bestand dat je wilt versleutelen: ")
            encrypt_file(bestand)

        elif keuze == "2":
            bestand = input("Voer de naam in van het versleutelde bestand (zonder '.enc'): ")
            decrypt_file(bestand)

        elif keuze == "3":
            lengte = int(input("Geef de lengte van het wachtwoord: "))
            use_uppercase = input("Gebruik hoofdletters? (y/n): ").strip().lower() == 'y'
            use_numbers = input("Gebruik cijfers? (y/n): ").strip().lower() == 'y'
            use_special_chars = input("Gebruik speciale tekens? (y/n): ").strip().lower() == 'y'
            
            wachtwoord = generate_password(lengte, use_uppercase, use_numbers, use_special_chars)
            print(f"Genereerd wachtwoord: {wachtwoord}")

        elif keuze == "4":
            wachtwoord = input("Voer het wachtwoord in om de sterkte te meten: ")
            sterkte, tips = check_password_strength(wachtwoord)
            print(f"Wachtwoordsterkte: {sterkte}")
            if tips != "n.v.t.":
                print("Tips om je wachtwoord te verbeteren:")
                for tip in tips:
                    print(f"  - {tip}")

        elif keuze == "5":
            print("Afsluiten...")
            exit(0)

        else:
            print("Ongeldige keuze, probeer opnieuw!")

menu()
