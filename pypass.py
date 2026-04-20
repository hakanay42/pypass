# my password manager project - prototype
# Hakan Ay - 4250
# Information Systems - Course Project 1

# need to install this first: pip install cryptography

import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# passwords will be saved here
SAVE_FILE = "my_passwords.json"


# this function takes the master password and makes an encryption key from it
# i learned about PBKDF2 from the cryptography docs, it makes brute force very slow
def get_key(master_pw, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=310000,   # NIST says this is safe enough
        backend=default_backend()
    )
    return kdf.derive(master_pw.encode())


# encrypt a password using AES-256
def lock(text, key):
    iv = os.urandom(16)  # random IV so same password encrypts differently each time

    # AES needs the input to be a specific size so we add padding
    p = padding.PKCS7(128).padder()
    padded_text = p.update(text.encode()) + p.finalize()

    # do the actual encryption
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    encrypted = enc.update(padded_text) + enc.finalize()

    # HMAC is like a checksum - if someone changes the file we will know
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + encrypted)
    mac = h.finalize()

    # combine everything and encode as base64 so it can be saved as text
    return base64.b64encode(iv + mac + encrypted).decode()


# decrypt a password
def unlock(token, key):
    raw = base64.b64decode(token)

    # split the parts back out
    iv        = raw[:16]
    mac       = raw[16:48]
    encrypted = raw[48:]

    # check the HMAC first - wrong password will fail here
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(iv + encrypted)
    h.verify(mac)

    # decrypt
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(encrypted) + dec.finalize()

    # remove the padding we added earlier
    up = padding.PKCS7(128).unpadder()
    return (up.update(padded) + up.finalize()).decode()


# load saved passwords from file
def load_data(key):
    if not os.path.exists(SAVE_FILE):
        return {}

    with open(SAVE_FILE, "r") as f:
        saved = json.load(f)

    if not saved.get("data"):
        return {}

    try:
        decrypted = unlock(saved["data"], key)
        return json.loads(decrypted)
    except:
        print("Wrong password! Cannot open vault.")
        return None


# save passwords to file
def save_data(all_passwords, key, salt):
    to_save = {
        "salt": base64.b64encode(salt).decode(),
        "data": lock(json.dumps(all_passwords), key)
    }
    with open(SAVE_FILE, "w") as f:
        json.dump(to_save, f)


# ---- start of program ----

print("PyPass - my password manager")
print("prototype version\n")

# first time using it
if not os.path.exists(SAVE_FILE):
    print("No vault found. Creating a new one...")
    master = getpass.getpass("Choose a master password: ")
    salt = os.urandom(32)
    key = get_key(master, salt)
    save_data({}, key, salt)
    print("Done! Vault created.\n")

else:
    # load the salt from existing file
    with open(SAVE_FILE, "r") as f:
        existing = json.load(f)
    salt = base64.b64decode(existing["salt"])

    master = getpass.getpass("Enter master password: ")
    key = get_key(master, salt)

# load the passwords
passwords = load_data(key)
if passwords is None:
    exit()

print("Vault opened!\n")

# main loop
while True:
    print("What do you want to do?")
    print("1 - add a password")
    print("2 - get a password")
    print("3 - see all services")
    print("0 - quit")

    choice = input("\n> ").strip()

    if choice == "1":
        service  = input("Service name (ex: gmail): ").strip()
        username = input("Username or email: ").strip()
        pw       = getpass.getpass("Password: ")

        passwords[service] = {
            "user": username,
            "pw":   pw
        }
        save_data(passwords, key, salt)
        print("Saved!\n")

    elif choice == "2":
        service = input("Which service? ").strip()
        if service in passwords:
            print(f"Username: {passwords[service]['user']}")
            print(f"Password: {passwords[service]['pw']}\n")
        else:
            print("Not found.\n")

    elif choice == "3":
        if not passwords:
            print("Nothing saved yet.\n")
        else:
            print("Saved services:")
            for s in passwords:
                print(f"  - {s}")
            print()

    elif choice == "0":
        print("Bye!")
        break
    else:
        print("Please enter 1, 2, 3 or 0\n")
