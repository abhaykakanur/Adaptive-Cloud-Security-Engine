from cryptography.fernet import Fernet
import os


KEY_FILE = "secret.key"


def generate_key():
    key = Fernet.generate_key()

    with open(KEY_FILE, "wb") as f:
        f.write(key)


def load_key():

    if not os.path.exists(KEY_FILE):
        generate_key()

    return open(KEY_FILE, "rb").read()


key = load_key()
cipher = Fernet(key)


def encrypt_data(data: bytes) -> bytes:
    return cipher.encrypt(data)


def decrypt_data(data: bytes) -> bytes:
    return cipher.decrypt(data)
