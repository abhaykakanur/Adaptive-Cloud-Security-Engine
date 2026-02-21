from cryptography.fernet import Fernet
import base64
import hashlib


# ---------------- KEY GENERATOR ----------------

def generate_key(password: str):

    # Always generate valid 32-byte Fernet key
    digest = hashlib.sha256(password.encode()).digest()

    return base64.urlsafe_b64encode(digest)


# ---------------- ENCRYPT ----------------

def encrypt_data(data: bytes, password: str, level: str):

    # Generate base key
    base_key = generate_key(password)

    # LOW / MEDIUM → Single encryption
    if level in ["LOW", "MEDIUM"]:

        f = Fernet(base_key)
        encrypted = f.encrypt(data)

        return encrypted, base_key


    # HIGH → Double encryption
    else:

        key1 = generate_key(password + "1")
        key2 = generate_key(password + "2")

        f1 = Fernet(key1)
        f2 = Fernet(key2)

        stage1 = f1.encrypt(data)
        stage2 = f2.encrypt(stage1)

        return stage2, (key1, key2)


# ---------------- DECRYPT ----------------

def decrypt_data(data: bytes, password: str, level: str):

    if level in ["LOW", "MEDIUM"]:

        key = generate_key(password)
        f = Fernet(key)

        return f.decrypt(data)


    else:

        key1 = generate_key(password + "1")
        key2 = generate_key(password + "2")

        f1 = Fernet(key1)
        f2 = Fernet(key2)

        stage1 = f2.decrypt(data)
        original = f1.decrypt(stage1)

        return original