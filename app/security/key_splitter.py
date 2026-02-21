# app/security/key_splitter.py

import base64
import secrets
from Crypto.Protocol.SecretSharing import Shamir


def split_key(key: bytes, parts: int, threshold: int):
    """
    Split encryption key into shares using Shamir Secret Sharing
    """

    # Ensure key is 16 bytes (AES compatible)
    if len(key) < 16:
        key = key.ljust(16, b"0")

    key = key[:16]

    shares = Shamir.split(threshold, parts, key)

    encoded = []

    for idx, share in shares:
        data = base64.b64encode(share).decode()
        encoded.append(f"{idx}:{data}")

    return encoded


def rebuild_key(shares: list):
    """
    Rebuild key from shares
    """

    decoded = []

    for item in shares:
        idx, data = item.split(":")
        decoded.append(
            (int(idx), base64.b64decode(data))
        )

    key = Shamir.combine(decoded)

    return key