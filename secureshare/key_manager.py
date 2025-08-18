# key_manager.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

MASTER_KEY = hashlib.sha256(b"my_master_encryption_key").digest()  # Should be secret & 32 bytes

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + chr(pad_len) * pad_len

def unpad(data):
    pad_len = ord(data[-1])
    return data[:-pad_len]

def encrypt_aes_key(aes_key: str) -> bytes:
    cipher = AES.new(MASTER_KEY, AES.MODE_ECB)
    padded = pad(aes_key).encode()
    encrypted = cipher.encrypt(padded)
    return encrypted  # store as BINARY in DB

def decrypt_aes_key(enc_key: bytes) -> str:
    cipher = AES.new(MASTER_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(enc_key).decode()
    return unpad(decrypted)
