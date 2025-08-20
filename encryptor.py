# encryptor.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Encrypts raw file bytes with user's 16-char key using AES-GCM
def encrypt_file(file_data: bytes, user_key: str) -> bytes:
    # Derive 32-byte key from the user's 16-char key
    key = hashlib.sha256(user_key.encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM)       # random nonce auto-generated
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    # Store: nonce(16) + tag(16) + ciphertext
    return cipher.nonce + tag + ciphertext

def decrypt_file(enc_data: bytes, user_key: str) -> bytes:
    key = hashlib.sha256(user_key.encode()).digest()
    nonce = enc_data[:16]
    tag   = enc_data[16:32]
    ct    = enc_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # will raise ValueError if tampered/wrong key
    return cipher.decrypt_and_verify(ct, tag)
