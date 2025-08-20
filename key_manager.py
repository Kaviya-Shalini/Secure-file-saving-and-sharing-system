# key_manager.py
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Master key derived from secrets (32 bytes)
MASTER_KEY = hashlib.sha256(st.secrets["security"]["master_key"].encode()).digest()

# Wrap the 16-char user AES key using AES-GCM with the app's master key
def encrypt_aes_key(aes_key: str) -> bytes:
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(aes_key.encode())
    return cipher.nonce + tag + ct  # bytes

def decrypt_aes_key(enc_key: bytes) -> str:
    nonce = enc_key[:16]
    tag   = enc_key[16:32]
    ct    = enc_key[32:]
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
    key = cipher.decrypt_and_verify(ct, tag)
    return key.decode()
