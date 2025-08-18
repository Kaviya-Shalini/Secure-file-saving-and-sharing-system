from Crypto.Cipher import AES
import hashlib

def pad(data):
    return data + b' ' * (16 - len(data) % 16)
def unpad(data):
    return data.rstrip(b' ')

def encrypt_file(file_data, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(file_data))

def encrypt_aes_key(user_key, master_secret):
    master_key = hashlib.sha256(master_secret.encode()).digest()
    cipher = AES.new(master_key, AES.MODE_ECB)
    padded_key = pad(user_key.encode())
    return cipher.encrypt(padded_key)
def decrypt_aes_key(enc_data, master_secret):
    key = hashlib.sha256(master_secret.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(enc_data)).decode()

def decrypt_file(enc_data, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(enc_data).rstrip(b' ')
