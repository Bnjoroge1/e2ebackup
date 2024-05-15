import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class MockPyKCS11:
    CKF_SERIAL_SESSION = 1
    CKF_RW_SESSION = 2
    CKO_SECRET_KEY = 3
    CKK_AES = 4
    CKA_CLASS = 5
    CKA_KEY_TYPE = 6
    CKA_VALUE = 7
    CKA_ENCRYPT = 8
    CKA_DECRYPT = 9

    def __init__(self):
        self.sessions = {}

    def load(self, path):
        print(f"Loaded library from {path}")

    def getSlotList(self, tokenPresent=True):
        return [1]

    def openSession(self, slot, flags):
        self.sessions[slot] = "session"
        return self.sessions[slot]

    def createObject(self, session, key_template):
        return "key_handle"

pkcs11 = MockPyKCS11()
pkcs11.load("/fake/path/libcloudhsm_pkcs11.so")
session = pkcs11.openSession(1, pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION)

def generate_aes_key(key_size=256):
    return os.urandom(key_size // 8)

def generate_key_pair():
    """
    Generate an RSA key pair and return the private key object, PEM-encoded private key,
    and PEM-encoded public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem_private_key, pem_public_key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def store_encrypted_key_in_hsm(encrypted_aes_key):
    key_template = [
        (pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
        (pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
        (pkcs11.CKA_VALUE, encrypted_aes_key),
        (pkcs11.CKA_ENCRYPT, True),
        (pkcs11.CKA_DECRYPT, True)
    ]
    key_handle = pkcs11.createObject(session, key_template)
    return key_handle

def encrypt_data(data, key_handle):
    if len(key_handle) not in {16, 24, 32}:  # Ensuring key is 128, 192, or 256 bits
        raise ValueError("Invalid key size for AES. Key must be 128, 192, or 256 bits.")

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key_handle), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return nonce, encryptor.tag, encrypted_data

def decrypt_data(encrypted_data, nonce, tag, key_handle):
    cipher = Cipher(algorithms.AES(key_handle), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data
