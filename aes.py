import os
import boto3
import PyKCS11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Function to generate a new AES key
def generate_aes_key(key_size=256):
    return os.urandom(key_size // 8)


def generate_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize the private key using PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key using PEM format
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key, pem_public_key

# Function to encrypt the AES key with an RSA public key
def encrypt_aes_key_with_rsa(aes_key, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Load the PKCS11 library
lib_path = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"  # Ensure this path is correct
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib_path)
slot = pkcs11.getSlotList(tokenPresent=True)[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

def store_key_in_hsm(aes_key):
    """Store AES key in AWS CloudHSM and return key handle."""
    session.login("CryptoUser", "password")  # Use actual user and password
    key_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
        (PyKCS11.CKA_VALUE, aes_key),
    ]
    key_handle = session.createObject(key_template)
    session.logout()
    return key_handle
    
# def encrypt_data(data, aes_key):
#     """Encrypt the provided data using AES GCM."""
#     iv = os.urandom(1)2
#     cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(data) + encryptor.finalize()
#     return iv + encryptor.tag + ciphertext

# def upload_encrypted_data_to_s3(encrypted_data, bucket_name, key_name):
#     """Upload encrypted data to S3."""
#     s3 = boto3.client('s3')
#     s3.put_object(Bucket=bucket_name, Key=key_name, Body=encrypted_data)

# def perform_backup(data, bucket_name, key_name):
#     aes_key = generate_aes_key()
#     key_handle = store_key_in_hsm(aes_key)
#     encrypted_data = encrypt_data(data, aes_key)
#     upload_encrypted_data_to_s3(encrypted_data, bucket_name, key_name)

# Example usage
data = b'Some important backup data'
bucket_name = 'your-s3-bucket-name'
key_name = 'backup/encrypted_data.enc'
#perform_backup(data, bucket_name, key_name)


if __name__ == "__main__":  
    # Generate AES key
    aes_key = generate_aes_key()

    # Encrypt AES key using RSA public key
    encrypted_key = encrypt_aes_key_with_rsa(aes_key, 'public_key.pem')

    # Store encrypted AES key in CloudHSM
    key_handle = store_key_in_hsm(encrypted_key)

    # Encrypt the data using the AES key
    #ciphertext = encrypt_data(data, aes_key)

    #






# # Function to securely store the AES key
# def encrypt_and_store_aes_key(aes_key, public_key_path):
#     # Load the public key
#     with open(public_key_path, "rb") as key_file:
#         public_key = serialization.load_pem_public_key(
#             key_file.read(),
#             backend=default_backend()
#         )

#     # Encrypt the AES key with the RSA public key
#     encrypted_key = public_key.encrypt(
#         aes_key,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )

#     # Store the encrypted AES key
#     with open("encrypted_aes_key.bin", "wb") as key_file:
#         key_file.write(encrypted_key)

#     return encrypted_key