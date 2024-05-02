import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Function to generate a new AES key
def generate_aes_key(key_size=256):
    return os.urandom(key_size // 8)

# Function to securely store the AES key
def encrypt_and_store_aes_key(aes_key, public_key_path):
    # Load the public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Encrypt the AES key with the RSA public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Store the encrypted AES key
    with open("encrypted_aes_key.bin", "wb") as key_file:
        key_file.write(encrypted_key)

    return encrypted_key


# Example usage
if __name__ == "__main__":
    # Generate AES key
    aes_key = generate_aes_key()

    # Assume that the public key is already generated and saved to a file
    # Encrypt the AES key with the RSA public key and store it
    encrypted_key = encrypt_and_store_aes_key(aes_key, 'public_key.pem')