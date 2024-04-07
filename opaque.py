from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

# OPRF and Key Generation
def generate_oprf_key():
    return x25519.X25519PrivateKey.generate()

def client_blind(password):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    hashed_password = digest.finalize()
    
    client_private_key = x25519.X25519PrivateKey.generate()
    client_public_key = client_private_key.public_key()
    
    blinded_input = client_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return blinded_input, client_private_key

def perform_oprf(blinded_input, oprf_key):
    shared_secret = oprf_key.exchange(x25519.X25519PublicKey.from_public_bytes(blinded_input))
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'oprf',
    )
    oprf_output = hkdf.derive(shared_secret)
    return oprf_output

def client_unblind(oprf_output, client_private_key):
    private_key_bytes = client_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'unblind',
    )
    unblinded_output = hkdf.derive(private_key_bytes + oprf_output)
    return unblinded_output

# Key Exchange
def generate_key_pair():
    return x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate().public_key()

def derive_shared_key(private_key, public_key):
    shared_secret = private_key.exchange(public_key)
    print("shared secret: ", shared_secret)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session_key',
    )
    return hkdf.derive(shared_secret)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_with_rwd(data, rwd):
    # Ensure rwd is the correct length for AES-256 (32 bytes)
    if len(rwd) != 32:
        raise ValueError("RWD must be 32 bytes (256 bits) long for AES-256.")
    
    # Generate a random 96-bit (12 bytes) nonce for AES-GCM
    nonce = os.urandom(12)
    
    # Encrypt the data using AES-GCM with the provided rwd as the key
    aesgcm = AESGCM(rwd)
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    
    # Return the nonce concatenated with the encrypted data
    # The nonce is needed for decryption and is safe to store with the encrypted data
    return nonce + encrypted_data
# # Example Usage
# password = "securepassword"
# blinded_input, client_private_key = client_blind(password)
# oprf_key = generate_oprf_key()
# oprf_output = perform_oprf(blinded_input, oprf_key)
# final_output = client_unblind(oprf_output, client_private_key)

# # Simulate server key pair generation and exchange
# server_private_key, server_public_key = generate_key_pair()
# client_public_key = client_private_key.public_key()

# # Derive shared session keys
# client_session_key = derive_shared_key(client_private_key, server_public_key)
# server_session_key = derive_shared_key(server_private_key, client_public_key)
# # Print the public keys in a human-readable format (e.g., hex) to verify they are generated correctly
# print("Client Public Key:", client_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
# print("Server Public Key:", server_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
# print("Server Private Key:", server_private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
# print("Client Private Key:", client_private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
# print(client_session_key)
# print(server_session_key)
# assert client_session_key == server_session_key, "Session keys do not match."

# print("Session key established.")