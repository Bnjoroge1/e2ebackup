import click
import requests
import base64
from opaque import client_blind, perform_oprf, client_unblind, generate_key_pair, encrypt_with_rwd
from cryptography.hazmat.primitives import serialization

# Assuming the server's OPRF endpoint
OPRF_ENDPOINT = "http://127.0.0.1:8000/oprf"
REGISTRATION_ENDPOINT = "http://127.0.0.1:8000/signup"

@click.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
def register(username, password):
    # Step 1: Blind the password
    blinded_input, client_private_key_blind = client_blind(password)
    
    # Step 2: Send blinded password to server and receive OPRF result
    # Note: The server needs the blinded password to perform its part of the OPRF
    response = requests.post(OPRF_ENDPOINT, json={"blinded_input": base64.b64encode(blinded_input).decode()})
    if response.status_code != 200:
        raise Exception("Failed to perform OPRF with the server.")
    oprf_result = base64.b64decode(response.json()["oprf_output"])
    server_public_key = base64.b64decode(response.json()["server_public_key"])
    
    # Step 3: Unblind the OPRF result to derive rwd
    rwd = client_unblind(oprf_result, client_private_key_blind)
    
    # Step 4: Generate a new private/public key pair for the client's OPAQUE identity
    client_private_key, client_public_key = generate_key_pair()
    client_private_key_bytes = client_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    #decode the server public key
    server_public_key_bytes = base64.b64decode(server_public_key)

     # Concatenate client's private key and server's public key for encryption
    data_to_encrypt = client_private_key_bytes + server_public_key_bytes

    #Encrypt the concatenated data with rwd to create encrypted envelope. 
    encrypted_envelope_bytes = encrypt_with_rwd(data_to_encrypt, rwd)

    
    # Step 6: Send the encrypted_envelope, the client's public key, and the blinded password to the server
    registration_data = {
        "email": username,  
        "client_public_key": base64.b64encode(client_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode(),
        "encrypted_envelope": base64.b64encode(encrypted_envelope_bytes).decode()
    }
    registration_response = requests.post(REGISTRATION_ENDPOINT, json=registration_data)
    if registration_response.status_code == 200:
        print("Registration successful.")
    else:
        print("Registration failed:", registration_response.text)

if __name__ == "__main__":
    register()