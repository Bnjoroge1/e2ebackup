# import click
# import requests
# import base64
# from opaque import client_blind, perform_oprf, client_unblind, generate_key_pair, encrypt_with_rwd
# from cryptography.hazmat.primitives import serialization

# # Assuming the server's OPRF endpoint
# LOGIN_ENDPOINT = "http://127.0.0.1:8000/login"
# REGISTRATION_ENDPOINT = "http://127.0.0.1:8000/signup"

# @click.group()
# def cli():
#     pass

# @cli.command()
# @click.option('--username', prompt=True)
# @click.option('--password', prompt=True, hide_input=True)
# def register(username, password):
    

    
#     registration_data = {
#         "email": username,
#         "password": password
#     }
#     response = requests.post(REGISTRATION_ENDPOINT, json=registration_data)
#     if response.status_code == 200:
#         print("Registration successful.")
#     else:
#         print("Registration failed:", response.text)

# @cli.command()
# @click.option('--username', prompt=True)
# @click.option('--password', prompt=True, hide_input=True)
# def login(username, password):
#     """Login an existing user."""
#     login_data = {
#         "username": username,
#         "password": password
#     }
#     response = requests.post(LOGIN_ENDPOINT, data=login_data)
#     if response.status_code == 200:
#         print("Login successful.")
#         print("Token:", response.json().get("access_token"))
#     else:
#         print("Login failed:", response.text)

# if __name__ == "__main__":
#     cli()



import click
import requests
import base64
from opaque import client_blind, perform_oprf, client_unblind, generate_key_pair, encrypt_with_rwd
from cryptography.hazmat.primitives import serialization

# Assuming the server's OPRF endpoint
LOGIN_ENDPOINT = "http://127.0.0.1:8000/login"
REGISTRATION_ENDPOINT = "http://127.0.0.1:8000/signup"
UPLOAD_ENDPOINT = "http://127.0.0.1:8000/upload"
DOWNLOAD_ENDPOINT = "http://127.0.0.1:8000/download/{file_id}"

@click.group()
def cli():
    pass

@cli.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
def register(username, password):
    """Create a new user"""
    registration_data = {
        "email": username,
        "password": password
    }
    response = requests.post(REGISTRATION_ENDPOINT, json=registration_data)
    if response.status_code == 200:
        print("Registration successful.")
    else:
        print("Registration failed:", response.text)

@cli.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
def login(username, password):
    """Login an existing user and return the access token."""
    login_data = {
        "username": username,
        "password": password
    }
    response = requests.post(LOGIN_ENDPOINT, data=login_data)
    if response.status_code == 200:
        print("Login successful.")
        token = response.json().get("access_token")
        print("Token:", token)
        return token
    else:
        print("Login failed:", response.text)
        return None

@cli.command()
@click.option('--token', prompt="Access token for authentication", help="Access token for authentication")
@click.option('--file', type=click.Path(exists=True), help="Path to the file to upload")
def upload(token, file):
    """Upload a file to the server using an authentication token."""
    with open(file, 'rb') as f:
        files = {'file': (file, f, 'application/octet-stream')} 
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.post(UPLOAD_ENDPOINT, files=files, headers=headers)
        if response.status_code == 200:
            click.echo("File uploaded successfully.")
            click.echo(response.json())
        else:
            click.echo(f"Failed to upload file: {response.text}")


@cli.command()
@click.option("--token", prompt="Access token for authentication", help="Access token for authentication")
@click.option("--file_id", prompt="File ID to download", help="File ID to download")
def download(token, file_id):
    """Download a file from the server."""
    url = f"{DOWNLOAD_ENDPOINT.format(file_id=file_id)}"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers, stream=True)

    if response.status_code == 200:
        content_disposition = response.headers.get('Content-Disposition')
        if content_disposition:
            filename = content_disposition.split("filename=")[1]
        else:
            # Handling the case where there is no Content-Disposition header
            filename = f'{file_id}-downloaded.ext'
            
           
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        click.echo(f"File downloaded successfully: {filename}")
    else:
        click.echo(f"Failed to download file: {response.text}")

if __name__ == "__main__":
    cli()