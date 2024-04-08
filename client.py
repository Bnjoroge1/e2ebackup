import click
import requests
import base64
from opaque import client_blind, perform_oprf, client_unblind, generate_key_pair, encrypt_with_rwd
from cryptography.hazmat.primitives import serialization

# Assuming the server's OPRF endpoint
LOGIN_ENDPOINT = "http://127.0.0.1:8000/login"
REGISTRATION_ENDPOINT = "http://127.0.0.1:8000/signup"

@click.group()
def cli():
    pass

@cli.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
def register(username, password):
    

    
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
    """Login an existing user."""
    login_data = {
        "username": username,
        "password": password
    }
    response = requests.post(LOGIN_ENDPOINT, data=login_data)
    if response.status_code == 200:
        print("Login successful.")
        print("Token:", response.json().get("access_token"))
    else:
        print("Login failed:", response.text)

if __name__ == "__main__":
    cli()

