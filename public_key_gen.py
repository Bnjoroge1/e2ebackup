from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pair
def generate_rsa_key_pair(private_key_path, public_key_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Save the private key to a file
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Save the public key to a file
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("RSA key pair generated successfully.")



if __name__ == "__main__":
    # File paths for the keys
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"

    # Generate the RSA key pair
    generate_rsa_key_pair(private_key_path, public_key_path)