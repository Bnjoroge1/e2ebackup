**End-to-end encrypted backup, using an TEE system such
as AWS Nitro enclaves.**
Demo here: https://bnjoroge1-e2ebackup-streamlit-ojlxhx.streamlit.app
Overview
This project aims to design and implement a system for end-to-end encrypted backups, utilizing Trusted Execution Environments (TEE) such as AWS Nitro Enclaves, and integrating with AWS Cloud HSM for secure key management. The system ensures secure processing, authentication, and encrypted storage of backup data in AWS S3.

Features
User Authentication: Secure login functionality to authenticate users before performing backup or restore operations.
Key Management:
Key Generation: Keys are generated securely and stored within AWS Cloud HSM, ensuring strong encryption for backups.
Key Lifecycle Management: Including key rotation, expiration, and revocation.

Encryption/Decryption:
Uses robust encryption algorithms for securing data before storage.
Integration with AWS Nitro for performing encryption within a secure enclave.
Secure File Storage:
Data is encrypted at rest and stored in Amazon S3.
Secure Communication:
All data transmitted between the client and server is encrypted and integrity-protected.
Data Integrity:
Implementation of checksums to ensure the integrity of data during transfer and storage.
Technologies Used
AWS Nitro Enclaves
AWS Cloud HSM
Amazon S3
Streamlit UI
Docker
Python (FastAPI, SQLAlchemy, cryptography libraries)


**Installation**
## Clone the repository:
```git clone https://github.com/bnjoroge1/e2ebackup.git```
## Change into the project directory:
```cd e2ebackup```
if you have docker installed, you can run the docker container
```docker build -t e2ebackup .```
```docker run -p 8000:8000 e2ebackup```
if not, you can run the project locally

Create a virtual environment:
```python3 -m venv venv```
Activate the virtual environment:
```source venv/bin/activate```
Install the dependencies:
```pip install -r requirements.txt```
Run the FastAPI server:
```uvicorn app.main:app --reload```
Open your browser and go to http://127.0.0.1:8000
then you can use the streamlit UI to interact with the API
```streamlit run streamlit.py```

Alternatively, you can use the API directly using tools like curl or Postman, or the client.py implementation that scaffolds the API calls.
run python3 client.py to interact with the API, with the required arguments. Run python3 client.py --help to see the available options.


Here is a more complete technical doc for the project: https://docs.google.com/document/d/1A_IaWtBNe1nDcBhuzflGDWajiMS0SM5NiQlVME2-1Nc/edit?usp=sharing