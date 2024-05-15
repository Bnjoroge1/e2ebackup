import os
import base64
import hashlib
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, SecretStr
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodels import Base, User, FileMetadata, SessionLocal, engine, create_database
import jwt
from sqlalchemy.orm import Session
import secrets
import bcrypt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from aes import generate_key_pair, encrypt_aes_key_with_rsa, store_encrypted_key_in_hsm, encrypt_data

# Initialize the database and ORM
create_database()
app = FastAPI()

def compute_checksum(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

# Configuration for JWT Authentication
SECRET_KEY = "L39UIWMb1L2U2rCbtjcJSnHpqdHWo_BmxHpDWXLSew"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserRegister(BaseModel):
    email: EmailStr
    password: str

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

@app.post("/signup")
def sign_up(user_data: UserRegister, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email is already registered")

    hashed_password = hash_password(user_data.password)
    private_key, pem_private_key, pem_public_key = generate_key_pair()  # Corrected function call

    # Additional logic for storing the key securely or using it goes here

    new_user = User(email=user_data.email, password=hashed_password, encryption_keys=pem_public_key.decode())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(email: str, password: str, db: Session):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return False
    return user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        file_content = file.file.read()
        key = os.urandom(32)  # Generate a random key
        nonce, encrypted_content = encrypt_data(file_content, key)

        # Upload encrypted content to S3
        s3_client = boto3.client('s3')
        bucket_name = 'e2ebackups3'
        s3_key = f"encrypted_files/{file.filename}"

        s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=encrypted_content)


        checksum = compute_checksum(file_content)

        encoded_content = base64.b64encode(file_content).decode('utf-8')

        # Save file metadata to database
        file_metadata = FileMetadata(
            filename=file.filename,
            content_type=file.content_type,
            file_content=encoded_content,
            upload_date=datetime.now(),
            s3_key=s3_key,
            checksum=checksum
        )
        db.add(file_metadata)
        db.commit()
        db.refresh(file_metadata)
        return {"message": "File uploaded successfully", "file_id": file_metadata.id}
    finally:
        file.file.close()
