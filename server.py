import os
import base64
import hashlib
import boto3
import io
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, SecretStr
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from sqlmodels import Base, User, FileMetadata, SessionLocal, engine, create_database, EncryptionKey
import jwt
from sqlalchemy.orm import Session
import secrets
import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from aes import generate_key_pair, encrypt_aes_key_with_rsa, store_encrypted_key_in_hsm, encrypt_data, decrypt_data

# Initialize the database and ORM
create_database()
app = FastAPI()

load_dotenv()

#set up S3
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    
)
def compute_checksum(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

# Configuration for JWT Authentication. should prob be moved to .env
SECRET_KEY = "L39UIWMb1L2U2rCbtjcJSnHpqdHWo_BmxHpDWXLSew"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user
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
    private_key, pem_private_key, pem_public_key = generate_key_pair()  
    new_user = User(email=user_data.email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    encryption_key = EncryptionKey(
        user_id=new_user.id,
        key_metadata=pem_public_key.decode(),
        key_status="active",
        creation_date=datetime.utcnow(),
        expiration_date=datetime.utcnow() + timedelta(days=365)  
    )

    db.add(encryption_key)
    db.commit()
    db.refresh(encryption_key)
    return {"message": "User created successfully"}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=60))
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
        print("len key: ", len(key))
        if len(key) not in {16, 24, 32}:  # Ensuring key is 128, 192, or 256 bits
            raise ValueError("Invalid key size for AES. Key must be 128, 192, or 256 bits.")
        nonce, tag, encrypted_content = encrypt_data(file_content, key)

        # Upload encrypted content to S3
        s3_client = boto3.client('s3')
        bucket_name = 'e2ebackups3'
        s3_key = f"encrypted_files/{file.filename}"

        s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=encrypted_content)


        checksum = compute_checksum(file_content)

        encoded_content = base64.b64encode(file_content).decode('utf-8')
         # Encode key, nonce, and tag for storage
        encoded_key = b64encode(key).decode('utf-8')
        encoded_nonce = b64encode(nonce).decode('utf-8')
        encoded_tag = b64encode(tag).decode('utf-8')

        # Save file metadata to database
        file_metadata = FileMetadata(
            filename=file.filename,
            content_type=file.content_type,
            file_content=encoded_content,
            upload_date=datetime.now(),
            s3_key=s3_key,
            checksum=checksum,
            tag=encoded_tag,
            nonce=encoded_nonce,
            encryption_key_s=encoded_key
        )
        db.add(file_metadata)
        db.commit()
        db.refresh(file_metadata)
        return {"message": "File uploaded successfully", "file_id": file_metadata.id}
    finally:
        file.file.close()

@app.get("/download/{file_id}")
async def download_file(file_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Retrieve file metadata from the database
    file_metadata = db.query(FileMetadata).filter(FileMetadata.id == file_id).first()
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    # Retrieve the file from S3
    s3_client = boto3.client('s3')
    response = s3_client.get_object(Bucket='e2ebackups3', Key=file_metadata.s3_key)
    file_content = response['Body'].read()
    # Decode key, nonce, and tag
    key = b64decode(file_metadata.encryption_key_s)
    nonce = b64decode(file_metadata.nonce)
    tag = b64decode(file_metadata.tag)

    # Decrypt the file content
    decrypted_content = decrypt_data(file_content, nonce, tag, key)
    

    # Return the decrypted file as a download
    return StreamingResponse(io.BytesIO(decrypted_content), media_type=file_metadata.content_type)