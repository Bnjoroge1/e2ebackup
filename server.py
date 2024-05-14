#!/usr/bin/env python3
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
import os
from datetime import datetime, timedelta
import bcrypt
from aes import generate_key_pair



create_database()

#FastAPI routes. 
app = FastAPI()

def compute_checksum(file_content):
    """Compute SHA-256 checksum of file content."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

def encrypt_data(data, key):
    """Encrypt data using ChaCha20 cipher."""
    nonce = os.urandom(16)  # Generate a random nonce
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return nonce, encrypted_data
    
#database connection
def get_db():
     db = SessionLocal()
     try:
          yield db
     finally:
          db.close()
     


#User models 
class UserRegister(BaseModel):
     email: EmailStr
     password: str


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


@app.post("/signup")
def sign_up(user_data: UserRegister, db: Session = Depends(get_db)):
     #check if user already exists
     user = db.query(User).filter(User.email == user_data.email).first()
     if user:
          raise HTTPException(status_code=400, detail="Email is already registered")
     
     hashed_password = hash_password(user_data.password)
     _, public_key = generate_key_pair()


     # Store the user 
     new_user = User(
        email=user_data.email,
        password=hashed_password,
        encryption_keys = public_key
    )
     
     db.add(new_user)
     db.commit()
     db.refresh(new_user)
     return {"message": "User created successfully"}

     
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

#Handcoding for now but should prolly also be stored in the HSM keyvault. 
SECRET_KEY = "L39UIWMb1L2U2rCbtjcJSnHpqdHWo_BmxHpDWXLSew"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
 #jwt authentication
def create_access_token(data: dict, expires_delta: timedelta = None):
     to_encode = data.copy()
     expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
     to_encode.update({"exp": expire})
     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
     return encoded_jwt

def authenticate_user(email:str, password:str, db:Session):
     user  = db.query(User).filter(User.email==email).first()
     if not user or not verify_password(password, user.password):
          return False
     #verify password TODO using OPAQUE protocol.
     if not verify_password(password, user.password):
          return False
     return user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm= Depends(), db: Session = Depends(get_db)):
     user = authenticate_user(form_data.username, form_data.password, db)
     if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
     access_token = create_access_token(data={"sub": user.email})
     return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
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
        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user
# @app.post("/upload")
# def upload_file(file: UploadFile = File(...), token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
#     try:
#         # Decode file content
#         file_content = file.file.read()
#         encoded_content = base64.b64encode(file_content).decode('utf-8')

#         # Save file metadata to database
#         file_metadata = FileMetadata(
#             filename=file.filename,
#             content_type=file.content_type,
#             file_content=encoded_content
#         )
#         db.add(file_metadata)
#         db.commit()
#         db.refresh(file_metadata)

#         return {"message": "File uploaded successfully", "file_id": file_metadata.id}
#     finally:
#         file.file.close()

@app.post("/upload")
def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        # Decode file content
        file_content = file.file.read()
        key = os.urandom(32)  # 256-bit key
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
          









