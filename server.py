#!/usr/bin/env python3
import base64
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, SecretStr
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodels import Base, User, FileMetadata, SessionLocal, engine
import jwt
from sqlalchemy.orm import Session
import secrets
import os
from datetime import datetime, timedelta
from opaque import *




#FastAPI routes. 
app = FastAPI()

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
     password: SecretStr

class UserLogin(BaseModel):
     email: EmailStr
     # Instead of a password, we accept the blinded password and possibly other OPAQUE-related fields
     client_public_key: Optional[str] = Field(None, description="Client's ephemeral public key, base64 or hex-encoded")
     encrypted_envelope: str
class OPRFInput(BaseModel):
     email: EmailStr
     blinded_input: str
     server_public_key: str

#ORPF endpoint
@app.post("/oprf")
def oprf(input_data: OPRFInput, db: Session = Depends(get_db)):
    # Decode the blinded password from base64
    print(f"Received data: {input_data.model_dump_json()}")

    blinded_input_bytes = base64.b64decode(input_data.blinded_password)
    
    # Generate server's OPRF key (this should be stored and reused, not generated on each request)
    oprf_key = generate_oprf_key()
    
    # Perform OPRF with the client's blinded password
    oprf_output = perform_oprf(blinded_input_bytes, oprf_key)

    #generate private and public key pair for the server
    server_private_key, server_public_key = generate_key_pair()
    server_public_key=server_public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw),
    
    # Encode the OPRF output to base64 to send back to the client
    oprf_output_base64 = base64.b64encode(oprf_output).decode()

    #store in User database
    user = db.query(User).filter(User.email==input_data.email).first()
    user.oprf_key = oprf_output_base64
    user.server_public_key = server_public_key
    if user:
         db.commit()
         db.refresh(user)
    else: 
          raise HTTPException(status_code=400, detail="User not found")
    return {"oprf_output": oprf_output_base64,
            "server_public_key": server_public_key}


@app.post("/signup")
def sign_up(user_data: UserRegister, db: Session = Depends(get_db)):
     #check if user already exists
     user = db.query(User).filer(User.email == user_data.email).first()
     if user:
          raise HTTPException(status_code=400, detail="Email is alrady registered")
     
     # Generate OPAQUE materials
     # Decode the blinded_password and client_public_key from base64
   
     client_public_key_bytes = base64.b64decode(user_data.client_public_key)
     encrypted_envelope_bytes = base64.b64decode(user_data.encrypted_envelope)

  
     # Generate server's OPAQUE key pair
     
     
     
     # Store the user with necessary OPAQUE materials
     new_user = User(
        email=user_data.email,
        client_public_key=client_public_key_bytes,
        encrypted_envelope=base64.b64decode(user_data.encrypted_envelope),  # Assuming encrypted_envelope is also base64-encoded
        
    )
     
     db.add(new_user)
     db.commit()
     db.refresh(new_user)
     return {"message": "User created successfully"}

     

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
     if not user:
          return False
     #verify password TODO using OPAQUE protocol.
     if not verify_password(password, user.hashed_password):
          return False
     return user

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm= Depends(), db: Session = Depends(get_db)):
     user = authenticate_user(form_data.username, form_data.password, db)
     if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
     access_token = create_access_token(data={"sub": user.email})
     return {"access_token": access_token, "token_type": "bearer"}

          






