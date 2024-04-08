#!/usr/bin/env python3
import base64
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, SecretStr
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodels import Base, User, FileMetadata, SessionLocal, engine, create_database
import jwt
from sqlalchemy.orm import Session
import secrets
import os
from datetime import datetime, timedelta

import bcrypt



create_database()

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
     password: str




     


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


@app.post("/signup")
def sign_up(user_data: UserRegister, db: Session = Depends(get_db)):
     #check if user already exists
     user = db.query(User).filter(User.email == user_data.email).first()
     if user:
          raise HTTPException(status_code=400, detail="Email is alrady registered")
     
     hashed_password = hash_password(user_data.password)
    
  
     
     
     
     
     # Store the user 
     new_user = User(
        email=user_data.email,
        password=hashed_password
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

          






