#!/usr/bin/env python3
from pydantic import BaseModel, EmailStr, SecretStr
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodels import Base, User, FileMetadata, SessionLocal, engine
import jwt
from sqlalchemy.orm import Session
import secrets
import os
from datetime import datetime, timedelta




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
     password: SecretStr



@app.post("/signup")
def sign_up(user_data: UserRegister, db: Session = Depends(get_db)):
     #check if user already exists
     user = db.query(User).filer(User.email == user_data.email).first()
     if user:
          raise HTTPException(status_code=400, detail="Email is alrady registered")
     password = get_password(user_data.password)
     new_user = User(email=user_data.email, hashed_password=password)
     db.add(new_user)
     db.commit()
     db.refresh(new_user)
     return {"message": "User created successfully"}

     

#Handcoding for now but should prolly also be stored in the HSM keyvault. 
SECRET_KEY = "L39UIWMb1L2U2rCbtjcJSnHpqdHWo_BmxHpDWXLSew"
ALGORITHM = "H256"

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

          






