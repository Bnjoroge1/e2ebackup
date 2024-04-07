#!/usr/bin/env python3
from pydantic import BaseModel, EmailStr, SecretStr
from fastapi import FastAPI, Depends, HTTPException
from sqlmodels import Base, User, FileMetadata, SessionLocal, engine
import jwt
from sqlalchemy.orm import Session



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

     








