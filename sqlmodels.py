
from sqlalchemy import LargeBinary, create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime





SQLALCHEMY_DATABASE_URL = "sqlite:///./e2ebackup.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

#SQLAlchemy models 
class User(Base):
     __tablename__ = 'users'
     id = Column(Integer, primary_key=True)
     email = Column(String, unique=True, index=True)
     password = Column(String)     
     files = relationship("FileMetadata", back_populates="user")
     encryption_keys = relationship("EncryptionKey", back_populates="user")
     backup_sessions = relationship("BackupSession", back_populates="user")
     access_logs = relationship("AccessLog", back_populates="user")
     audit_trails = relationship("AuditTrail", back_populates="user")

class FileMetadata(Base):
    __tablename__ = 'file_metadata'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    filename = Column(String)
    file_size = Column(Integer)
    file_content = Column(String)
    content_type = Column(String)
    s3_key = Column(String)
    #reference to where the key is securely stored i.e Cloud HSM
    encryption_key_id = Column(Integer, ForeignKey('encryption_keys.id'))
    checksum = Column(String)
    upload_date = Column(DateTime, default=datetime.datetime.utcnow)
    modification_date = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    user = relationship("User", back_populates="files")
    encryption_key = relationship("EncryptionKey", back_populates="files")

class EncryptionKey(Base):
    __tablename__ = 'encryption_keys'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    key_metadata = Column(Text)
    key_status = Column(String)
    creation_date = Column(DateTime, default=datetime.datetime.utcnow)
    expiration_date = Column(DateTime)
    user = relationship("User", back_populates="encryption_keys")
    files = relationship("FileMetadata", back_populates="encryption_key")

class BackupSession(Base):
    __tablename__ = 'backup_sessions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    start_time = Column(DateTime, default=datetime.datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String)
    files_backed_up = Column(Integer)
    user = relationship("User", back_populates="backup_sessions")

class AccessLog(Base):
    __tablename__ = 'access_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
    status = Column(String)
    user = relationship("User", back_populates="access_logs")

class AuditTrail(Base):
    __tablename__ = 'audit_trails'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    affected_resources = Column(Text)
    user = relationship("User", back_populates="audit_trails")

def create_database():
    Base.metadata.create_all(engine)