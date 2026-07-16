from __future__ import annotations

import os
from datetime import datetime
from typing import Optional, List

from sqlmodel import SQLModel, Field, Relationship, Session, create_engine


# --- Database Setup ---
DATABASE_FILE = os.getenv("FARO_DB_FILE", "faro_detect.db")
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise


# --- Models ---
class UserBase(SQLModel):
    email: str = Field(index=True, unique=True, nullable=False)


class User(UserBase, table=True):
    __tablename__ = "users"
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    scans: List["ScanHistory"] = Relationship(back_populates="owner")


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int
    is_active: bool
    created_at: datetime


class UserLogin(SQLModel):
    email: str
    password: str


class ScanStatus:
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    SCAM = "SCAM"


class ScanHistoryBase(SQLModel):
    message: str = Field(nullable=False)
    risk_score: int = Field(default=0, ge=0, le=100)
    status: str = Field(default=ScanStatus.SAFE)
    scam_category: Optional[str] = Field(default=None)
    reason: Optional[str] = Field(default=None)
    confidence_level: float = Field(default=0.0, ge=0.0, le=1.0)


class ScanHistory(ScanHistoryBase, table=True):
    __tablename__ = "scan_history"
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False, index=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    owner: Optional[User] = Relationship(back_populates="scans")


class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
    timestamp: datetime


class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(SQLModel):
    email: Optional[str] = Noneclass UserBase(SQLModel):
    email: str = Field(index=True, unique=True, nullable=False)


class User(UserBase, table=True):
    __tablename__ = "users"
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    scans: List["ScanHistory"] = Relationship(back_populates="owner")


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int
    is_active: bool
    created_at: datetime


class UserLogin(SQLModel):
    email: str
    password: str


class ScanStatus:
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    SCAM = "SCAM"


class ScanHistoryBase(SQLModel):
    message: str = Field(nullable=False)
    risk_score: int = Field(default=0, ge=0, le=100)
    status: str = Field(default=ScanStatus.SAFE)
    scam_category: Optional[str] = Field(default=None)
    reason: Optional[str] = Field(default=None)
    confidence_level: float = Field(default=0.0, ge=0.0, le=1.0)


class ScanHistory(ScanHistoryBase, table=True):
    __tablename__ = "scan_history"
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False, index=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    owner: Optional[User] = Relationship(back_populates="scans")


class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
    timestamp: datetime


class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(SQLModel):
    email: Optional[str] = None
