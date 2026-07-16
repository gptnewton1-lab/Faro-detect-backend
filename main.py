from __future__ import annotations  # <-- Solves the type-hint forward reference issue

import jwt
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import SQLModel, Field, Relationship, Session, create_engine, select

# =============================================================================
# DATABASE SETUP
# =============================================================================
DATABASE_URL = "sqlite:///faro_detect.db"
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})

def get_session():
    with Session(engine) as session:
        yield session

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# =============================================================================
# MODELS (SQLModel)
# =============================================================================
class UserBase(SQLModel):
    email: str = Field(index=True, unique=True, nullable=False)

class User(UserBase, table=True):
    __tablename__ = "users"
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    # Corrected modern timezone-aware default_factory
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scans: List[ScanHistory] = Relationship(back_populates="owner")

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
    message: str
    risk_score: int = 0
    status: str = ScanStatus.SAFE
    scam_category: Optional[str] = None
    reason: Optional[str] = None
    confidence_level: float = 0.0

class ScanHistory(ScanHistoryBase, table=True):
    __tablename__ = "scan_history"
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False, index=True)
    # Corrected modern timezone-aware default_factory
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    owner: Optional[User] = Relationship(back_populates="scans")

class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
    timestamp: datetime

# Pydantic schema to handle JSON payload inside HTTP POST requests safely
class ScanRequest(BaseModel):
    message: str

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(SQLModel):
    email: Optional[str] = None

# =============================================================================
# AUTHENTICATION
# =============================================================================
SECRET_KEY = "CHANGE_ME_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    # Fixed deprecated naive datetime
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> TokenData:
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
        return TokenData(email=email)
    except Exception:  # Unified catch-all for JWT issues
        raise credentials_exception

def get_user_by_email(session: Session, email: str):
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def authenticate_user(session: Session, email: str, password: str):
    user = get_user_by_email(session, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    token_data = decode_access_token(token)
    user = get_user_by_email(session, token_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user account")
    return current_user

# =============================================================================
# DETECTION ENGINE
# =============================================================================
def run_detection(message: str) -> dict:
    text_upper = message.upper()
    risk = 0
    category = "Legitimate"
    reason = "No suspicious patterns detected."
    confidence = "Low"

    if "OTP" in text_upper or "PIN" in text_upper:
        risk += 40
        category = "OTP Theft"
        reason = "Request for sensitive OTP or PIN detected."
        confidence = "High"

    if "URGENT" in text_upper or "IMMEDIATELY" in text_upper or "SUSPENDED" in text_upper:
        risk += 30
        if category == "Legitimate":
            category = "Urgency Scam"
        reason += " Urgency language detected."

    if "MTN" in text_upper or "ORANGE" in text_upper or "MOMO" in text_upper:
        risk += 20
        if category == "Legitimate":
            category = "Fake Mobile Money Alert"
        reason += " Spoofed Mobile Money reference."

    if "http" in message.lower() or "www." in message.lower():
        risk += 25
        if category == "Legitimate":
            category = "Phishing Link"
        reason += " Suspicious link detected."

    if "WINNER" in text_upper or "PRIZE" in text_upper or "LOTTERY" in text_upper:
        risk += 25
        if category == "Legitimate":
            category = "Lottery Scam"
        reason += " Fake prize offer."

    risk = min(risk, 100)

    if risk < 25:
        status = ScanStatus.SAFE
    elif risk < 60:
        status = ScanStatus.SUSPICIOUS
    else:
        status = ScanStatus.SCAM

    return {
        "risk_score": risk,
        "status": status,
        "scam_category": category,
        "reason": reason,
        "confidence_level": 0.9 if confidence == "High" else 0.5,
    }

# =============================================================================
# FASTAPI APP (with Modern Lifespan Event Handler)
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initializes database structures on application load
    create_db_and_tables()
    yield

app = FastAPI(
    title="Faro-Detect API",
    description="Scam detection API for Mobile Money, phishing, and fake notifications in Cameroon.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS Middleware config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Health check ---
@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}

# --- Authentication routes ---
@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    existing = get_user_by_email(session, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return Token(access_token=access_token, token_type="bearer")

# --- Scan routes (protected) ---
@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    payload: ScanRequest,  # <-- Uses ScanRequest payload model for safe HTTP POST JSON requests
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
    message = payload.message
    if not message or not message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    result = run_detection(message)
    scan = ScanHistory(
        message=message,
        user_id=current_user.id,
        **result,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan

@app.get("/scan/history", response_model=List[ScanHistoryRead])
def get_history(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
    statement = (
        select(ScanHistory)
        .where(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.timestamp.desc())
    )
    return session.exec(statement).all()
