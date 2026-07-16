from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Relationship, Session, create_engine, select
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import jwt
import bcrypt
from pydantic import BaseModel

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
# MODELS
# =============================================================================
class UserBase(SQLModel):
    email: str = Field(index=True, unique=True, nullable=False)

class User(UserBase, table=True):
    __tablename__ = "users"
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    owner: Optional["User"] = Relationship(back_populates="scans")

class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
    timestamp: datetime

class ScanRequest(BaseModel):
    message: str

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(SQLModel):
    email: Optional[str] = None

# Rebuild models to resolve forward references
User.model_rebuild()
ScanHistory.model_rebuild()

# =============================================================================
# AUTHENTICATION
# =============================================================================
SECRET_KEY = "CHANGE_ME_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_password_hash(password: str) -> str:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or fewer")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
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
    except Exception:
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
DETECTION_RULES = [
    (["OTP", "PIN", "CODE SECRET", "MOT DE PASSE"], 40, "OTP/PIN Theft", "Request for sensitive OTP or PIN."),
    (["URGENT", "IMMEDIATELY", "SUSPENDED", "EXPIRE TODAY", "BLOCKED", "IMMEDIATEMENT"], 25, "Urgency Pressure", "Artificial urgency language."),
    (["MTN", "ORANGE", "MOMO", "MOBILE MONEY", "CAMTEL"], 20, "Fake Mobile Money Alert", "Spoofed Mobile Money reference."),
    (["HTTP", "WWW.", "BIT.LY", "CLICK HERE", "CLIQUEZ ICI"], 25, "Phishing Link", "Suspicious or shortened link."),
    (["WINNER", "PRIZE", "LOTTERY", "GAGNANT", "FELICITATION", "CONGRATULATIONS"], 25, "Lottery/Prize Scam", "Fake prize or lottery win."),
    (["SEND MONEY", "TRANSFER NOW", "ENVOYER", "VIREMENT"], 20, "Money Transfer Request", "Request to send money."),
    (["ACCOUNT WILL BE CLOSED", "VERIFY YOUR ACCOUNT", "VERIFIEZ VOTRE COMPTE"], 20, "Fake Verification Request", "Pressure to 'verify' an account."),
    (["FREE", "GRATUIT", "CADEAU", "BONUS"], 10, "Bait Offer", "Unsolicited free offer."),
    (["WHATSAPP INVESTMENT", "DOUBLE YOUR MONEY", "FOREX PROFIT"], 30, "Investment Scam", "Unrealistic investment claim."),
]

def run_detection(message: str) -> dict:
    text_upper = message.upper()
    risk = 0
    categories = []
    reasons = []

    for keywords, points, category, reason_fragment in DETECTION_RULES:
        if any(keyword in text_upper for keyword in keywords):
            risk += points
            categories.append(category)
            reasons.append(reason_fragment)

    risk = min(risk, 100)

    if not categories:
        scam_category = "Legitimate"
        reason = "No suspicious patterns detected."
    else:
        scam_category = " + ".join(categories)
        reason = " ".join(reasons)

    if risk < 25:
        status = ScanStatus.SAFE
    elif risk < 60:
        status = ScanStatus.SUSPICIOUS
    else:
        status = ScanStatus.SCAM

    return {
        "risk_score": risk,
        "status": status,
        "scam_category": scam_category,
        "reason": reason,
        "confidence_level": round(risk / 100, 2),
    }

# =============================================================================
# FASTAPI APP (with fixed CORS)
# =============================================================================
app = FastAPI(
    title="Faro-Detect API",
    description="Scam detection API for Mobile Money, phishing, and fake notifications in Cameroon.",
    version="0.2.0",
)

# --- CORS FIX: allow all origins, but set allow_credentials=False ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,      # <-- Set to False to avoid CORS preflight crash
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- Health ---
@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}

# --- Auth ---
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

# --- Scan ---
@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    payload: ScanRequest,
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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    owner: Optional["User"] = Relationship(back_populates="scans")

class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
    timestamp: datetime

class ScanRequest(BaseModel):
    message: str

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(SQLModel):
    email: Optional[str] = None

# Rebuild models to resolve forward references
User.model_rebuild()
ScanHistory.model_rebuild()

# =============================================================================
# AUTHENTICATION
# =============================================================================
SECRET_KEY = "CHANGE_ME_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_password_hash(password: str) -> str:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or fewer")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
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
    except Exception:
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
DETECTION_RULES = [
    (["OTP", "PIN", "CODE SECRET", "MOT DE PASSE"], 40, "OTP/PIN Theft", "Request for sensitive OTP or PIN."),
    (["URGENT", "IMMEDIATELY", "SUSPENDED", "EXPIRE TODAY", "BLOCKED", "IMMEDIATEMENT"], 25, "Urgency Pressure", "Artificial urgency language."),
    (["MTN", "ORANGE", "MOMO", "MOBILE MONEY", "CAMTEL"], 20, "Fake Mobile Money Alert", "Spoofed Mobile Money reference."),
    (["HTTP", "WWW.", "BIT.LY", "CLICK HERE", "CLIQUEZ ICI"], 25, "Phishing Link", "Suspicious or shortened link."),
    (["WINNER", "PRIZE", "LOTTERY", "GAGNANT", "FELICITATION", "CONGRATULATIONS"], 25, "Lottery/Prize Scam", "Fake prize or lottery win."),
    (["SEND MONEY", "TRANSFER NOW", "ENVOYER", "VIREMENT"], 20, "Money Transfer Request", "Request to send money."),
    (["ACCOUNT WILL BE CLOSED", "VERIFY YOUR ACCOUNT", "VERIFIEZ VOTRE COMPTE"], 20, "Fake Verification Request", "Pressure to 'verify' an account."),
    (["FREE", "GRATUIT", "CADEAU", "BONUS"], 10, "Bait Offer", "Unsolicited free offer."),
    (["WHATSAPP INVESTMENT", "DOUBLE YOUR MONEY", "FOREX PROFIT"], 30, "Investment Scam", "Unrealistic investment claim."),
]

def run_detection(message: str) -> dict:
    text_upper = message.upper()
    risk = 0
    categories = []
    reasons = []

    for keywords, points, category, reason_fragment in DETECTION_RULES:
        if any(keyword in text_upper for keyword in keywords):
            risk += points
            categories.append(category)
            reasons.append(reason_fragment)

    risk = min(risk, 100)

    if not categories:
        scam_category = "Legitimate"
        reason = "No suspicious patterns detected."
    else:
        scam_category = " + ".join(categories)
        reason = " ".join(reasons)

    if risk < 25:
        status = ScanStatus.SAFE
    elif risk < 60:
        status = ScanStatus.SUSPICIOUS
    else:
        status = ScanStatus.SCAM

    return {
        "risk_score": risk,
        "status": status,
        "scam_category": scam_category,
        "reason": reason,
        "confidence_level": round(risk / 100, 2),
    }

# =============================================================================
# FASTAPI APP (with fixed CORS)
# =============================================================================
app = FastAPI(
    title="Faro-Detect API",
    description="Scam detection API for Mobile Money, phishing, and fake notifications in Cameroon.",
    version="0.2.0",
)

# --- CORS FIX: allow all origins, but set allow_credentials=False ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,      # <-- Set to False to avoid CORS preflight crash
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- Health ---
@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}

# --- Auth ---
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

# --- Scan ---
@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    payload: ScanRequest,
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
