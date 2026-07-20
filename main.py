
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, Relationship, Session, create_engine, select
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import jwt
from passlib.context import CryptContext
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

User.model_rebuild()
ScanHistory.model_rebuild()

# =============================================================================
# AUTHENTICATION
# =============================================================================
SECRET_KEY = "CHANGE_ME_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return TokenData(email=email)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_user_by_email(session: Session, email: str):
    return session.exec(select(User).where(User.email == email)).first()

def authenticate_user(session: Session, email: str, password: str):
    user = get_user_by_email(session, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    token_data = decode_access_token(token)
    user = get_user_by_email(session, token_data.email)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
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
        if any(kw in text_upper for kw in keywords):
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
        scan_status = ScanStatus.SAFE
    elif risk < 60:
        scan_status = ScanStatus.SUSPICIOUS
    else:
        scan_status = ScanStatus.SCAM

    return {
        "risk_score": risk,
        "status": scan_status,
        "scam_category": scam_category,
        "reason": reason,
        "confidence_level": round(risk / 100, 2),
    }

# =============================================================================
# FASTAPI APP
# =============================================================================
app = FastAPI(
    title="Faro-Detect API",
    description="Scam detection API for Mobile Money, phishing, and fake notifications in Cameroon.",
    version="0.2.0",
)

# =============================================================================
# CORS
# =============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# ROOT ENDPOINT — JUST JSON (NO HTML)
# =============================================================================
@app.get("/")
def root():
    return {
        "message": "Faro-Detect API is live",
        "docs": "/docs",
        "endpoints": {
            "register": "/auth/register",
            "login": "/auth/login",
            "scan": "/scan",
            "history": "/scan/history"
        }
    }

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# =============================================================================
# API ENDPOINTS
# =============================================================================
@app.get("/health")
def health():
    return {"status": "ok", "service": "Faro-Detect API"}

@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    if get_user_by_email(session, user_in.email):
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
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return Token(access_token=create_access_token(data={"sub": user.email}), token_type="bearer")

@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    payload: ScanRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    result = run_detection(payload.message)
    scan = ScanHistory(message=payload.message, user_id=current_user.id, **result)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan

@app.get("/scan/history", response_model=List[ScanHistoryRead])
def get_history(session: Session = Depends(get_session), current_user: User = Depends(get_current_active_user)):
    return session.exec(select(ScanHistory).where(ScanHistory.user_id == current_user.id).order_by(ScanHistory.timestamp.desc())).all()
