from __future__ import annotations  # Lets us reference classes before they're defined (e.g. ScanHistory inside User)

import bcrypt  # Using bcrypt DIRECTLY instead of via passlib — avoids the passlib/bcrypt 4.1+ crash
import jwt  # For creating/decoding JWT access tokens
from datetime import datetime, timedelta, timezone  # Time handling for token expiry and timestamps
from contextlib import asynccontextmanager  # Needed for FastAPI's modern startup/shutdown lifespan
from typing import Optional, List  # Type hints
from fastapi import FastAPI, HTTPException, Depends, status  # Core FastAPI pieces
from fastapi.middleware.cors import CORSMiddleware  # Lets frontend (different origin) call this API
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm  # Standard OAuth2 login flow helpers
from pydantic import BaseModel  # Used for the simple scan request payload
from sqlmodel import SQLModel, Field, Relationship, Session, create_engine, select  # ORM + validation in one

# =============================================================================
# DATABASE SETUP
# =============================================================================
DATABASE_URL = "sqlite:///faro_detect.db"  # Local SQLite file as the database
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})  # check_same_thread=False needed for SQLite + FastAPI

def get_session():
    with Session(engine) as session:  # Opens a DB session per request
        yield session  # Hands the session to the route, then closes it automatically after

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)  # Creates all tables if they don't already exist

# =============================================================================
# MODELS (SQLModel)
# =============================================================================
class UserBase(SQLModel):
    email: str = Field(index=True, unique=True, nullable=False)  # Shared base field so we don't repeat ourselves

class User(UserBase, table=True):
    __tablename__ = "users"  # Explicit table name
    id: Optional[int] = Field(default=None, primary_key=True)  # Auto-incrementing primary key
    hashed_password: str  # Never store plain text passwords
    is_active: bool = Field(default=True)  # Allows disabling accounts without deleting them
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))  # Timezone-aware creation timestamp
    scans: List["ScanHistory"] = Relationship(back_populates="owner")  # One user -> many scans

class UserCreate(UserBase):
    password: str  # Plain password only exists transiently during registration input

class UserRead(UserBase):
    id: int  # What we expose back to clients (never the hashed_password)
    is_active: bool
    created_at: datetime

class UserLogin(SQLModel):
    email: str
    password: str

class ScanStatus:
    SAFE = "SAFE"  # Risk score below the suspicious threshold
    SUSPICIOUS = "SUSPICIOUS"  # Middle band, worth a warning
    SCAM = "SCAM"  # High confidence this is a scam

class ScanHistoryBase(SQLModel):
    message: str  # The raw text that was scanned
    risk_score: int = 0  # 0-100 numeric score
    status: str = ScanStatus.SAFE  # One of the ScanStatus values
    scam_category: Optional[str] = None  # e.g. "OTP Theft", "Phishing Link"
    reason: Optional[str] = None  # Human-readable explanation of why it was flagged
    confidence_level: float = 0.0  # 0.0-1.0 confidence in the verdict

class ScanHistory(ScanHistoryBase, table=True):
    __tablename__ = "scan_history"  # Explicit table name
    id: Optional[int] = Field(default=None, primary_key=True)  # Auto-incrementing primary key
    user_id: int = Field(foreign_key="users.id", nullable=False, index=True)  # Links scan to its owner
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)  # When the scan happened
    owner: Optional["User"] = Relationship(back_populates="scans")  # Many scans -> one user

class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
    timestamp: datetime

# FIX: with `from __future__ import annotations`, relationship type hints are strings.
# We explicitly rebuild the models so SQLModel/Pydantic can resolve "ScanHistory" and "User"
# now that BOTH classes exist in this module's namespace. Without this, mapper configuration
# can fail with NameError at first use (often the very first request, which looks like a "random crash").
User.model_rebuild()
ScanHistory.model_rebuild()

# Pydantic schema for the JSON body of POST /scan
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
SECRET_KEY = "CHANGE_ME_IN_PRODUCTION"  # TODO before your demo: replace with a real secret from an env variable
ALGORITHM = "HS256"  # JWT signing algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # Tokens last 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")  # Tells FastAPI where clients get tokens from

def get_password_hash(password: str) -> str:
    # bcrypt has a hard 72-BYTE limit on input; reject longer passwords with a clear error
    # instead of letting bcrypt silently truncate or throw a confusing internal error.
    password_bytes = password.encode("utf-8")  # Convert to bytes since bcrypt works on bytes
    if len(password_bytes) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or fewer")
    salt = bcrypt.gensalt()  # Generates a fresh random salt for this password
    hashed = bcrypt.hashpw(password_bytes, salt)  # Actually hashes the password
    return hashed.decode("utf-8")  # Store as a string in the database

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode("utf-8")  # Convert incoming password to bytes
    hashed_bytes = hashed_password.encode("utf-8")  # Convert stored hash back to bytes
    return bcrypt.checkpw(plain_bytes, hashed_bytes)  # True only if they match

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()  # Don't mutate the caller's dict
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))  # Compute expiry
    to_encode.update({"exp": expire})  # JWT standard "exp" claim
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # Sign and return the token string

def decode_access_token(token: str) -> TokenData:
    credentials_exception = HTTPException(  # Reused for any decode failure
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Verify signature + expiry
        email: str = payload.get("sub")  # We stored the user's email in the "sub" claim
        if email is None:
            raise credentials_exception
        return TokenData(email=email)
    except Exception:  # Covers expired tokens, bad signatures, malformed tokens, etc.
        raise credentials_exception

def get_user_by_email(session: Session, email: str):
    statement = select(User).where(User.email == email)  # Build the query
    return session.exec(statement).first()  # Return the first match or None

def authenticate_user(session: Session, email: str, password: str):
    user = get_user_by_email(session, email)  # Look the user up
    if not user or not verify_password(password, user.hashed_password):  # Fail closed on either miss
        return None
    return user

def get_current_user(
    token: str = Depends(oauth2_scheme),  # Pulls the bearer token out of the request header
    session: Session = Depends(get_session),
) -> User:
    token_data = decode_access_token(token)  # Validate + decode
    user = get_user_by_email(session, token_data.email)  # Look up the user the token claims to be
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:  # Blocks disabled accounts even with a valid token
        raise HTTPException(status_code=400, detail="Inactive user account")
    return current_user

# =============================================================================
# DETECTION ENGINE
# =============================================================================
# Each rule is (keywords, points, category_if_none_set, reason_fragment).
# Multiple rules can now fire and STACK, instead of only the first match setting the category.
DETECTION_RULES = [
    (["OTP", "PIN", "CODE SECRET", "MOT DE PASSE"], 40, "OTP/PIN Theft", "Request for a sensitive OTP, PIN, or password."),
    (["URGENT", "IMMEDIATELY", "SUSPENDED", "EXPIRE TODAY", "BLOCKED", "IMMEDIATEMENT"], 25, "Urgency Pressure", "Artificial urgency language detected."),
    (["MTN", "ORANGE", "MOMO", "MOBILE MONEY", "CAMTEL"], 20, "Fake Mobile Money Alert", "Spoofed Mobile Money / telecom reference."),
    (["HTTP", "WWW.", "BIT.LY", "CLICK HERE", "CLIQUEZ ICI"], 25, "Phishing Link", "Suspicious or shortened link detected."),
    (["WINNER", "PRIZE", "LOTTERY", "GAGNANT", "FELICITATION", "CONGRATULATIONS"], 25, "Lottery/Prize Scam", "Fake prize or lottery win offer."),
    (["SEND MONEY", "TRANSFER NOW", "ENVOYER", "VIREMENT"], 20, "Money Transfer Request", "Direct request to send or transfer money."),
    (["ACCOUNT WILL BE CLOSED", "VERIFY YOUR ACCOUNT", "VERIFIEZ VOTRE COMPTE"], 20, "Fake Verification Request", "Pressure to 'verify' an account."),
    (["FREE", "GRATUIT", "CADEAU", "BONUS"], 10, "Bait Offer", "Unsolicited free offer or bonus bait."),
    (["WHATSAPP INVESTMENT", "DOUBLE YOUR MONEY", "FOREX PROFIT"], 30, "Investment Scam", "Unrealistic investment or profit-doubling claim."),
]

def run_detection(message: str) -> dict:
    text_upper = message.upper()  # Case-insensitive matching
    risk = 0  # Running total risk score
    categories: List[str] = []  # All categories that matched (stacking, not just the first)
    reasons: List[str] = []  # All reason fragments that matched

    for keywords, points, category, reason_fragment in DETECTION_RULES:  # Check every rule
        if any(keyword in text_upper for keyword in keywords):  # Does any keyword for this rule appear?
            risk += points  # Add its points to the running score
            categories.append(category)  # Record which category it belongs to
            reasons.append(reason_fragment)  # Record why it was flagged

    risk = min(risk, 100)  # Cap the score at 100

    if not categories:  # Nothing matched at all
        scam_category = "Legitimate"
        reason = "No suspicious patterns detected."
    else:
        scam_category = " + ".join(categories)  # Combine ALL matched categories, e.g. "Urgency Pressure + Phishing Link"
        reason = " ".join(reasons)  # Combine all reasons into one explanation

    if risk < 25:
        scan_status = ScanStatus.SAFE  # Renamed from "status" to avoid shadowing FastAPI's status module
    elif risk < 60:
        scan_status = ScanStatus.SUSPICIOUS
    else:
        scan_status = ScanStatus.SCAM

    return {
        "risk_score": risk,  # Final numeric score 0-100
        "status": scan_status,  # SAFE / SUSPICIOUS / SCAM
        "scam_category": scam_category,  # All matched categories combined
        "reason": reason,  # All matched reasons combined
        "confidence_level": round(risk / 100, 2),  # Scaled directly from risk instead of just 2 fixed values
    }

# =============================================================================
# FASTAPI APP (with Modern Lifespan Event Handler)
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()  # Runs once on startup, before any requests are served
    yield  # App runs here; nothing needed on shutdown

app = FastAPI(
    title="Faro-Detect API",
    description="Scam detection API for Mobile Money, phishing, and fake notifications in Cameroon.",
    version="0.2.0",  # Bumped since detection engine changed
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to your actual frontend domain before going live
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}  # Simple health check for uptime monitors

@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    existing = get_user_by_email(session, user_in.email)  # Prevent duplicate accounts
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password))  # Hash before saving
    session.add(user)  # Stage the new row
    session.commit()  # Write it to the database
    session.refresh(user)  # Pull back the generated id/created_at
    return user

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = authenticate_user(session, form_data.username, form_data.password)  # OAuth2 form uses "username" for the email field
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})  # Embed the user's email as the token subject
    return Token(access_token=access_token, token_type="bearer")

@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    payload: ScanRequest,  # Safe JSON body parsing for the message to scan
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),  # Requires a valid, active login
):
    message = payload.message  # Extract the message text
    if not message or not message.strip():  # Reject empty/whitespace-only input
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    result = run_detection(message)  # Run it through the detection engine
    scan = ScanHistory(
        message=message,
        user_id=current_user.id,  # Tie this scan to the logged-in user
        **result,  # Unpacks risk_score, status, scam_category, reason, confidence_level
    )
    session.add(scan)  # Stage the new row
    session.commit()  # Save it
    session.refresh(scan)  # Pull back the generated id/timestamp
    return scan

@app.get("/scan/history", response_model=List[ScanHistoryRead])
def get_history(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),  # Only returns the logged-in user's own scans
):
    statement = (
        select(ScanHistory)
        .where(ScanHistory.user_id == current_user.id)  # Filter to this user only
        .order_by(ScanHistory.timestamp.desc())  # Most recent scans first
    )
    return session.exec(statement).all()

