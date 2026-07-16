from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from typing import List

from models import (
    User, UserCreate, UserRead, ScanHistory, ScanHistoryRead,
    Token, get_session, create_db_and_tables
)
from auth import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, get_current_active_user
)
from detection import run_detection


app = FastAPI(
    title="Faro-Detect API",
    description="Scam detection API for Mobile Money, phishing, and fake notifications in Cameroon.",
    version="0.1.0",
)


# --- CORS ---
origins = ["*"]  # Replace with your Vercel URL later
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


# --- Auth Routes ---
@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    existing_user = session.exec(select(User).where(User.email == user_in.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return Token(access_token=access_token, token_type="bearer")


# --- Scan Routes ---
@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    message: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
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


# --- Health Check ---
@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}        raise HTTPException(status_code=400, detail="Message cannot be empty")
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


# --- Health Check ---
@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}    created_at: datetime

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

# --- Security (pure Python, no bcrypt compilation needed) ---
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Use pbkdf2_sha256 – pure Python, no compiler required
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
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
    except jwt.PyJWTError:
        raise credentials_exception
    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise credentials_exception
    return user

# --- App & CORS ---
app = FastAPI(title="Faro-Detect", description="Protecting Cameroonians from mobile money scams")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

# --- Detection Engine ---
def analyze_text(text: str):
    text_upper = text.upper()
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

    if "http" in text.lower() or "www." in text.lower():
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
        status = "Safe"
    elif risk < 60:
        status = "Warning"
    else:
        status = "Dangerous"

    return {
        "risk_score": risk,
        "status": status,
        "category": category,
        "reason": reason,
        "confidence": confidence
    }

# --- API Endpoints ---
@app.get("/")
def root():
    return {"message": "Faro-Detect is alive! Use /docs for API documentation"}

@app.post("/register")
def register(user: UserCreate, session: Session = Depends(get_session)):
    existing = session.exec(select(User).where(User.email == user.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {"message": "User created successfully", "user": UserRead.from_orm(db_user)}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/scan/analyze")
async def analyze_scan(request: dict, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    message = request.get("message")
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    result = analyze_text(message)
    scan = ScanHistory(
        user_id=current_user.id,
        message=message,
        risk_score=result["risk_score"],
        status=result["status"],
        scam_category=result["category"],
        reason=result["reason"],
        confidence_level=float(result["confidence"] == "High") * 0.9 or 0.5
    )
    session.add(scan)
    session.commit()
    return result

@app.get("/scan/history", response_model=List[ScanHistoryRead])
async def get_history(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    scans = session.exec(select(ScanHistory).where(ScanHistory.user_id == current_user.id).order_by(ScanHistory.timestamp.desc())).all()
    return scans
