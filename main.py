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
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    # Add your deployed frontend URL here, e.g., "https://faro-detect.vercel.app"
]

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


# --- AUTH ROUTES ---
@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    existing_user = session.exec(select(User).where(User.email == user_in.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(credentials: UserLogin, session: Session = Depends(get_session)):
    user = authenticate_user(session, credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return Token(access_token=access_token, token_type="bearer")


# --- SCAN ROUTES ---
@app.post("/scan", response_model=ScanHistoryRead, status_code=status.HTTP_201_CREATED)
def scan_message(
    message: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
    if not message or not message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
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


# --- HEALTH CHECK ---
@app.get("/")
def read_root():
    return {"status": "ok", "service": "Faro-Detect API"}
