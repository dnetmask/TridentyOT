import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user
from app.auth.security import generate_token, hash_token, verify_password
from app.config import SESSION_LIFETIME_SECONDS
from app.db import get_db
from app.models import AuthToken, User, utcnow
from app.schemas import LoginRequest, LoginResponse, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).one_or_none()
    if user is None or not verify_password(payload.password, user.password_salt, user.password_hash):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    token = generate_token()
    expires_at = utcnow() + datetime.timedelta(seconds=SESSION_LIFETIME_SECONDS)
    db.add(AuthToken(token_hash=hash_token(token), user_id=user.id, expires_at=expires_at))
    db.commit()
    return LoginResponse(token=token, user=UserOut.model_validate(user))


@router.post("/logout", status_code=204)
def logout(authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        db.query(AuthToken).filter(AuthToken.token_hash == hash_token(token)).delete()
        db.commit()
    return None


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
