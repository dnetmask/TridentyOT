import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user
from app.auth.security import generate_token, hash_token, verify_password
from app.config import SESSION_LIFETIME_SECONDS
from app.db import get_db
from app.i18n import message, resolve_locale
from app.models import AuthToken, User, utcnow
from app.schemas import LoginRequest, LoginResponse, UserOut, UserSelfUpdateRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    accept_language: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == payload.username).one_or_none()
    if user is None or not verify_password(payload.password, user.password_salt, user.password_hash):
        # No user resolved (or the wrong password for one) -- there's no
        # stored locale preference to trust either way, so this falls back
        # to the request's own Accept-Language.
        locale = resolve_locale(user.locale if user else None, accept_language)
        raise HTTPException(status_code=401, detail=message("auth.invalid_credentials", locale))

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


@router.patch("/me", response_model=UserOut)
def update_me(
    payload: UserSelfUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Lets any authenticated user (editor or viewer alike) change their own
    display-language preference -- unlike UserUpdateRequest in routes_users.py,
    which only an editor can use, and only to change role/password."""
    updates = payload.model_dump(exclude_unset=True)
    if "locale" in updates and updates["locale"]:
        user.locale = updates["locale"]
    db.commit()
    db.refresh(user)
    return user
