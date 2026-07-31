from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth import ROLE_EDITOR
from app.auth.security import hash_token
from app.db import get_db
from app.models import AuthToken, User, utcnow


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="No autenticado")

    token = authorization.split(" ", 1)[1].strip()
    auth_token = db.query(AuthToken).filter(AuthToken.token_hash == hash_token(token)).one_or_none()
    if auth_token is None:
        raise HTTPException(status_code=401, detail="Sesión inválida")

    now = utcnow()
    expires_at = auth_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=now.tzinfo)
    if expires_at < now:
        db.delete(auth_token)
        db.commit()
        raise HTTPException(status_code=401, detail="Sesión expirada, vuelve a iniciar sesión")

    user = db.get(User, auth_token.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Sesión inválida")
    return user


def require_editor(user: User = Depends(get_current_user)) -> User:
    if user.role != ROLE_EDITOR:
        raise HTTPException(status_code=403, detail="Esta acción requiere el perfil de editor")
    return user
