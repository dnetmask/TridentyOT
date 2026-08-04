from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import ROLE_EDITOR
from app.auth.deps import require_editor
from app.auth.security import hash_password
from app.db import get_db
from app.i18n import message
from app.models import User
from app.schemas import UserCreateRequest, UserOut, UserUpdateRequest

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), current: User = Depends(require_editor)):
    return (
        db.query(User)
        .filter(User.organization_id == current.organization_id)
        .order_by(User.username)
        .all()
    )


@router.post("", response_model=UserOut, status_code=201)
def create_user(payload: UserCreateRequest, db: Session = Depends(get_db), current: User = Depends(require_editor)):
    if db.query(User).filter(User.username == payload.username).one_or_none() is not None:
        raise HTTPException(status_code=409, detail=message("users.duplicate_username", current.locale))

    salt, password_hash = hash_password(payload.password)
    user = User(
        organization_id=current.organization_id,
        username=payload.username,
        password_salt=salt,
        password_hash=password_hash,
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _remaining_editors(db: Session, organization_id: int | None, excluding_user_id: int) -> int:
    return (
        db.query(User)
        .filter(
            User.organization_id == organization_id,
            User.role == ROLE_EDITOR,
            User.id != excluding_user_id,
        )
        .count()
    )


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    current: User = Depends(require_editor),
):
    user = db.query(User).filter(User.id == user_id, User.organization_id == current.organization_id).one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail=message("users.not_found", current.locale))

    updates = payload.model_dump(exclude_unset=True)

    if "role" in updates and updates["role"] != user.role:
        if user.role == ROLE_EDITOR and _remaining_editors(db, user.organization_id, user.id) == 0:
            raise HTTPException(
                status_code=400,
                detail=message("users.cannot_remove_last_editor_role", current.locale),
            )
        user.role = updates["role"]

    if updates.get("password"):
        user.password_salt, user.password_hash = hash_password(updates["password"])

    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), current: User = Depends(require_editor)):
    user = db.query(User).filter(User.id == user_id, User.organization_id == current.organization_id).one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail=message("users.not_found", current.locale))
    if user.id == current.id:
        raise HTTPException(status_code=400, detail=message("users.cannot_delete_self", current.locale))
    if user.role == ROLE_EDITOR and _remaining_editors(db, user.organization_id, user.id) == 0:
        raise HTTPException(status_code=400, detail=message("users.cannot_delete_last_editor", current.locale))

    db.delete(user)
    db.commit()
    return None
