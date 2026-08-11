from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import ROLE_ADMIN, ROLE_SUPER_ADMIN
from app.auth.deps import is_super_admin, require_admin
from app.auth.security import hash_password
from app.db import get_db
from app.i18n import message
from app.models import User
from app.schemas import UserCreateRequest, UserOut, UserUpdateRequest

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(
    organization_id: int | None = None,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    query = db.query(User)
    if is_super_admin(current):
        if organization_id is not None:
            query = query.filter(User.organization_id == organization_id)
    else:
        # An admin can only ever see their own organization's users --
        # any organization_id they pass is ignored rather than honored, so
        # they can't probe another organization's user list by guessing ids.
        query = query.filter(User.organization_id == current.organization_id)
    return query.order_by(User.username).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(payload: UserCreateRequest, db: Session = Depends(get_db), current: User = Depends(require_admin)):
    if payload.role == ROLE_SUPER_ADMIN:
        # Only an existing Super Admin can mint another one -- an admin
        # hitting this with role=super_admin is treated the same as if the
        # role didn't exist at all.
        if not is_super_admin(current):
            raise HTTPException(status_code=403, detail=message("auth.super_admin_required", current.locale))
        # A super_admin has no organization, like the caller -- payload.organization_id
        # (meant for a new admin/viewer) doesn't apply here and is ignored.
        organization_id = None
    elif current.organization_id is None:
        # A super_admin has no organization of its own to default to --
        # they must say which organization the new admin/viewer belongs to.
        if payload.organization_id is None:
            raise HTTPException(status_code=400, detail=message("users.super_admin_has_no_organization", current.locale))
        organization_id = payload.organization_id
    else:
        # An admin's new user always belongs to their own organization --
        # any organization_id they pass is ignored, mirroring list_users.
        organization_id = current.organization_id

    # organization_id IS NULL for every super_admin, so this scopes the
    # duplicate check to "other super_admins" when creating one -- same
    # shape as the per-organization check for admin/viewer, matching the
    # partial unique index on User (see models.py).
    duplicate_query = db.query(User).filter(User.username == payload.username)
    duplicate_query = (
        duplicate_query.filter(User.organization_id.is_(None))
        if organization_id is None
        else duplicate_query.filter(User.organization_id == organization_id)
    )
    if duplicate_query.one_or_none() is not None:
        raise HTTPException(status_code=409, detail=message("users.duplicate_username", current.locale))

    salt, password_hash = hash_password(payload.password)
    user = User(
        organization_id=organization_id,
        username=payload.username,
        password_salt=salt,
        password_hash=password_hash,
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _remaining_admins(db: Session, organization_id: int | None, excluding_user_id: int) -> int:
    return (
        db.query(User)
        .filter(
            User.organization_id == organization_id,
            User.role == ROLE_ADMIN,
            User.id != excluding_user_id,
        )
        .count()
    )


def _remaining_super_admins(db: Session, excluding_user_id: int) -> int:
    return (
        db.query(User)
        .filter(User.organization_id.is_(None), User.role == ROLE_SUPER_ADMIN, User.id != excluding_user_id)
        .count()
    )


def _get_managed_user(db: Session, current: User, user_id: int) -> User:
    query = db.query(User).filter(User.id == user_id)
    if not is_super_admin(current):
        query = query.filter(User.organization_id == current.organization_id)
    user = query.one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail=message("users.not_found", current.locale))
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    user = _get_managed_user(db, current, user_id)

    updates = payload.model_dump(exclude_unset=True)

    if "role" in updates and updates["role"] != user.role:
        if user.role == ROLE_ADMIN and _remaining_admins(db, user.organization_id, user.id) == 0:
            raise HTTPException(
                status_code=400,
                detail=message("users.cannot_remove_last_admin_role", current.locale),
            )
        # UserUpdateRequest.role can only be "admin"/"viewer", both of which
        # require an organization_id -- a super_admin has none, so there's
        # no valid organization for it to land in. Demoting one is refused
        # outright (regardless of how many other super_admins remain);
        # removing one is only ever done via DELETE, which is protected by
        # _remaining_super_admins below instead.
        if user.role == ROLE_SUPER_ADMIN:
            raise HTTPException(
                status_code=400,
                detail=message("users.cannot_change_super_admin_role", current.locale),
            )
        user.role = updates["role"]

    if updates.get("password"):
        user.password_salt, user.password_hash = hash_password(updates["password"])

    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), current: User = Depends(require_admin)):
    user = _get_managed_user(db, current, user_id)
    if user.id == current.id:
        raise HTTPException(status_code=400, detail=message("users.cannot_delete_self", current.locale))
    if user.role == ROLE_ADMIN and _remaining_admins(db, user.organization_id, user.id) == 0:
        raise HTTPException(status_code=400, detail=message("users.cannot_delete_last_admin", current.locale))
    if user.role == ROLE_SUPER_ADMIN and _remaining_super_admins(db, user.id) == 0:
        raise HTTPException(status_code=400, detail=message("users.cannot_delete_last_super_admin", current.locale))

    db.delete(user)
    db.commit()
    return None
