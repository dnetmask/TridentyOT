import zoneinfo

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import ROLE_ADMIN
from app.auth.deps import require_admin, require_super_admin
from app.auth.security import hash_password
from app.db import get_db
from app.i18n import message
from app.models import Organization, User
from app.schemas import (
    OrganizationCreateRequest,
    OrganizationOut,
    OrganizationSettingsUpdateRequest,
    OrganizationUpdateRequest,
    OrganizationWithAdminOut,
)

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationOut])
def list_organizations(db: Session = Depends(get_db), _current: User = Depends(require_super_admin)):
    return db.query(Organization).order_by(Organization.name).all()


@router.post("", response_model=OrganizationWithAdminOut, status_code=201)
def create_organization(
    payload: OrganizationCreateRequest,
    db: Session = Depends(get_db),
    current: User = Depends(require_super_admin),
):
    if db.query(Organization).filter(Organization.slug == payload.slug).one_or_none() is not None:
        raise HTTPException(status_code=409, detail=message("organizations.duplicate_slug", current.locale))

    org = Organization(
        name=payload.name,
        slug=payload.slug,
        deployment_mode=payload.deployment_mode,
        default_locale=payload.default_locale,
    )
    db.add(org)
    db.flush()

    # A brand-new organization's username scope starts empty, so no
    # per-organization collision is possible here -- unlike POST
    # /api/users, this never has to check for one.
    salt, password_hash = hash_password(payload.admin_password)
    admin_user = User(
        organization_id=org.id,
        username=payload.admin_username,
        password_salt=salt,
        password_hash=password_hash,
        role=ROLE_ADMIN,
        locale=payload.default_locale,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(org)
    db.refresh(admin_user)
    return OrganizationWithAdminOut(organization=org, admin_user=admin_user)


@router.patch("/me", response_model=OrganizationOut)
def update_my_organization(
    payload: OrganizationSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current: User = Depends(require_admin),
):
    """Self-service settings for the caller's own organization (Ajustes,
    under Administración) -- open to that org's own admin, unlike
    update_organization above (platform-level management, super_admin
    only, acting on any organization by id). Declared before
    "/{organization_id}" so "me" is never mistaken for one.

    A super_admin has no organization of their own (see User.organization_id's
    docstring), so this 404s for one exactly like a real caller with a
    dangling/deleted organization_id would."""
    if current.organization_id is None:
        raise HTTPException(status_code=404, detail=message("organizations.no_organization", current.locale))
    org = db.get(Organization, current.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail=message("organizations.not_found", current.locale))

    if payload.timezone not in zoneinfo.available_timezones():
        raise HTTPException(status_code=400, detail=message("organizations.invalid_timezone", current.locale))
    org.timezone = payload.timezone
    db.commit()
    db.refresh(org)
    return org


@router.patch("/{organization_id}", response_model=OrganizationOut)
def update_organization(
    organization_id: int,
    payload: OrganizationUpdateRequest,
    db: Session = Depends(get_db),
    current: User = Depends(require_super_admin),
):
    org = db.get(Organization, organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail=message("organizations.not_found", current.locale))

    org.name = payload.name
    db.commit()
    db.refresh(org)
    return org
