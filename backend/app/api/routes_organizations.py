from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import ROLE_ADMIN
from app.auth.deps import require_super_admin
from app.auth.security import hash_password
from app.db import get_db
from app.i18n import message
from app.models import Organization, User
from app.schemas import OrganizationCreateRequest, OrganizationOut, OrganizationWithAdminOut

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
