from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, is_super_admin, require_admin
from app.db import get_db
from app.i18n import message
from app.models import SENSOR_KIND_LIVE, Sensor, Site, User, Zone
from app.schemas import (
    SensorCreateRequest,
    SensorOut,
    SensorUpdateRequest,
    SiteCreateRequest,
    SiteOut,
    SiteUpdateRequest,
    ZoneCreateRequest,
    ZoneOut,
    ZoneUpdateRequest,
)

# Every Zona gets one of these the moment it's created, so Captura/
# Descubrimiento activo always have at least one Sensor to select --
# nothing to configure before a Zona is usable. Admins can still rename it,
# add more, or set its physical interface (see update_sensor below).
DEFAULT_SENSOR_NAME = "Sensor interno"

router = APIRouter(prefix="/api", tags=["hierarchy"])


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------


@router.get("/sites", response_model=list[SiteOut])
def list_sites(
    organization_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Site)
    if is_super_admin(user):
        if organization_id is not None:
            query = query.filter(Site.organization_id == organization_id)
    else:
        query = query.filter(Site.organization_id == user.organization_id)
    return query.order_by(Site.name).all()


@router.post("/sites", response_model=SiteOut, status_code=201)
def create_site(payload: SiteCreateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if is_super_admin(user):
        if payload.organization_id is None:
            raise HTTPException(status_code=400, detail=message("sites.organization_id_required", user.locale))
        organization_id = payload.organization_id
    else:
        organization_id = user.organization_id

    site = Site(
        organization_id=organization_id,
        name=payload.name,
        city=payload.city,
        country=payload.country,
        timezone=payload.timezone,
    )
    db.add(site)
    db.commit()
    db.refresh(site)
    return site


def _get_owned_site(db: Session, user: User, site_id: int) -> Site:
    query = db.query(Site).filter(Site.id == site_id)
    if not is_super_admin(user):
        query = query.filter(Site.organization_id == user.organization_id)
    site = query.one_or_none()
    if site is None:
        raise HTTPException(status_code=404, detail=message("sites.not_found", user.locale))
    return site


@router.patch("/sites/{site_id}", response_model=SiteOut)
def update_site(
    site_id: int, payload: SiteUpdateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    site = _get_owned_site(db, user, site_id)  # 404s unless the site is the caller's (or caller is super_admin)
    site.name = payload.name
    db.commit()
    db.refresh(site)
    return site


# ---------------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------------


@router.get("/zones", response_model=list[ZoneOut])
def list_zones(
    site_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Zone)
    if site_id is not None:
        _get_owned_site(db, user, site_id)  # 404s if it doesn't exist / isn't the caller's
        query = query.filter(Zone.site_id == site_id)
    elif not is_super_admin(user):
        query = query.join(Site, Zone.site_id == Site.id).filter(Site.organization_id == user.organization_id)
    return query.order_by(Zone.name).all()


@router.post("/zones", response_model=ZoneOut, status_code=201)
def create_zone(payload: ZoneCreateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    _get_owned_site(db, user, payload.site_id)  # 404s unless the site is the caller's (or caller is super_admin)

    zone = Zone(
        site_id=payload.site_id,
        name=payload.name,
        description=payload.description,
        security_level=payload.security_level,
    )
    db.add(zone)
    db.flush()  # zone.id is needed for the default Sensor below
    db.add(Sensor(zone_id=zone.id, name=DEFAULT_SENSOR_NAME, kind=SENSOR_KIND_LIVE))
    db.commit()
    db.refresh(zone)
    return zone


def _get_owned_zone(db: Session, user: User, zone_id: int) -> Zone:
    query = db.query(Zone).filter(Zone.id == zone_id)
    if not is_super_admin(user):
        query = query.join(Site, Zone.site_id == Site.id).filter(Site.organization_id == user.organization_id)
    zone = query.one_or_none()
    if zone is None:
        raise HTTPException(status_code=404, detail=message("zones.not_found", user.locale))
    return zone


@router.patch("/zones/{zone_id}", response_model=ZoneOut)
def update_zone(
    zone_id: int, payload: ZoneUpdateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    zone = _get_owned_zone(db, user, zone_id)  # 404s unless the zone is the caller's (or caller is super_admin)
    zone.name = payload.name
    db.commit()
    db.refresh(zone)
    return zone


# ---------------------------------------------------------------------------
# Sensors
# ---------------------------------------------------------------------------


@router.get("/sensors", response_model=list[SensorOut])
def list_sensors(
    zone_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Sensor)
    if zone_id is not None:
        _get_owned_zone(db, user, zone_id)  # 404s if it doesn't exist / isn't the caller's
        query = query.filter(Sensor.zone_id == zone_id)
    elif not is_super_admin(user):
        query = (
            query.join(Zone, Sensor.zone_id == Zone.id)
            .join(Site, Zone.site_id == Site.id)
            .filter(Site.organization_id == user.organization_id)
        )
    return query.order_by(Sensor.name).all()


@router.post("/sensors", response_model=SensorOut, status_code=201)
def create_sensor(payload: SensorCreateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    _get_owned_zone(db, user, payload.zone_id)  # 404s unless the zone is the caller's (or caller is super_admin)

    sensor = Sensor(
        zone_id=payload.zone_id,
        name=payload.name,
        description=payload.description,
        kind=payload.kind,
        interface=payload.interface,
    )
    db.add(sensor)
    db.commit()
    db.refresh(sensor)
    return sensor


def _get_owned_sensor(db: Session, user: User, sensor_id: int) -> Sensor:
    query = db.query(Sensor).filter(Sensor.id == sensor_id)
    if not is_super_admin(user):
        query = (
            query.join(Zone, Sensor.zone_id == Zone.id)
            .join(Site, Zone.site_id == Site.id)
            .filter(Site.organization_id == user.organization_id)
        )
    sensor = query.one_or_none()
    if sensor is None:
        raise HTTPException(status_code=404, detail=message("sensors.not_found", user.locale))
    return sensor


@router.patch("/sensors/{sensor_id}", response_model=SensorOut)
def update_sensor(
    sensor_id: int, payload: SensorUpdateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    sensor = _get_owned_sensor(db, user, sensor_id)  # 404s unless the sensor is the caller's (or caller is super_admin)
    sensor.name = payload.name
    sensor.description = payload.description
    # Not user.locale-sensitive, and deliberately not validated against
    # GET /api/capture/interfaces here: that list is specific to whichever
    # host this API process happens to be running on right now, which may
    # not be the host a remote Sensor eventually runs on (see docs, "Sensor
    # remoto") -- the frontend still only offers that list in its own
    # dropdown, this just doesn't hard-block a name outside it.
    sensor.interface = payload.interface
    db.commit()
    db.refresh(sensor)
    return sensor
