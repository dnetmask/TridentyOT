import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.i18n import render_i18n


class DeviceProtocolOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    protocol: str
    port: int | None
    transport: str
    role: str
    category: str
    banner: str | None
    packet_count: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime


class VulnerabilityFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    device_ip: str | None
    device_name: str | None
    source: str
    rule_id: str | None
    cve_id: str | None
    title: str
    description: str
    severity: str
    cvss_score: float | None
    evidence: str | None
    created_at: datetime.datetime


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mac: str | None
    ip: str | None
    hostname: str | None
    custom_name: str | None
    display_name: str | None
    vendor: str | None
    custom_vendor: str | None
    display_vendor: str | None
    os_guess: str | None
    os_confidence: float
    firmware_version: str | None
    custom_firmware_version: str | None
    display_firmware_version: str | None
    model: str | None
    custom_model: str | None
    display_model: str | None
    device_type: str | None
    device_type_confidence: float
    device_type_evidence: str | None
    custom_device_type: str | None
    display_device_type: str | None
    device_type_secondary: str | None
    custom_device_type_secondary: str | None
    display_device_type_secondary: str | None
    is_ot_suspected: bool
    is_external: bool
    protocol_count: int
    protocol_names: list[str] = []
    first_seen: datetime.datetime
    last_seen: datetime.datetime


class DeviceDetailOut(DeviceOut):
    protocols: list[DeviceProtocolOut] = []
    findings: list[VulnerabilityFindingOut] = []


class DeviceUpdateRequest(BaseModel):
    """PATCH semantics: only fields present in the request body are applied
    (see routes_inventory.py, which uses exclude_unset). Sending an explicit
    null clears the override back to the auto-detected value."""

    custom_name: str | None = None
    custom_vendor: str | None = None
    custom_firmware_version: str | None = None
    custom_model: str | None = None
    custom_device_type: Literal["plc", "hmi", "server", "workstation", "network_device", "other"] | None = None
    custom_device_type_secondary: (
        Literal["switch_l2", "switch_l3", "firewall", "access_point", "router_nat", "transport_controller"] | None
    ) = None


class FlowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_a_id: int
    device_a_ip: str | None
    device_a_name: str | None
    device_b_id: int
    device_b_ip: str | None
    device_b_name: str | None
    server_device_id: int
    transport: str
    port: int | None
    protocol: str
    category: str
    packet_count: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime


class CaptureSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source_type: str
    source: str
    bpf_filter: str
    status: str
    packet_count: int
    dropped_count: int
    total_bytes: int
    bytes_processed: int
    progress_percent: float | None
    error_message: str | None
    started_at: datetime.datetime
    ended_at: datetime.datetime | None


class StartLiveCaptureRequest(BaseModel):
    interface: str
    bpf_filter: str | None = None
    name: str | None = None
    # Which Sensor (and therefore which Zona/Sitio) this capture belongs to
    # -- lets the resulting devices/flows/findings be attributed to a
    # specific Sitio, instead of only ever being scoped to the whole
    # organization. Optional: a caller with exactly one Sensor available
    # (the common single-site case) doesn't have to pick; required only
    # when there's more than one to choose from -- see
    # routes_capture._resolve_capture_sensor.
    sensor_id: int | None = None


class ProfinetDcpScanRequest(BaseModel):
    """Kicks off one PROFINET DCP "Identify All" broadcast + a short listen
    window on interface -- see app/capture/active_discovery.py. Unlike live
    capture's sensor_id, this one is required: active discovery is a
    deliberate, explicit action against one specific interface, not
    something that should ever silently auto-pick."""

    interface: str
    sensor_id: int
    duration_seconds: float = Field(default=5.0, ge=1, le=30)


class NmapScanRequest(BaseModel):
    """A light nmap service/OS scan -- see app/capture/nmap_discovery.py
    for exactly what it does and doesn't run. No duration_seconds: this
    scan has no fixed time limit, and instead exposes live progress
    (CaptureSessionOut.progress_percent) and a stop endpoint
    (POST /api/discovery/nmap/stop/{id}) for cutting it short. sensor_id is
    required for the same reason as ProfinetDcpScanRequest's: this is a
    deliberate, explicit active action, never something to auto-pick a
    target or a sensor for."""

    target: str = Field(min_length=1, max_length=255)
    sensor_id: int


class ScanRequest(BaseModel):
    device_id: int | None = None
    use_nvd: bool = True


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    locale: str
    created_at: datetime.datetime
    # organization_id is a real column on User, so it's always populated
    # automatically. organization_name has no equivalent attribute on the
    # ORM object (User has no `organization` relationship) -- it stays
    # None unless a caller explicitly fills it in, see user_out() below.
    organization_id: int | None = None
    organization_name: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: UserOut


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=4, max_length=256)
    # "super_admin" is only accepted from a super_admin caller (checked in
    # routes_users.create_user, since a Literal can't condition on who's
    # asking) -- an admin trying to set it gets a 403, same as if it
    # weren't a valid value at all.
    role: Literal["super_admin", "admin", "viewer"]
    # Only used (and required) when the caller is a super_admin creating an
    # admin/viewer, who has no organization of their own to default to --
    # ignored for an admin (whose new user always belongs to their own
    # organization) and for a new super_admin (who has none, like the
    # caller). Mirrors SiteCreateRequest.organization_id.
    organization_id: int | None = None


class UserUpdateRequest(BaseModel):
    """PATCH semantics: only fields present in the request body are applied."""

    password: str | None = Field(default=None, min_length=4, max_length=256)
    role: Literal["admin", "viewer"] | None = None


class UserSelfUpdateRequest(BaseModel):
    """Fields any authenticated user (admin or viewer) can change about
    their own account, as opposed to UserUpdateRequest which is
    admin-only and can target any user."""

    locale: Literal["es", "en"] | None = None


# ---------------------------------------------------------------------------
# Organization -> Site -> Zone -> Sensor hierarchy (see docs, Parte C)
# ---------------------------------------------------------------------------


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    deployment_mode: str
    default_locale: str
    created_at: datetime.datetime


class OrganizationCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    deployment_mode: Literal["self_hosted", "managed"] = "managed"
    default_locale: Literal["es", "en"] = "es"
    # Bootstraps the organization's first admin user in the same call --
    # otherwise a freshly created organization has no user able to log
    # into it, since POST /api/users always scopes to the caller's own
    # organization and a super_admin (the only caller of this endpoint)
    # has none.
    admin_username: str = Field(min_length=1, max_length=64)
    admin_password: str = Field(min_length=4, max_length=256)


class OrganizationWithAdminOut(BaseModel):
    organization: OrganizationOut
    admin_user: UserOut


class OrganizationUpdateRequest(BaseModel):
    """Only the display name is editable here -- slug/deployment_mode/
    default_locale are set once at creation and aren't exposed for
    renaming (the slug in particular may be referenced elsewhere)."""

    name: str = Field(min_length=1, max_length=255)


class SiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    name: str
    city: str | None
    country: str | None
    timezone: str | None
    created_at: datetime.datetime


class SiteCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    city: str | None = None
    country: str | None = None
    timezone: str | None = None
    # Only used (and required) when the caller is a super_admin, who has no
    # organization of their own to default to -- ignored for an admin,
    # whose site always belongs to their own organization.
    organization_id: int | None = None


class SiteUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class ZoneOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    site_id: int
    name: str
    description: str | None
    security_level: str | None
    created_at: datetime.datetime


class ZoneCreateRequest(BaseModel):
    site_id: int
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    # IEC 62443 security level -- deliberately optional, see docs (Parte C).
    security_level: Literal["SL0", "SL1", "SL2", "SL3", "SL4"] | None = None


class ZoneUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class SensorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    zone_id: int
    name: str
    description: str | None
    kind: str
    interface: str | None
    last_seen_at: datetime.datetime | None
    created_at: datetime.datetime


class SensorCreateRequest(BaseModel):
    zone_id: int
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    kind: Literal["live", "external"] = "live"
    # The physical NIC this Sensor listens on/transmits from for live
    # capture and active discovery -- optional at creation (Captura/
    # Descubrimiento still let you pick one ad hoc), but setting it here
    # (or later via PATCH) lets those pre-select it instead of asking every
    # time. Not validated against GET /api/capture/interfaces -- see
    # update_sensor's docstring.
    interface: str | None = None


class SensorUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    interface: str | None = None


# ---------------------------------------------------------------------------
# Locale-aware response construction.
#
# device_type_evidence / title / description / evidence are stored as
# app.i18n-encoded JSON (see fingerprint/device_classifier.py, identity_
# detect.py, vuln/rules.py, vuln/engine.py) so one row serves every locale.
# These helpers render that JSON into the requesting user's language at
# response time, in place of the plain from_attributes conversion the
# *Out models would otherwise do on their own.
# ---------------------------------------------------------------------------


def device_out(device, locale: str) -> DeviceOut:
    data = DeviceOut.model_validate(device).model_dump()
    data["device_type_evidence"] = render_i18n(device.device_type_evidence, locale)
    return DeviceOut(**data)


def device_detail_out(device, locale: str) -> DeviceDetailOut:
    data = DeviceDetailOut.model_validate(device).model_dump()
    data["device_type_evidence"] = render_i18n(device.device_type_evidence, locale)
    data["findings"] = [vulnerability_finding_out(f, locale).model_dump() for f in device.findings]
    return DeviceDetailOut(**data)


def vulnerability_finding_out(finding, locale: str) -> VulnerabilityFindingOut:
    data = VulnerabilityFindingOut.model_validate(finding).model_dump()
    data["title"] = render_i18n(finding.title, locale)
    data["description"] = render_i18n(finding.description, locale)
    data["evidence"] = render_i18n(finding.evidence, locale)
    return VulnerabilityFindingOut(**data)


def capture_session_out(session_obj, locale: str) -> CaptureSessionOut:
    data = CaptureSessionOut.model_validate(session_obj).model_dump()
    data["error_message"] = render_i18n(session_obj.error_message, locale)
    return CaptureSessionOut(**data)


def user_out(db, user) -> UserOut:
    """Like UserOut.model_validate(user), but also fills in
    organization_name -- there's no `organization` relationship on the User
    model to pull that from automatically. Used for a user's own account
    (GET/PATCH /api/auth/me) so the frontend can label its nav tree root
    without a super_admin-only call to GET /api/organizations."""
    from app.models import Organization

    data = UserOut.model_validate(user).model_dump()
    if user.organization_id is not None:
        org = db.get(Organization, user.organization_id)
        if org is not None:
            data["organization_name"] = org.name
    return UserOut(**data)
