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


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: UserOut


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=4, max_length=256)
    # super_admin is deliberately not assignable here -- this endpoint
    # always attaches the new user to the caller's own organization, and a
    # super_admin has none (see routes_users.create_user).
    role: Literal["admin", "viewer"]


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
