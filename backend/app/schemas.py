import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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
    device_type: str | None
    device_type_confidence: float
    device_type_evidence: str | None
    custom_device_type: str | None
    display_device_type: str | None
    is_ot_suspected: bool
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
    custom_device_type: Literal["plc", "server", "workstation", "network_device", "other"] | None = None


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
    role: Literal["editor", "viewer"]


class UserUpdateRequest(BaseModel):
    """PATCH semantics: only fields present in the request body are applied."""

    password: str | None = Field(default=None, min_length=4, max_length=256)
    role: Literal["editor", "viewer"] | None = None
