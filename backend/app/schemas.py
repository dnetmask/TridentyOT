import datetime

from pydantic import BaseModel, ConfigDict


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
    os_guess: str | None
    os_confidence: float
    is_ot_suspected: bool
    protocol_count: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime


class DeviceDetailOut(DeviceOut):
    protocols: list[DeviceProtocolOut] = []
    findings: list[VulnerabilityFindingOut] = []


class CaptureSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source_type: str
    source: str
    bpf_filter: str
    status: str
    packet_count: int
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
