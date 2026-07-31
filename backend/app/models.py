import datetime

from sqlalchemy import (
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class CaptureSession(Base):
    __tablename__ = "capture_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    source_type: Mapped[str] = mapped_column(String(16))  # "live" | "pcap"
    source: Mapped[str] = mapped_column(String(255))  # interface name or original filename
    bpf_filter: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|stopped|completed|error
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    ended_at: Mapped[datetime.datetime | None] = mapped_column(nullable=True)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("mac", "ip", name="uq_device_mac_ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)

    # hostname/vendor are auto-detected (DHCP/DNS/mDNS option 12, MAC OUI);
    # custom_name/custom_vendor are manual overrides that always win when set,
    # editable regardless of whether auto-detection found anything.
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    custom_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    custom_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)

    os_guess: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    os_signature: Mapped[str | None] = mapped_column(String(255), nullable=True)

    is_ot_suspected: Mapped[bool] = mapped_column(default=False)

    first_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)

    protocols: Mapped[list["DeviceProtocol"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    @property
    def protocol_count(self) -> int:
        return len(self.protocols)

    @property
    def display_name(self) -> str | None:
        return self.custom_name or self.hostname

    @property
    def display_vendor(self) -> str | None:
        return self.custom_vendor or self.vendor


class DeviceProtocol(Base):
    __tablename__ = "device_protocols"
    __table_args__ = (
        UniqueConstraint("device_id", "protocol", "port", "role", name="uq_device_protocol_port_role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    transport: Mapped[str] = mapped_column(String(8), default="tcp")
    role: Mapped[str] = mapped_column(String(8), default="server")  # server|client
    category: Mapped[str] = mapped_column(String(8), default="IT")  # IT|OT
    banner: Mapped[str | None] = mapped_column(String(512), nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)

    device: Mapped[Device] = relationship(back_populates="protocols")


class Flow(Base):
    """A TCP/UDP 'conversation' between two devices -- who talks to whom,
    over which protocol/port, aggregated across the whole capture rather
    than one row per packet. device_a/device_b are normalized (a.id <
    b.id) so both directions of a conversation land in a single row.
    """

    __tablename__ = "flows"
    __table_args__ = (
        UniqueConstraint(
            "device_a_id", "device_b_id", "transport", "port", name="uq_flow_pair_transport_port"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_a_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    device_b_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    server_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    transport: Mapped[str] = mapped_column(String(8))  # tcp|udp
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(8), default="IT")  # IT|OT
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)

    device_a: Mapped[Device] = relationship(foreign_keys=[device_a_id])
    device_b: Mapped[Device] = relationship(foreign_keys=[device_b_id])
    server_device: Mapped[Device] = relationship(foreign_keys=[server_device_id])

    @property
    def device_a_ip(self) -> str | None:
        return self.device_a.ip if self.device_a else None

    @property
    def device_a_name(self) -> str | None:
        return self.device_a.display_name if self.device_a else None

    @property
    def device_b_ip(self) -> str | None:
        return self.device_b.ip if self.device_b else None

    @property
    def device_b_name(self) -> str | None:
        return self.device_b.display_name if self.device_b else None


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint("device_id", "rule_id", "cve_id", name="uq_finding_device_rule_cve"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    source: Mapped[str] = mapped_column(String(16))  # "rule" | "nvd"
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))  # info|low|medium|high|critical
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)

    device: Mapped[Device] = relationship(back_populates="findings")

    @property
    def device_ip(self) -> str | None:
        return self.device.ip if self.device else None

    @property
    def device_name(self) -> str | None:
        return self.device.display_name if self.device else None


class CveCache(Base):
    __tablename__ = "cve_cache"

    id: Mapped[int] = mapped_column(primary_key=True)
    keyword: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    response_json: Mapped[str] = mapped_column(Text)
    fetched_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_salt: Mapped[str] = mapped_column(String(32))
    password_hash: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16))  # "editor" | "viewer"
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)

    tokens: Mapped[list["AuthToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime.datetime] = mapped_column()

    user: Mapped[User] = relationship(back_populates="tokens")
