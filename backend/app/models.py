import datetime

from sqlalchemy import (
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.fingerprint.ip_scope import is_lan_ip


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# Deployment modes an Organization can run under -- see docs on multi-tenant
# support. "self_hosted" is one org per instance/database (a large client
# running its own sensor/console); "managed" is one of several orgs sharing
# a central console instance. Both share the exact same schema: the only
# difference is how many Organization rows a given deployment ever has.
DEPLOYMENT_SELF_HOSTED = "self_hosted"
DEPLOYMENT_MANAGED = "managed"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    deployment_mode: Mapped[str] = mapped_column(String(16), default=DEPLOYMENT_SELF_HOSTED)
    # Default locale for new users created under this org; each user can
    # still override it individually (see User.locale).
    default_locale: Mapped[str] = mapped_column(String(5), default="es")
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


class Site(Base):
    """A physical location (a plant, a branch) belonging to one Organization.
    See docs (Parte C) for the full Organization -> Site -> Zone -> Sensor
    hierarchy this and the two models below exist for.
    """

    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


class Zone(Base):
    """A deployment-level area within a Site (a line, a building) -- distinct
    from an IEC 62443 security zone, which is a logical grouping that can
    span several physical areas. See docs (Parte C, "matiz de terminología")
    for the full distinction.
    """

    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # IEC 62443 security level (SL0-SL4). Nullable/optional on purpose, with
    # no default forced at creation: this platform also serves pure IT
    # inventory/topology use cases where the concept doesn't apply -- see
    # docs (Parte C, resolved question on this field). NULL means
    # "unclassified", never "SL0" -- a future criticality-weighting engine
    # must treat the two differently.
    security_level: Mapped[str | None] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


SENSOR_KIND_LIVE = "live"
SENSOR_KIND_EXTERNAL = "external"  # pcap-only uploads, no live interface of its own


class Sensor(Base):
    """The identity a capture process enrolls under -- stable across
    restarts and across however many CaptureSessions it ever runs, unlike a
    CaptureSession itself which is created fresh per run. A Zone accepts
    more than one Sensor (co-located isolated processes on the same
    physical area, each on its own segment/VLAN) -- see docs (Parte C,
    resolved question on this).
    """

    __tablename__ = "sensors"

    id: Mapped[int] = mapped_column(primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default=SENSOR_KIND_LIVE)
    # The physical NIC (e.g. "eth0") this Sensor listens on for live
    # capture and transmits/listens on for active discovery -- NULL until
    # an admin sets it (see routes_hierarchy.update_sensor), in which case
    # Captura/Descubrimiento activo still ask for one ad hoc every time.
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Set once this sensor actually runs as its own remote enrollment
    # target (see docs, "Sensor remoto") -- NULL until that lands.
    enrollment_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
    last_seen_at: Mapped[datetime.datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


class CaptureSession(Base):
    __tablename__ = "capture_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Nullable at the DB level only because it's added via an additive
    # ALTER TABLE to databases that predate multi-tenancy (see db.py's
    # _ensure_default_organization_and_backfill) -- every row, old or new,
    # always has one in practice, same pattern as Device.capture_session_id.
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    # Nullable for the same additive-migration reason -- see db.py's
    # _ensure_default_site_zone_sensor_and_backfill, which points every
    # existing (and NULL) row at a "Default" Sensor per organization.
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    source_type: Mapped[str] = mapped_column(String(16))  # "live" | "pcap" | "active_pnio_dcp"
    source: Mapped[str] = mapped_column(String(255))  # interface name or original filename
    bpf_filter: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|stopped|completed|error
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    # Live captures only: packets pulled off the wire but discarded because
    # the ingest queue was full (the DB-write side couldn't keep up) -- see
    # app/capture/live_capture.py. Always 0 for a pcap upload, which has no
    # producer/consumer split to drop anything from.
    dropped_count: Mapped[int] = mapped_column(Integer, default=0)
    # pcap uploads only: the file's total size and how many bytes of it the
    # reader has consumed so far, set by process_pcap_file -- see
    # progress_percent. A live capture has no known "total" to measure
    # against, so both stay 0 for it and progress_percent is always None.
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    bytes_processed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    ended_at: Mapped[datetime.datetime | None] = mapped_column(nullable=True)

    @property
    def progress_percent(self) -> float | None:
        if not self.total_bytes:
            return None
        return round(min(self.bytes_processed / self.total_bytes, 1.0) * 100, 1)


class Device(Base):
    __tablename__ = "devices"
    # Scoped by organization: two different clients' networks can
    # (and, on shared physical vendor gear, sometimes do) see the exact same
    # MAC/IP pair without being the same asset -- see
    # db._rebuild_device_unique_constraint for how a pre-multi-tenant
    # database's old (mac, ip) index gets migrated to this one.
    __table_args__ = (UniqueConstraint("organization_id", "mac", "ip", name="uq_device_org_mac_ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # Nullable at the DB level for the same additive-migration reason as
    # CaptureSession.organization_id above.
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
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

    # Self-reported firmware/software version -- from EtherNet/IP CIP List
    # Identity (Major/Minor Revision), Modbus Read Device Identification
    # (MajorMinorRevision), or a switch/router's CDP Software Version/LLDP
    # System Description TLV. Same auto/custom-override pattern as
    # hostname/vendor above. Left blank (not guessed) for protocols that
    # don't self-report it -- notably PROFINET DCP, which has no firmware
    # field in its Identify response.
    #
    # Text, not a bounded VARCHAR: a CDP Software Version TLV is routinely
    # a full multi-line banner (IOS version, copyright, compile date --
    # easily 200-400+ characters), and unlike a Postgres VARCHAR(n) a plain
    # string column never rejects the row for exceeding it. On a live
    # capture, that rejection has no per-record handling to catch it (see
    # live_capture.py's _ingest_batch) -- it kills the consumer thread
    # outright, silently freezing the capture at whatever packet last made
    # it through the queue.
    firmware_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    custom_firmware_version: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Manufacturer's model/order-code reference for this specific unit --
    # e.g. an EtherNet/IP CIP productName ("1756-L83E"), a Siemens MLFB
    # order code from S7comm SZL, a PROFINET DCP "Type of Station" block, or
    # a switch/router's CDP Platform TLV. Distinct from hostname: a
    # hostname is how a site names this specific asset ("plc-line3"); a
    # model is what the vendor calls the product itself, and is often the
    # same value across every identical unit on the network. String(255),
    # matching hostname/vendor above -- these are short identifiers in
    # practice, unlike the free-text firmware banners above.
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    custom_model: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # device_type is auto-detected (see app/fingerprint/device_classifier.py);
    # custom_device_type is a manual override, same pattern as custom_name/vendor.
    device_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    device_type_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    device_type_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    custom_device_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Subcategory for NETWORK_DEVICE rows only (switch L2/L3, firewall,
    # access point, router/NAT) -- a second, independent type field, same
    # auto/custom-override pattern as device_type above. Only "router_nat"
    # is ever auto-detected today (see inventory_service.apply_gateway_detection).
    device_type_secondary: Mapped[str | None] = mapped_column(String(32), nullable=True)
    custom_device_type_secondary: Mapped[str | None] = mapped_column(String(32), nullable=True)

    is_ot_suspected: Mapped[bool] = mapped_column(default=False)

    # The capture session that *first* discovered this device -- used to
    # remove it when that session is deleted, provided no other session's
    # protocols/flows still reference it (see inventory_service.purge_capture_session).
    capture_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("capture_sessions.id"), nullable=True, index=True
    )

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
    def protocol_names(self) -> list[str]:
        return sorted({p.protocol for p in self.protocols})

    @property
    def display_name(self) -> str | None:
        return self.custom_name or self.hostname

    @property
    def display_vendor(self) -> str | None:
        return self.custom_vendor or self.vendor

    @property
    def display_firmware_version(self) -> str | None:
        return self.custom_firmware_version or self.firmware_version

    @property
    def display_model(self) -> str | None:
        return self.custom_model or self.model

    @property
    def display_device_type(self) -> str | None:
        return self.custom_device_type or self.device_type

    @property
    def display_device_type_secondary(self) -> str | None:
        return self.custom_device_type_secondary or self.device_type_secondary

    @property
    def is_external(self) -> bool:
        """A device counts as external only if BOTH signals agree: its IP
        looks public AND we've never captured it transmitting (mac is None
        -- see inventory_service.get_or_create_device, which only ever
        learns mac from a packet's sender, never its destination). A LAN
        host misconfigured with a public IP range still has a captured mac,
        so it's correctly kept off this flag; a real off-network host
        reached only through a router never does."""
        return self.mac is None and not is_lan_ip(self.ip)


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
    # The capture session that first observed this protocol -- see Device.capture_session_id.
    capture_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("capture_sessions.id"), nullable=True, index=True
    )
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
    # The capture session that first observed this flow -- see Device.capture_session_id.
    capture_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("capture_sessions.id"), nullable=True, index=True
    )
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
    __table_args__ = (
        # Scoped per-organization for admin/viewer -- two different clients
        # of a central console can each pick "admin" as a username without
        # colliding. Never satisfied for a super_admin row (organization_id
        # IS NULL), since NULL is never equal to NULL in either dialect --
        # see the partial index below for that case instead.
        UniqueConstraint("organization_id", "username", name="uq_user_org_username"),
        # super_admin has no organization to scope by, so it needs its own
        # globally-unique-among-org-less-rows index instead of the
        # composite constraint above. Both SQLite (3.8+) and Postgres
        # support a WHERE-qualified unique index identically.
        Index(
            "uq_user_username_super_admin",
            "username",
            unique=True,
            sqlite_where=text("organization_id IS NULL"),
            postgresql_where=text("organization_id IS NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # NULL only for a super_admin (the Netmask platform role -- administers
    # organizations/sites/zones/sensors, no organization of its own).
    # Nullable at the DB level for admin/viewer too, for the same
    # additive-migration reason as CaptureSession.organization_id above.
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    password_salt: Mapped[str] = mapped_column(String(32))
    password_hash: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16))  # "super_admin" | "admin" | "viewer"
    # UI/evidence text language preference -- see app/i18n. Defaults to "es"
    # on creation; changeable by the user themself via PATCH /api/auth/me.
    locale: Mapped[str] = mapped_column(String(5), default="es")
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
