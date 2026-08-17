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
    # IANA zone name (e.g. "America/Bogota") used to display every
    # timestamp this organization's users see (Últ. visto, Primera vez,
    # ...) -- everything is stored as UTC (see utcnow() below); this is a
    # purely presentational setting, editable by the org's own admin (see
    # routes_organizations.update_my_organization), not just a super_admin.
    # UTC is the safe default for a brand-new org rather than guessing a
    # region.
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
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
    source_type: Mapped[str] = mapped_column(
        String(16)
    )  # "live" | "pcap" | "active_pnio_dcp" | "active_nmap" | "active_snmp"
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

    # 802.1Q VLAN ID, last-seen wins. Only ever learned from a frame this
    # device sent (mirrors mac's sender-only semantics in
    # inventory_service.get_or_create_device), and only overwritten when the
    # frame actually carried a tag -- an untagged frame leaves this
    # unchanged rather than clearing it, since "no tag on this frame" isn't
    # proof the device has no VLAN (native/untagged VLANs exist).
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # IP TTL from the most recently captured packet this device sent -- a
    # coarse hop-distance/OS-family signal (see fingerprint/os_fingerprint.py)
    # kept separate from os_guess/os_confidence since TTL alone is weak and
    # easily conflated (a Linux host and a network appliance can both boot
    # from 64) and is meant for hop-distance inference, not classification.
    last_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Fase 2 de la hoja de ruta de topología: "same_segment" | "routed_local"
    # | "internet" -- see inventory_service.apply_segment_classification,
    # which computes this as a whole-table pass, the same way
    # apply_gateway_detection already does. None for a MAC-only device (no
    # ip at all -- the question doesn't apply) or before the first pass has
    # run. Deliberately NOT a confidence-gated/never-downgrade field like
    # os_guess: it's a deterministic snapshot of "does an ArpObservation
    # exist for this ip on this device's own sensor right now", recomputed
    # fresh every pass rather than accumulated evidence.
    segment_relation: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # True when `mac` was only ever learned from a gateway/firewall
    # forwarding this row's traffic (2+ distinct IPs sharing one MAC --
    # see inventory_service.apply_gateway_detection), never a frame this
    # IP's own NIC actually sent. `mac` itself is deliberately left in
    # place rather than cleared: get_or_create_device re-attaches it
    # (`if mac and not device.mac`) on the very next packet from this same
    # IP, which would just silently undo a cleared value on the next
    # ingest -- this flag is the stable signal instead, recomputed fresh
    # on every apply_gateway_detection pass same as segment_relation
    # above. The one row in a shared-MAC group actually confirmed (via
    # ArpObservation, a real self-identification) or heuristically chosen
    # as the gateway's own address keeps this False.
    is_mac_shared: Mapped[bool] = mapped_column(default=False)

    # Where a human dragged this device to on the Topología canvas --
    # nullable (not a scalar default like is_mac_shared above) because
    # "never placed" is a real, distinct state from "placed at (0, 0)":
    # a null pair means the frontend's auto layout ('cose'/'grid', see
    # renderTopologyGraph) still owns this node's position, exactly as it
    # did before these columns existed, when placement lived only in the
    # browser's topologyPositions cache and vanished on every reload. Once
    # set (PATCH /api/topology/positions, on a real drag), it sticks across
    # reloads and other users' sessions, same as a NetworkLink.
    topology_x: Mapped[float | None] = mapped_column(Float, nullable=True)
    topology_y: Mapped[float | None] = mapped_column(Float, nullable=True)

    # The capture session that *most recently* confirmed this device (see
    # inventory_service.get_or_create_device) -- also used to remove it when
    # that session is deleted, provided no other session's protocols/flows
    # still reference it (see inventory_service.purge_capture_session).
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
        """A device counts as external if its IP looks public AND we have
        no MAC that's genuinely this row's own: either mac is None (we've
        never captured it transmitting -- see inventory_service.
        get_or_create_device, which only ever learns mac from a packet's
        sender, never its destination), or the mac we do have is only
        borrowed from whatever gateway forwarded its traffic
        (is_mac_shared, see apply_gateway_detection). A LAN host
        misconfigured with a public IP range still has its own real mac
        (is_mac_shared False), so it's correctly kept off this flag; a
        real off-network host reached only through a router never does."""
        return not is_lan_ip(self.ip) and (self.mac is None or self.is_mac_shared)


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


# NetworkLink.status -- LINK_CONFIRMED means a human who knows the real
# wiring vouched for it; LINK_UNCERTAIN means it's noted but not verified
# (e.g. "creo que va por acá pero no estoy seguro"). Both are always shown
# on the topology graph, just styled differently (see app/topology.py) --
# neither is ever auto-created; both only ever come from
# POST/PATCH /api/topology/links.
LINK_CONFIRMED = "confirmed"
LINK_UNCERTAIN = "uncertain"


LINK_SOURCE_MANUAL = "manual"
LINK_SOURCE_MAC_TABLE = "mac_table"
LINK_SOURCE_CDP = "cdp"
LINK_SOURCE_LLDP = "lldp"
# A human promoted a FlowLinkCandidate (see that model below) -- weaker
# provenance than mac_table/cdp/lldp (a switch never confirmed this pair
# directly), but still a human's explicit "yes, promote this" decision,
# not something the app asserted on its own.
LINK_SOURCE_FLOW_CANDIDATE = "flow_candidate"


# FlowLinkCandidate.status.
CANDIDATE_PENDING = "pending"
CANDIDATE_CONFIRMED = "confirmed"
CANDIDATE_DISMISSED = "dismissed"


class NetworkLink(Base):
    """A physical link between two Devices -- "this cable really exists".

    Never inferred from Flow (see routes_topology.py's module docstring:
    who-talked-to-whom is not proof of a direct cable). `source` records
    *how* this row came to exist:
      - "manual": a human entered it directly on the topology graph.
      - "mac_table"/"cdp"/"lldp": derived from real switch-reported data
        (a MAC address table, or a CDP/LLDP neighbor announcement) -- see
        app/topology_from_switch.py, fed by either an SNMP walk or a
        manually pasted/uploaded table (app/switch_table_parsers.py).
    A "manual" row always wins: re-running a walk/import that would derive
    a link for the same device pair skips it entirely if a human already
    asserted something there, same principle as NetworkLink always
    outranking a Flow inference used to. A non-manual row *can* be
    refreshed by a newer walk/import for the same pair (ports/status may
    have changed since).

    device_a_id/device_b_id are normalized (a.id < b.id) the same way
    Flow's own device_a/device_b are, so the same physical link is never
    stored twice depending on which end the user clicked first.
    """

    __tablename__ = "network_links"
    __table_args__ = (UniqueConstraint("device_a_id", "device_b_id", name="uq_network_link_pair"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_a_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    device_b_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    # The port on device_a/device_b this link uses, e.g. "Gi0/3" -- free
    # text (not validated against anything the device itself reported),
    # since the whole point of this table is recording what a human knows
    # that the app couldn't observe on its own. Either side may be blank
    # (a technician might know the link exists without knowing the exact
    # port on one end).
    source_port: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_port: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=LINK_CONFIRMED)  # "confirmed" | "uncertain"
    # See LINK_SOURCE_* above. Defaults to "manual" so the additive-column
    # backfill (app/db.py's _add_missing_columns) gives every pre-existing
    # row the value that's actually true for it -- every one was entered
    # by hand before this column existed.
    source: Mapped[str] = mapped_column(String(20), default=LINK_SOURCE_MANUAL)
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime.datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    device_a: Mapped[Device] = relationship(foreign_keys=[device_a_id])
    device_b: Mapped[Device] = relationship(foreign_keys=[device_b_id])


ANNOTATION_BOX = "box"
ANNOTATION_TEXT = "text"


class TopologyAnnotation(Base):
    """A freeform object a human adds directly on the Topología canvas,
    with no device semantics at all -- inspired by draw.io's grouping
    rectangles and text notes, for giving a big topology visual structure
    (an "this whole area is the DMZ" box, a caption) beyond what devices
    and links alone can show.

    - "box": a background rectangle, always rendered behind every device
      (see routes_topology.py's z_order docstring below) so it reads as a
      labeled area rather than an interactive node competing for clicks.
    - "text": a plain caption with no border/fill.

    Scoped by zone_id/site_id exactly like the topology view itself (see
    get_topology's zone_id/site_id query params) -- an annotation drawn
    while looking at one Zona/Sitio only ever reappears in that same view,
    same as how devices are filtered.
    """

    __tablename__ = "topology_annotations"

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("zones.id"), nullable=True, index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(8))  # ANNOTATION_BOX | ANNOTATION_TEXT
    label: Mapped[str] = mapped_column(Text, default="")
    x: Mapped[float] = mapped_column(Float, default=0.0)
    y: Mapped[float] = mapped_column(Float, default=0.0)
    width: Mapped[float] = mapped_column(Float, default=220.0)
    height: Mapped[float] = mapped_column(Float, default=140.0)
    # Lower always draws first (further back) -- "Enviar al fondo" just
    # sets this below whatever the lowest value currently on screen is.
    # Devices/links have no z_order of their own; they're implicitly drawn
    # in front of every annotation regardless of this value (see
    # renderTopologyGraph, which always adds annotation elements to
    # Cytoscape before device/link elements).
    z_order: Mapped[int] = mapped_column(Integer, default=0)
    # A hex color ("#f5a623") for a "box"'s fill -- null means "use the
    # dashboard's own default (muted/theme-driven)", matching how a
    # freshly-created box looked before this column existed. Meaningless
    # for "text" (no fill to begin with), so the frontend never shows a
    # color picker for that kind.
    color: Mapped[str | None] = mapped_column(String(9), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime.datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class FlowLinkCandidate(Base):
    """Fase 3 of the topology-accuracy roadmap: a *suggestion* that two
    devices might be directly cabled, derived from a Flow between them
    where both ends were independently ARP-confirmed on the very same
    Sensor (inventory_service.apply_flow_link_candidates) -- never a
    NetworkLink itself, and never promoted to one automatically. Same
    principle repeated throughout this schema: who-talked-to-whom is not
    proof of a direct cable (a Flow can always have an unmanaged switch, or
    even a managed one this deployment hasn't walked yet, sitting between
    the two ends) -- confidence here tops out well below 1.0 for exactly
    that reason, and reaching 1.0 is reserved for CDP/LLDP/MAC-table
    evidence a switch itself reported (see NetworkLink/SwitchNeighborEntry).

    A pending row is recomputed fresh on every apply_flow_link_candidates
    pass (confidence/evidence/sensor_id may change as more data arrives,
    same as Device.segment_relation). Once a human decides -- POST .../
    promote (creates a real NetworkLink, source="flow_candidate") or
    .../dismiss -- that decision is final and never touched again by a
    later pass; a promoted pair also stops generating new candidate rows
    at all, since a real NetworkLink for that pair now exists.
    """

    __tablename__ = "flow_link_candidates"
    __table_args__ = (UniqueConstraint("device_a_id", "device_b_id", name="uq_flow_link_candidate_pair"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_a_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    device_b_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    # The Sensor both devices were ARP-confirmed on -- the segment this
    # candidate is scoped to (see ArpObservation/Device.segment_relation).
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id"), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=CANDIDATE_PENDING)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime.datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    device_a: Mapped[Device] = relationship(foreign_keys=[device_a_id])
    device_b: Mapped[Device] = relationship(foreign_keys=[device_b_id])


class SwitchTableImport(Base):
    """One switch-reported table (MAC address table / ARP table / CDP-LLDP
    neighbors) that got turned into topology data -- either walked live via
    SNMP or pasted/uploaded by a human (app/switch_table_parsers.py parses
    the raw text into the child rows below; app/topology_from_switch.py
    turns those into NetworkLink rows / Device enrichment).

    `raw_text` is kept even for a successful parse -- if a parser turns out
    to have a bug, this is what lets it be re-run later without asking the
    user to paste the same table again.

    `result_summary` is the plain-JSON dict app/topology_from_switch.py's
    apply_*() returned (links_created_or_updated, suspected_uplinks,
    etc.) -- otherwise that conclusion only ever existed in the single
    HTTP response for whoever ran the import, gone the moment they
    navigated away, with no way to later answer "what did importing this
    table actually do?" (mirrors why CaptureSession persists its own
    packet_count/dropped_count instead of only returning them once)."""

    __tablename__ = "switch_table_imports"

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)  # the switch itself
    table_type: Mapped[str] = mapped_column(String(16))  # "mac_table" | "arp" | "neighbors"
    source: Mapped[str] = mapped_column(String(16))  # "snmp" | "manual_paste"
    # "cisco" | "siemens_scalance" for a manual paste (selects which CLI
    # dialect app/switch_table_parsers.py parses it as); "unknown" for a
    # live SNMP walk, which reads the same standard MIBs regardless of who
    # made the switch.
    vendor: Mapped[str] = mapped_column(String(24))
    raw_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    entries_parsed: Mapped[int] = mapped_column(default=0)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    imported_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(default=utcnow)


class SwitchMacTableEntry(Base):
    """One row of a switch's MAC address table: this MAC was learned on
    this interface. A port that shows up here with more than one MAC is
    the classic sign of an uplink to another switch, not a single
    directly-attached device -- see apply_mac_table() in
    app/topology_from_switch.py, which is the thing that actually acts on
    that (a single-MAC port becomes a NetworkLink; a multi-MAC one is
    reported as a suspected uplink instead, never guessed at)."""

    __tablename__ = "switch_mac_table_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    switch_table_import_id: Mapped[int] = mapped_column(ForeignKey("switch_table_imports.id"), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    interface_name: Mapped[str] = mapped_column(String(64))
    vlan: Mapped[str | None] = mapped_column(String(16), nullable=True)


class SwitchArpEntry(Base):
    """One row of a switch's ARP table (IP <-> MAC). Only ever used to
    backfill a Device's missing ip/mac -- see apply_arp_table() -- never to
    create a NetworkLink; an ARP entry says nothing about physical
    adjacency, only about an IP-to-MAC binding the switch happened to
    observe."""

    __tablename__ = "switch_arp_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    switch_table_import_id: Mapped[int] = mapped_column(ForeignKey("switch_table_imports.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)


class SwitchNeighborEntry(Base):
    """One CDP or LLDP neighbor a switch announced about itself: "my port
    local_port connects to remote_device_name's remote_port". This is the
    strongest signal this app has for a real physical link -- the switch
    is asserting its own direct neighbor, not something inferred -- see
    apply_neighbor_table(). A neighbor that can't be matched to an existing
    Device is reported as unresolved rather than auto-created: a CDP/LLDP
    announcement is good evidence a *link* exists, but not enough on its
    own to invent a whole new Device record for the other end."""

    __tablename__ = "switch_neighbor_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    switch_table_import_id: Mapped[int] = mapped_column(ForeignKey("switch_table_imports.id"), index=True)
    protocol: Mapped[str] = mapped_column(String(8))  # "cdp" | "lldp"
    local_port: Mapped[str] = mapped_column(String(64))
    remote_device_name: Mapped[str] = mapped_column(String(255))
    remote_port: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_mgmt_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    remote_platform: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ArpObservation(Base):
    """A live IP<->MAC binding this sensor itself captured off the wire (an
    ARP request or reply), upserted by (organization_id, sensor_id, ip) --
    last_seen wins, this is not an append-only log. Distinct from
    SwitchArpEntry above, which is a point-in-time snapshot pasted/walked
    from a switch's own ARP table: this one is continuously refreshed from
    passive capture. ARP never routes past a default gateway, so two
    devices with an entry for each other here are proof of sharing one L2
    broadcast domain -- exactly the corroborating signal later
    topology-inference phases need before treating a Flow as anything more
    than "these two IPs talked".

    Scoped by sensor, not just organization: a private IP range is
    routinely reused across independent segments (two different sites, or
    even two isolated lines within the same site -- a Zone can host more
    than one Sensor, each on its own segment/VLAN, see Sensor's docstring),
    so organization-wide (or even site-wide) uniqueness would let one
    segment's binding silently overwrite an unrelated device elsewhere
    that happens to share the same IP. Sensor is the closest thing this
    schema has to "a specific broadcast domain", and unlike Zone/Site it
    costs nothing extra to resolve: CaptureSession.sensor_id is already
    loaded by every caller of ingest_packet_record before it ever reaches
    here."""

    __tablename__ = "arp_observations"
    __table_args__ = (
        UniqueConstraint("organization_id", "sensor_id", "ip", name="uq_arp_observation_org_sensor_ip"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    # Nullable: a caller without sensor context (a direct/manual call, or a
    # pre-migration CaptureSession row) still gets a usable, if
    # org-wide-degraded, binding rather than being rejected outright.
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id"), nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    last_seen: Mapped[datetime.datetime] = mapped_column(default=utcnow)


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
