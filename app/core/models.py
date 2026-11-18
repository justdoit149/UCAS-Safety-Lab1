"""Data structures shared by the dissector and the UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.core.flowkey import endpoint_key


@dataclass
class Field:
    name: str
    value: str
    offset: int
    length: int
    children: list["Field"] = field(default_factory=list)


@dataclass
class Layer:
    name: str
    fields: list[Field]
    offset: int
    length: int


@dataclass
class Packet:
    index: int
    ts: float
    caplen: int
    orig_len: int
    raw: bytes
    linktype: int
    layers: list[Layer] = field(default_factory=list)

    src: str = ""              # link-layer source (MAC)
    dst: str = ""              # link-layer destination (MAC)
    ip_src: str = ""
    ip_dst: str = ""
    ip_version: int = 0        # 4 / 6 / 0 when no IP layer
    sport: int = 0
    dport: int = 0
    transport: str = ""        # TCP / UDP / ICMP / ICMPv6
    proto_label: str = ""      # highest recognized protocol
    summary: str = ""          # Info column
    tcp_flags: str = ""
    app: str = ""              # filled in M4
    flow_key: Optional[tuple] = None  # filled in M6
    truncated: bool = False

    @property
    def display_src(self) -> str:
        return self.ip_src or self.src or "-"

    @property
    def display_dst(self) -> str:
        return self.ip_dst or self.dst or "-"


@dataclass
class Flow:
    """A bidirectional TCP/UDP conversation.

    ``key`` is the canonical direction-independent tuple from
    :func:`app.core.flowkey.flow_key_for`; the ``src_*`` fields preserve the
    first packet's direction so the table and timeline stay readable.
    """

    key: tuple
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    src_endpoint: tuple[bytes, int]
    dst_endpoint: tuple[bytes, int]
    first_ts: float
    last_ts: float
    packets: list[Packet] = field(default_factory=list)
    byte_count: int = 0
    app: str = ""
    state: str = ""
    fin_directions: set[str] = field(default_factory=set)
    proc_src: object | None = None
    proc_dst: object | None = None

    def __post_init__(self) -> None:
        if not self.state:
            self.state = "NEW" if self.protocol == "TCP" else "ACTIVE"

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def endpoint_procs(self) -> list[object]:
        return [proc for proc in (self.proc_src, self.proc_dst) if proc]

    @property
    def process_pids(self) -> set[int]:
        pids = set()
        for proc in self.endpoint_procs:
            pid = int(getattr(proc, "pid", 0) or 0)
            if pid:
                pids.add(pid)
        return pids

    @property
    def process_label(self) -> str:
        left = _process_text(self.proc_src)
        right = _process_text(self.proc_dst)
        if left and right:
            if getattr(self.proc_src, "pid", None) == getattr(
                self.proc_dst, "pid", None
            ):
                return left
            return f"{left} ↔ {right}"
        return left or right or "-"

    def add_packet(self, packet: Packet) -> None:
        self.packets.append(packet)
        self.byte_count += max(0, int(packet.orig_len))
        if packet.ts < self.first_ts:
            self.first_ts = packet.ts
        if packet.ts >= self.last_ts:
            self.last_ts = packet.ts
        if packet.app:
            self.app = packet.app
        if self.protocol == "TCP":
            flags = {
                part.strip()
                for part in (packet.tcp_flags or "").split(",")
                if part.strip()
            }
            self._update_tcp_state(flags, self._direction(packet))

    def _direction(self, packet: Packet) -> str:
        endpoint = endpoint_key(packet.ip_src, packet.sport)
        return "src" if endpoint == self.src_endpoint else "dst"

    def direction_label(self, packet: Packet) -> str:
        return "A → B" if self._direction(packet) == "src" else "B → A"

    def _update_tcp_state(self, flags: set[str], direction: str) -> None:
        if "RST" in flags:
            self.state = "CLOSED"
            return
        if "SYN" in flags:
            if "ACK" in flags:
                if self.state in ("NEW", "SYN_SENT"):
                    self.state = "SYN_RCVD"
            elif self.state == "NEW":
                self.state = "SYN_SENT"
        elif "ACK" in flags and self.state in (
            "NEW", "SYN_SENT", "SYN_RCVD"
        ):
            self.state = "ESTABLISHED"
        if "FIN" in flags:
            self.fin_directions.add(direction)
            if self.state != "CLOSED":
                self.state = (
                    "CLOSED" if len(self.fin_directions) >= 2 else "FIN_WAIT"
                )


def _process_text(proc: object | None) -> str:
    if proc is None:
        return ""
    name = str(getattr(proc, "name", "") or "?")
    pid = int(getattr(proc, "pid", 0) or 0)
    return f"{name}({pid})" if pid else name
