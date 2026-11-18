"""Data structures shared by the dissector and the UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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
