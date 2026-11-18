"""Link-layer and network/transport dissector.

The dissector is intentionally dependency-free and defensive: every read is
bounds-checked, so a truncated or malicious frame produces a partial packet
instead of an exception.  Application protocols are handled in M4.
"""

from __future__ import annotations

import socket

from app.core.models import Field, Layer, Packet

# libpcap link-layer types
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

_IP_PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

_TCP_OPTION_NAMES = {
    0: "End of Option List",
    1: "No-Operation",
    2: "MSS",
    3: "Window Scale",
    4: "SACK Permitted",
    5: "SACK",
    8: "Timestamps",
    28: "User Timeout",
    29: "TCP-AO",
    30: "Multipath TCP",
}


# ---------------------------------------------------------------- primitives
def _u8(data: bytes, offset: int) -> int:
    return data[offset] if 0 <= offset < len(data) else 0


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 2], "big")


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 4], "big")


def _mac(data: bytes, offset: int) -> str:
    part = data[offset : offset + 6]
    return ":".join(f"{byte:02x}" for byte in part) if len(part) == 6 else ""


def _ipv4(data: bytes, offset: int) -> str:
    part = data[offset : offset + 4]
    return ".".join(str(byte) for byte in part) if len(part) == 4 else ""


def _ipv6(data: bytes, offset: int) -> str:
    part = data[offset : offset + 16]
    if len(part) != 16:
        return ""
    try:
        return socket.inet_ntop(socket.AF_INET6, part)
    except OSError:
        return ""


def _hex(value: int, width: int = 2) -> str:
    return f"0x{value:0{width}x}"


def _proto_name(proto: int) -> str:
    return _IP_PROTO_NAMES.get(proto, f"protocol {proto}")


def _tcp_flags(flags: int, ns: bool = False) -> str:
    names = []
    if flags & 0x01:
        names.append("FIN")
    if flags & 0x02:
        names.append("SYN")
    if flags & 0x04:
        names.append("RST")
    if flags & 0x08:
        names.append("PSH")
    if flags & 0x10:
        names.append("ACK")
    if flags & 0x20:
        names.append("URG")
    if flags & 0x40:
        names.append("ECE")
    if flags & 0x80:
        names.append("CWR")
    if ns:
        names.append("NS")
    return ", ".join(names) if names else "none"


def _ipv4_flags(flags: int) -> str:
    names = []
    if flags & 0x4:
        names.append("DF")
    if flags & 0x2:
        names.append("MF")
    if flags & 0x1:
        names.append("reserved")
    return ", ".join(names) if names else "none"


def _field(layer: Layer, name: str, value: str, offset: int, length: int,
           children: list[Field] | None = None) -> Field:
    item = Field(name, value, offset, length, children or [])
    layer.fields.append(item)
    return item


def _clamped_length(raw: bytes, offset: int, length: int) -> int:
    return max(0, min(length, len(raw) - offset))


# --------------------------------------------------------------- entry point
def dissect(
    index: int,
    ts: float,
    raw: bytes,
    orig_len: int,
    linktype: int,
) -> Packet:
    """Dissect one captured frame.

    ``index`` is the 1-based packet number within the capture session.
    """
    raw = bytes(raw)
    packet = Packet(
        index=index,
        ts=ts,
        caplen=len(raw),
        orig_len=max(orig_len, len(raw)),
        raw=raw,
        linktype=linktype,
        truncated=orig_len > len(raw),
    )

    offset = 0
    ethertype: int | None = None

    if linktype == DLT_EN10MB:
        ethertype, offset = _parse_ethernet(packet, raw)
    elif linktype == DLT_NULL:
        ethertype, offset = _parse_null(packet, raw)
    elif linktype == DLT_RAW:
        ethertype, offset = _parse_raw_ip(packet, raw)
    else:
        length = len(raw)
        layer = Layer(
            f"Link type {linktype}",
            [Field("Raw bytes", f"{length} bytes", 0, length)],
            0,
            length,
        )
        packet.layers.append(layer)
        packet.proto_label = f"LINKTYPE {linktype}"
        packet.summary = f"{length} bytes"

    if ethertype == ETHERTYPE_IPV4:
        _parse_ipv4(packet, raw, offset)
    elif ethertype == ETHERTYPE_IPV6:
        _parse_ipv6(packet, raw, offset)
    elif ethertype == ETHERTYPE_ARP:
        _parse_arp(packet, raw, offset)
    elif ethertype is not None:
        length = max(0, len(raw) - offset)
        layer = Layer(
            "Payload",
            [Field("Data", f"{length} bytes", offset, length)],
            offset,
            length,
        )
        packet.layers.append(layer)
        packet.proto_label = f"EtherType {_hex(ethertype, 4)}"
        packet.summary = f"{_hex(ethertype, 4)}  {length} bytes"

    _finish(packet)
    return packet


def _finish(packet: Packet) -> None:
    if not packet.layers:
        packet.layers.append(Layer("Raw", [Field("Raw bytes", "0 bytes", 0, 0)], 0, 0))
    if not packet.proto_label:
        packet.proto_label = packet.layers[-1].name
    if not packet.summary:
        packet.summary = packet.proto_label
    if packet.truncated and "[truncated]" not in packet.summary:
        packet.summary += " [truncated]"


# --------------------------------------------------------------- link layers
def _parse_ethernet(packet: Packet, raw: bytes) -> tuple[int | None, int]:
    if len(raw) < 14:
        length = len(raw)
        layer = Layer(
            "Ethernet",
            [Field("Error", "truncated Ethernet header", 0, length)],
            0,
            length,
        )
        packet.layers.append(layer)
        packet.truncated = True
        packet.proto_label = "Ethernet"
        packet.summary = "Truncated Ethernet"
        return None, length

    layer = Layer("Ethernet", [], 0, 14)
    _field(layer, "Destination", _mac(raw, 0), 0, 6)
    _field(layer, "Source", _mac(raw, 6), 6, 6)
    ethertype = _u16(raw, 12)
    type_name = {
        ETHERTYPE_IPV4: "IPv4",
        ETHERTYPE_ARP: "ARP",
        ETHERTYPE_IPV6: "IPv6",
        0x8100: "802.1Q VLAN",
        0x88A8: "802.1ad QinQ",
    }.get(ethertype, "")
    _field(layer, "Type", f"{_hex(ethertype, 4)} ({type_name})" if type_name
           else _hex(ethertype, 4), 12, 2)

    packet.src = _mac(raw, 6)
    packet.dst = _mac(raw, 0)
    packet.layers.append(layer)

    offset = 14
    vlan_depth = 0
    while ethertype in (0x8100, 0x88A8) and vlan_depth < 3:
        if offset + 4 > len(raw):
            packet.truncated = True
            break
        tci = _u16(raw, offset)
        inner = _u16(raw, offset + 2)
        vlan = Layer("802.1Q VLAN", [], offset, 4)
        _field(vlan, "Priority", str((tci >> 13) & 0x7), offset, 1)
        _field(vlan, "DEI", str((tci >> 12) & 0x1), offset, 1)
        _field(vlan, "VLAN ID", str(tci & 0x0FFF), offset, 2)
        _field(vlan, "Type", _hex(inner, 4), offset + 2, 2)
        packet.layers.append(vlan)
        ethertype = inner
        offset += 4
        vlan_depth += 1

    return ethertype, offset


def _parse_null(packet: Packet, raw: bytes) -> tuple[int | None, int]:
    if len(raw) < 4:
        length = len(raw)
        packet.layers.append(
            Layer("Null/Loopback", [Field("Error", "truncated", 0, length)], 0, length)
        )
        packet.truncated = True
        packet.proto_label = "Null/Loopback"
        packet.summary = "Truncated loopback header"
        return None, length

    family = int.from_bytes(raw[0:4], "little")
    family_name = {
        2: "AF_INET (IPv4)",
        23: "AF_INET6 (IPv6)",
        24: "AF_INET6 (IPv6)",
        28: "AF_INET6 (IPv6)",
        30: "AF_INET6 (IPv6)",
    }.get(family, "unknown")
    layer = Layer("Null/Loopback", [], 0, 4)
    _field(layer, "Family", f"{family} ({family_name})", 0, 4)
    packet.layers.append(layer)

    if family == 2:
        return ETHERTYPE_IPV4, 4
    if family in (23, 24, 28, 30):
        return ETHERTYPE_IPV6, 4

    packet.proto_label = "Null/Loopback"
    packet.summary = f"Address family {family}"
    return None, 4


def _parse_raw_ip(packet: Packet, raw: bytes) -> tuple[int | None, int]:
    if not raw:
        packet.proto_label = "Raw IP"
        packet.summary = "Empty frame"
        return None, 0
    version = raw[0] >> 4
    packet.layers.append(
        Layer("Raw IP", [Field("Version", str(version), 0, 1)], 0, 0)
    )
    if version == 4:
        return ETHERTYPE_IPV4, 0
    if version == 6:
        return ETHERTYPE_IPV6, 0
    packet.proto_label = "Raw IP"
    packet.summary = f"IP version {version}"
    return None, 0


# ---------------------------------------------------------------------- ARP
def _parse_arp(packet: Packet, raw: bytes, offset: int) -> None:
    available = len(raw) - offset
    if available < 8:
        length = max(0, available)
        packet.layers.append(
            Layer("ARP", [Field("Error", "truncated ARP header", offset, length)],
                  offset, length)
        )
        packet.truncated = True
        packet.proto_label = "ARP"
        packet.summary = "Truncated ARP"
        return

    htype = _u16(raw, offset)
    ptype = _u16(raw, offset + 2)
    hlen = _u8(raw, offset + 4)
    plen = _u8(raw, offset + 5)
    oper = _u16(raw, offset + 6)
    arp_len = 8 + 2 * hlen + 2 * plen
    captured_len = min(arp_len, available)

    layer = Layer("ARP", [], offset, captured_len)
    _field(layer, "Hardware type", str(htype), offset, 2)
    _field(layer, "Protocol type", _hex(ptype, 4), offset + 2, 2)
    _field(layer, "Hardware size", str(hlen), offset + 4, 1)
    _field(layer, "Protocol size", str(plen), offset + 5, 1)
    _field(layer, "Opcode", str(oper), offset + 6, 2)

    sha_off = offset + 8
    spa_off = sha_off + hlen
    tha_off = spa_off + plen
    tpa_off = tha_off + hlen

    sha_len = max(0, min(hlen, len(raw) - sha_off))
    spa_len = max(0, min(plen, len(raw) - spa_off))
    tha_len = max(0, min(hlen, len(raw) - tha_off))
    tpa_len = max(0, min(plen, len(raw) - tpa_off))

    sha = _mac(raw, sha_off) if sha_len == 6 else raw[sha_off : sha_off + sha_len].hex()
    spa = (
        _ipv4(raw, spa_off)
        if ptype == ETHERTYPE_IPV4 and spa_len == 4
        else raw[spa_off : spa_off + spa_len].hex()
    )
    tha = _mac(raw, tha_off) if tha_len == 6 else raw[tha_off : tha_off + tha_len].hex()
    tpa = (
        _ipv4(raw, tpa_off)
        if ptype == ETHERTYPE_IPV4 and tpa_len == 4
        else raw[tpa_off : tpa_off + tpa_len].hex()
    )

    _field(layer, "Sender MAC", sha, sha_off, sha_len)
    _field(layer, "Sender IP", spa, spa_off, spa_len)
    _field(layer, "Target MAC", tha, tha_off, tha_len)
    _field(layer, "Target IP", tpa, tpa_off, tpa_len)
    packet.layers.append(layer)

    packet.src = sha
    packet.dst = tha
    if ptype == ETHERTYPE_IPV4 and plen == 4:
        packet.ip_src = spa
        packet.ip_dst = tpa
    packet.proto_label = "ARP"
    packet.transport = "ARP"
    if arp_len > available:
        packet.truncated = True

    if oper == 1:
        packet.summary = f"Who has {tpa}? Tell {spa}"
    elif oper == 2:
        packet.summary = f"{spa} is at {sha}"
    else:
        packet.summary = f"ARP opcode {oper}: {spa} -> {tpa}"


# --------------------------------------------------------------------- IPv4
def _parse_ipv4(packet: Packet, raw: bytes, offset: int) -> None:
    available = len(raw) - offset
    if available < 20:
        length = max(0, available)
        packet.layers.append(
            Layer("IPv4", [Field("Error", "truncated IPv4 header", offset, length)],
                  offset, length)
        )
        packet.truncated = True
        packet.proto_label = "IPv4"
        packet.summary = "Truncated IPv4"
        return

    version_ihl = _u8(raw, offset)
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    total_len = _u16(raw, offset + 2)
    if total_len == 0 or total_len < ihl:
        total_len = available
        packet.truncated = True
    if ihl < 20:
        packet.truncated = True
        ihl = 20
    header_len = min(ihl, available)
    ip_end = min(offset + total_len, len(raw))

    flags_frag = _u16(raw, offset + 6)
    flags = flags_frag >> 13
    frag_offset = (flags_frag & 0x1FFF) * 8
    proto = _u8(raw, offset + 9)

    layer = Layer("IPv4", [], offset, max(header_len, ip_end - offset))
    _field(layer, "Version", str(version), offset, 1)
    _field(layer, "IHL", f"{ihl // 4} ({ihl} bytes)", offset, 1)
    _field(layer, "DSCP", str(_u8(raw, offset + 1) >> 2), offset + 1, 1)
    _field(layer, "ECN", str(_u8(raw, offset + 1) & 0x3), offset + 1, 1)
    _field(layer, "Total Length", str(total_len), offset + 2, 2)
    _field(layer, "Identification", _hex(_u16(raw, offset + 4), 4), offset + 4, 2)
    _field(layer, "Flags", f"{_hex(flags, 1)} ({_ipv4_flags(flags)})", offset + 6, 1)
    _field(layer, "Fragment Offset", str(frag_offset), offset + 6, 2)
    _field(layer, "TTL", str(_u8(raw, offset + 8)), offset + 8, 1)
    _field(layer, "Protocol", f"{proto} ({_proto_name(proto)})", offset + 9, 1)
    _field(layer, "Header Checksum", _hex(_u16(raw, offset + 10), 4), offset + 10, 2)
    _field(layer, "Source", _ipv4(raw, offset + 12), offset + 12, 4)
    _field(layer, "Destination", _ipv4(raw, offset + 16), offset + 16, 4)
    if ihl > 20:
        options_len = max(0, min(ihl - 20, available - 20))
        _field(layer, "Options", f"{ihl - 20} bytes", offset + 20, options_len)
    packet.layers.append(layer)

    packet.ip_src = _ipv4(raw, offset + 12)
    packet.ip_dst = _ipv4(raw, offset + 16)
    packet.proto_label = "IPv4"
    packet.summary = f"{packet.ip_src} → {packet.ip_dst}  proto={_proto_name(proto)}"

    if total_len > available:
        packet.truncated = True
    if frag_offset != 0:
        packet.summary += f"  Fragment offset={frag_offset}"
        return

    l4_offset = offset + ihl
    l4_avail = max(0, ip_end - l4_offset)
    if l4_avail <= 0:
        return

    if proto == 6:
        _parse_tcp(packet, raw, l4_offset, l4_avail)
    elif proto == 17:
        _parse_udp(packet, raw, l4_offset, l4_avail)
    elif proto == 1:
        _parse_icmp(packet, raw, l4_offset, l4_avail)
    else:
        packet.layers.append(
            Layer(f"IP payload: {_proto_name(proto)}",
                  [Field("Data", f"{l4_avail} bytes", l4_offset, l4_avail)],
                  l4_offset, l4_avail)
        )


# --------------------------------------------------------------------- IPv6
def _parse_ipv6(packet: Packet, raw: bytes, offset: int) -> None:
    available = len(raw) - offset
    if available < 40:
        length = max(0, available)
        packet.layers.append(
            Layer("IPv6", [Field("Error", "truncated IPv6 header", offset, length)],
                  offset, length)
        )
        packet.truncated = True
        packet.proto_label = "IPv6"
        packet.summary = "Truncated IPv6"
        return

    first = _u32(raw, offset)
    version = first >> 28
    traffic_class = (first >> 20) & 0xFF
    flow_label = first & 0xFFFFF
    payload_len = _u16(raw, offset + 4)
    next_header = _u8(raw, offset + 6)
    hop_limit = _u8(raw, offset + 7)
    src = _ipv6(raw, offset + 8)
    dst = _ipv6(raw, offset + 24)

    header_len = min(40, available)
    layer = Layer("IPv6", [], offset, header_len)
    _field(layer, "Version", str(version), offset, 1)
    _field(layer, "Traffic Class", str(traffic_class), offset, 1)
    _field(layer, "Flow Label", _hex(flow_label, 5), offset + 1, 3)
    _field(layer, "Payload Length", str(payload_len), offset + 4, 2)
    _field(layer, "Next Header", f"{next_header} ({_proto_name(next_header)})",
           offset + 6, 1)
    _field(layer, "Hop Limit", str(hop_limit), offset + 7, 1)
    _field(layer, "Source", src, offset + 8, 16)
    _field(layer, "Destination", dst, offset + 24, 16)
    packet.layers.append(layer)

    packet.ip_src = src
    packet.ip_dst = dst
    packet.proto_label = "IPv6"
    packet.summary = f"{src} → {dst}  next={_proto_name(next_header)}"

    if payload_len == 0:
        end = len(raw)
    else:
        end = min(offset + 40 + payload_len, len(raw))
        if offset + 40 + payload_len > len(raw):
            packet.truncated = True

    cursor = offset + 40
    ext_count = 0
    while next_header in (0, 43, 60):
        name = {
            0: "IPv6 Hop-by-Hop Options",
            43: "IPv6 Routing",
            60: "IPv6 Destination Options",
        }[next_header]
        if cursor + 2 > len(raw) or cursor + 2 > end:
            packet.truncated = True
            packet.layers.append(
                Layer(name, [Field("Error", "truncated extension header",
                                   cursor, max(0, len(raw) - cursor))],
                      cursor, max(0, len(raw) - cursor))
            )
            packet.summary += f"  {name}"
            return
        new_next = _u8(raw, cursor)
        ext_len = (_u8(raw, cursor + 1) + 1) * 8
        actual = min(ext_len, max(0, len(raw) - cursor))
        ext = Layer(name, [], cursor, actual)
        _field(ext, "Next Header", f"{new_next} ({_proto_name(new_next)})",
               cursor, 1)
        _field(ext, "Header Length", f"{ext_len} bytes", cursor + 1, 1)
        if actual > 2:
            _field(ext, "Data", f"{actual - 2} bytes", cursor + 2, actual - 2)
        packet.layers.append(ext)
        packet.summary += f"  {name}"
        if ext_len > actual:
            packet.truncated = True
        cursor += ext_len
        next_header = new_next
        ext_count += 1
        if ext_count > 8 or cursor > end:
            packet.truncated = True
            break

    if next_header == 44:  # Fragment header
        if cursor + 8 > len(raw) or cursor + 8 > end:
            packet.truncated = True
            packet.layers.append(
                Layer("IPv6 Fragment",
                      [Field("Error", "truncated fragment header", cursor,
                             max(0, len(raw) - cursor))],
                      cursor, max(0, len(raw) - cursor))
            )
            return
        new_next = _u8(raw, cursor)
        frag_field = _u16(raw, cursor + 2)
        frag_offset = (frag_field >> 3) * 8
        more_fragments = bool(frag_field & 0x1)
        ident = _u32(raw, cursor + 4)
        frag = Layer("IPv6 Fragment", [], cursor, 8)
        _field(frag, "Next Header", f"{new_next} ({_proto_name(new_next)})",
               cursor, 1)
        _field(frag, "Fragment Offset", str(frag_offset), cursor + 2, 2)
        _field(frag, "More Fragments", "yes" if more_fragments else "no",
               cursor + 3, 1)
        _field(frag, "Identification", _hex(ident, 8), cursor + 4, 4)
        packet.layers.append(frag)
        packet.summary += "  IPv6 Fragment"
        cursor += 8
        next_header = new_next
        if frag_offset != 0:
            packet.summary += f" offset={frag_offset}"
            return
    elif next_header == 51:  # Authentication Header
        if cursor + 2 > end:
            packet.truncated = True
            return
        new_next = _u8(raw, cursor)
        ah_len = (_u8(raw, cursor + 1) + 2) * 4
        actual = min(ah_len, max(0, len(raw) - cursor))
        ah = Layer("IPv6 Authentication Header", [], cursor, actual)
        _field(ah, "Next Header", f"{new_next} ({_proto_name(new_next)})",
               cursor, 1)
        _field(ah, "Header Length", f"{ah_len} bytes", cursor + 1, 1)
        if actual > 2:
            _field(ah, "Data", f"{actual - 2} bytes", cursor + 2, actual - 2)
        packet.layers.append(ah)
        packet.summary += "  IPv6 AH"
        cursor += ah_len
        next_header = new_next
        if ah_len > actual:
            packet.truncated = True
    elif next_header == 50:  # ESP is encrypted; stop at the IP layer.
        packet.layers.append(
            Layer("ESP", [Field("Encrypted payload", f"{max(0, end - cursor)} bytes",
                                cursor, max(0, end - cursor))],
                  cursor, max(0, end - cursor))
        )
        packet.proto_label = "ESP"
        packet.summary += "  ESP (encrypted)"
        return

    l4_avail = max(0, end - cursor)
    if l4_avail <= 0:
        return
    if next_header == 6:
        _parse_tcp(packet, raw, cursor, l4_avail)
    elif next_header == 17:
        _parse_udp(packet, raw, cursor, l4_avail)
    elif next_header == 58:
        _parse_icmpv6(packet, raw, cursor, l4_avail)
    else:
        packet.layers.append(
            Layer(f"IPv6 payload: {_proto_name(next_header)}",
                  [Field("Data", f"{l4_avail} bytes", cursor, l4_avail)],
                  cursor, l4_avail)
        )


# ---------------------------------------------------------------------- TCP
def _parse_tcp(packet: Packet, raw: bytes, offset: int, available: int) -> None:
    if available < 20:
        length = max(0, min(available, len(raw) - offset))
        packet.layers.append(
            Layer("TCP", [Field("Error", "truncated TCP header", offset, length)],
                  offset, length)
        )
        packet.truncated = True
        packet.proto_label = "TCP"
        packet.transport = "TCP"
        packet.summary = "Truncated TCP"
        return

    sport = _u16(raw, offset)
    dport = _u16(raw, offset + 2)
    seq = _u32(raw, offset + 4)
    ack = _u32(raw, offset + 8)
    data_offset = (_u8(raw, offset + 12) >> 4) * 4
    flags_byte = _u8(raw, offset + 13)
    ns = bool(_u8(raw, offset + 12) & 0x01)
    flags = _tcp_flags(flags_byte, ns)
    claimed_header_len = data_offset
    if data_offset < 20:
        data_offset = 20
        packet.truncated = True
    header_len = min(data_offset, available)
    options_len = max(0, header_len - 20)
    payload_len = max(0, available - data_offset) if data_offset <= available else 0
    if data_offset > available:
        packet.truncated = True

    layer = Layer("TCP", [], offset, available)
    _field(layer, "Source Port", str(sport), offset, 2)
    _field(layer, "Destination Port", str(dport), offset + 2, 2)
    _field(layer, "Sequence Number", str(seq), offset + 4, 4)
    _field(layer, "Acknowledgment Number", str(ack), offset + 8, 4)
    _field(layer, "Data Offset", f"{claimed_header_len // 4} ({claimed_header_len} bytes)",
           offset + 12, 1)
    _field(layer, "Flags", flags, offset + 13, 1)
    _field(layer, "Window", str(_u16(raw, offset + 14)), offset + 14, 2)
    _field(layer, "Checksum", _hex(_u16(raw, offset + 16), 4), offset + 16, 2)
    _field(layer, "Urgent Pointer", str(_u16(raw, offset + 18)), offset + 18, 2)

    if options_len > 0:
        children: list[Field] = []
        pos = offset + 20
        end = offset + 20 + options_len
        while pos < end:
            kind = _u8(raw, pos)
            if kind == 0:
                children.append(Field("End of Option List", "1 byte", pos, 1))
                break
            if kind == 1:
                children.append(Field("No-Operation", "1 byte", pos, 1))
                pos += 1
                continue
            if pos + 2 > end:
                children.append(Field("Malformed option", "1 byte", pos, end - pos))
                break
            opt_len = _u8(raw, pos + 1)
            if opt_len < 2 or pos + opt_len > end:
                children.append(Field("Malformed option", f"{end - pos} bytes",
                                      pos, end - pos))
                break
            name = _TCP_OPTION_NAMES.get(kind, f"Option {kind}")
            value = raw[pos + 2 : pos + opt_len].hex()
            children.append(Field(name, value if value else "present",
                                  pos, opt_len))
            pos += opt_len
        _field(layer, "Options", f"{options_len} bytes", offset + 20,
               options_len, children)

    if payload_len > 0:
        _field(layer, "TCP payload", f"{payload_len} bytes",
               offset + data_offset, payload_len)
    packet.layers.append(layer)

    packet.sport = sport
    packet.dport = dport
    packet.transport = "TCP"
    packet.tcp_flags = flags
    packet.proto_label = "TCP"
    parts = [f"{sport} → {dport}", f"[{flags}]", f"Seq={seq}"]
    if flags_byte & 0x10:
        parts.append(f"Ack={ack}")
    parts.extend([f"Win={_u16(raw, offset + 14)}", f"Len={payload_len}"])
    packet.summary = "  ".join(parts)
    if packet.truncated and "truncated" not in packet.summary.lower():
        # _finish appends the marker; avoid double-marking here.
        pass


# ---------------------------------------------------------------------- UDP
def _parse_udp(packet: Packet, raw: bytes, offset: int, available: int) -> None:
    if available < 8:
        length = max(0, min(available, len(raw) - offset))
        packet.layers.append(
            Layer("UDP", [Field("Error", "truncated UDP header", offset, length)],
                  offset, length)
        )
        packet.truncated = True
        packet.proto_label = "UDP"
        packet.transport = "UDP"
        packet.summary = "Truncated UDP"
        return

    sport = _u16(raw, offset)
    dport = _u16(raw, offset + 2)
    udp_len = _u16(raw, offset + 4)
    layer_len = min(available, udp_len) if udp_len >= 8 else available
    payload_len = max(0, layer_len - 8)
    if udp_len < 8 or udp_len > available:
        packet.truncated = True

    layer = Layer("UDP", [], offset, layer_len)
    _field(layer, "Source Port", str(sport), offset, 2)
    _field(layer, "Destination Port", str(dport), offset + 2, 2)
    _field(layer, "Length", str(udp_len), offset + 4, 2)
    _field(layer, "Checksum", _hex(_u16(raw, offset + 6), 4), offset + 6, 2)
    if payload_len > 0:
        _field(layer, "UDP payload", f"{payload_len} bytes", offset + 8, payload_len)
    packet.layers.append(layer)

    packet.sport = sport
    packet.dport = dport
    packet.transport = "UDP"
    packet.proto_label = "UDP"
    packet.summary = f"{sport} → {dport}  Len={payload_len}"


# --------------------------------------------------------------- ICMP / v6
def _parse_icmp(packet: Packet, raw: bytes, offset: int, available: int) -> None:
    if available < 4:
        length = max(0, min(available, len(raw) - offset))
        packet.layers.append(
            Layer("ICMP", [Field("Error", "truncated ICMP header", offset, length)],
                  offset, length)
        )
        packet.truncated = True
        packet.proto_label = "ICMP"
        packet.transport = "ICMP"
        packet.summary = "Truncated ICMP"
        return

    icmp_type = _u8(raw, offset)
    code = _u8(raw, offset + 1)
    layer = Layer("ICMP", [], offset, available)
    _field(layer, "Type", f"{icmp_type} ({_icmp_type_name(icmp_type)})",
           offset, 1)
    _field(layer, "Code", str(code), offset + 1, 1)
    _field(layer, "Checksum", _hex(_u16(raw, offset + 2), 4), offset + 2, 2)

    if icmp_type in (0, 8) and available >= 8:
        ident = _u16(raw, offset + 4)
        seq = _u16(raw, offset + 6)
        _field(layer, "Identifier", _hex(ident, 4), offset + 4, 2)
        _field(layer, "Sequence", str(seq), offset + 6, 2)
        if available > 8:
            _field(layer, "Data", f"{available - 8} bytes", offset + 8,
                   available - 8)
        kind = "request" if icmp_type == 8 else "reply"
        packet.summary = f"Echo (ping) {kind}  id={_hex(ident, 4)}, seq={seq}"
    else:
        if available > 4:
            _field(layer, "Data", f"{available - 4} bytes", offset + 4,
                   available - 4)
        packet.summary = f"Type {icmp_type} ({_icmp_type_name(icmp_type)}), Code {code}"

    packet.layers.append(layer)
    packet.proto_label = "ICMP"
    packet.transport = "ICMP"


def _parse_icmpv6(packet: Packet, raw: bytes, offset: int, available: int) -> None:
    if available < 4:
        length = max(0, min(available, len(raw) - offset))
        packet.layers.append(
            Layer("ICMPv6", [Field("Error", "truncated ICMPv6 header",
                                   offset, length)], offset, length)
        )
        packet.truncated = True
        packet.proto_label = "ICMPv6"
        packet.transport = "ICMPv6"
        packet.summary = "Truncated ICMPv6"
        return

    icmp_type = _u8(raw, offset)
    code = _u8(raw, offset + 1)
    layer = Layer("ICMPv6", [], offset, available)
    _field(layer, "Type", f"{icmp_type} ({_icmpv6_type_name(icmp_type)})",
           offset, 1)
    _field(layer, "Code", str(code), offset + 1, 1)
    _field(layer, "Checksum", _hex(_u16(raw, offset + 2), 4), offset + 2, 2)

    if icmp_type in (128, 129) and available >= 8:
        ident = _u16(raw, offset + 4)
        seq = _u16(raw, offset + 6)
        _field(layer, "Identifier", _hex(ident, 4), offset + 4, 2)
        _field(layer, "Sequence", str(seq), offset + 6, 2)
        if available > 8:
            _field(layer, "Data", f"{available - 8} bytes", offset + 8,
                   available - 8)
        kind = "request" if icmp_type == 128 else "reply"
        packet.summary = f"Echo (ping) {kind}  id={_hex(ident, 4)}, seq={seq}"
    elif icmp_type in (135, 136) and available >= 24:
        target = _ipv6(raw, offset + 8)
        _field(layer, "Target Address", target, offset + 8, 16)
        if available > 24:
            _field(layer, "Options", f"{available - 24} bytes", offset + 24,
                   available - 24)
        verb = "solicitation" if icmp_type == 135 else "advertisement"
        packet.summary = f"Neighbor {verb}  {target}"
    else:
        if available > 4:
            _field(layer, "Data", f"{available - 4} bytes", offset + 4,
                   available - 4)
        packet.summary = f"Type {icmp_type} ({_icmpv6_type_name(icmp_type)}), Code {code}"

    packet.layers.append(layer)
    packet.proto_label = "ICMPv6"
    packet.transport = "ICMPv6"


def _icmp_type_name(value: int) -> str:
    return {
        0: "Echo reply",
        3: "Destination unreachable",
        4: "Source quench",
        5: "Redirect",
        8: "Echo request",
        9: "Router advertisement",
        10: "Router solicitation",
        11: "Time exceeded",
        12: "Parameter problem",
        13: "Timestamp request",
        14: "Timestamp reply",
    }.get(value, "unknown")


def _icmpv6_type_name(value: int) -> str:
    return {
        1: "Destination unreachable",
        2: "Packet too big",
        3: "Time exceeded",
        4: "Parameter problem",
        128: "Echo request",
        129: "Echo reply",
        133: "Router solicitation",
        134: "Router advertisement",
        135: "Neighbor solicitation",
        136: "Neighbor advertisement",
        137: "Redirect",
    }.get(value, "unknown")
