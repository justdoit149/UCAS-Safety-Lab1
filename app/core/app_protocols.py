"""Application-layer dissectors: HTTP, DNS and TLS.

The transport dissector hands the payload of a TCP/UDP segment to this module.
Identification follows DESIGN.md §6.8: port hints first, then payload
signatures, then the application already associated with the flow.  Only a
single segment is inspected; TCP stream reassembly is intentionally out of
scope for this lab.
"""

from __future__ import annotations

import ipaddress

from app.core.flowkey import flow_key_for
from app.core.models import Field, Layer, Packet

HTTP_PORTS = {80, 8080, 8000, 8888}
TLS_PORTS = {443, 8443}
DNS_PORTS = {53}

_HTTP_METHODS = {
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
    b"TRACE",
    b"PRI",
}

_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    65: "HTTPS",
}

_DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

_DNS_OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}

_DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

_TLS_CONTENT_TYPES = {
    20: "Change Cipher Spec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat",
}

_TLS_HANDSHAKE_TYPES = {
    0: "Hello Request",
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    8: "Encrypted Extensions",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
    24: "Key Update",
    254: "Message Hash",
}

_TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_TLS_EXTENSIONS = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    35: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    65281: "renegotiation_info",
}

_TLS_CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
}

_TLS_ALERT_LEVELS = {1: "warning", 2: "fatal"}
_TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    109: "missing_extension",
    112: "unrecognized_name",
    120: "no_application_protocol",
}


class ApplicationContext:
    """Very small per-flow application cache.

    M6 will replace this with the full flow table.  Here it only prevents a
    response or a continuation packet from being re-classified as something
    else when its payload no longer contains a signature.
    """

    MAX_FLOWS = 4096

    def __init__(self) -> None:
        self._flows: dict[tuple, str] = {}

    def lookup(self, packet: Packet) -> str | None:
        key = _flow_key(packet)
        if key is None:
            return None
        return self._flows.get(key)

    def remember(self, packet: Packet, app: str) -> None:
        key = _flow_key(packet)
        if key is None:
            return
        if len(self._flows) >= self.MAX_FLOWS:
            self._flows.clear()
        self._flows[key] = app

    def clear(self) -> None:
        self._flows.clear()


# ------------------------------------------------------------------ helpers
def _flow_key(packet: Packet) -> tuple | None:
    if not packet.ip_src or not packet.ip_dst:
        return None
    return flow_key_for(
        packet.transport,
        packet.ip_src,
        packet.sport,
        packet.ip_dst,
        packet.dport,
    )


def _safe_offset_length(capture_len: int, offset: int, length: int) -> tuple[int, int]:
    offset = max(0, min(offset, capture_len))
    length = max(0, min(length, capture_len - offset))
    return offset, length


def _field(
    layer: Layer,
    capture_len: int,
    name: str,
    value: str,
    offset: int,
    length: int,
    children: list[Field] | None = None,
) -> Field:
    offset, length = _safe_offset_length(capture_len, offset, length)
    item = Field(name, value, offset, length, children or [])
    layer.fields.append(item)
    return item


def _child(
    field: Field,
    capture_len: int,
    name: str,
    value: str,
    offset: int,
    length: int,
    children: list[Field] | None = None,
) -> Field:
    offset, length = _safe_offset_length(capture_len, offset, length)
    item = Field(name, value, offset, length, children or [])
    field.children.append(item)
    return item


def _u8(data: bytes, offset: int) -> int:
    return data[offset] if 0 <= offset < len(data) else 0


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 2], "big")


def _u24(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 3 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 3], "big")


def _text(data: bytes) -> str:
    return data.decode("latin-1", "replace")


def _hex(value: int, width: int = 2) -> str:
    return f"0x{value:0{width}x}"


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A


def _tls_version(value: int) -> str:
    return _TLS_VERSIONS.get(value, _hex(value, 4))


def _tls_cipher(value: int) -> str:
    name = _TLS_CIPHERS.get(value)
    return f"{_hex(value, 4)} ({name})" if name else _hex(value, 4)


# ------------------------------------------------------------- entry point
def dissect_application(
    packet: Packet,
    raw: bytes,
    payload_offset: int,
    payload_length: int,
    context: ApplicationContext | None = None,
) -> bool:
    """Identify and dissect the application payload of a TCP/UDP packet.

    Returns True when an application layer was appended and ``Packet.app`` was
    set.  The function never raises for malformed payloads; it simply leaves
    the packet at TCP/UDP level.
    """
    capture_len = len(raw)
    start = max(0, min(payload_offset, capture_len))
    end = min(capture_len, start + max(0, payload_length))
    if end <= start:
        return False

    payload = raw[start:end]
    hint = context.lookup(packet) if context is not None else None

    for app in _candidates(packet, payload, hint):
        parsed = _parse_as(app, packet, raw, start, end, payload, app == hint)
        if parsed is None:
            continue
        layer, summary = parsed
        packet.app = app
        packet.proto_label = app
        packet.summary = summary
        packet.layers.append(layer)
        if context is not None:
            context.remember(packet, app)
        return True
    return False


def _candidates(packet: Packet, payload: bytes, hint: str | None) -> list[str]:
    result: list[str] = []
    ports = {packet.sport, packet.dport}

    if packet.transport == "TCP":
        if ports & TLS_PORTS:
            result.append("TLS")
        if ports & HTTP_PORTS:
            result.append("HTTP")
        if ports & DNS_PORTS:
            result.append("DNS")
        if _looks_http(payload):
            result.append("HTTP")
        if _looks_tls(payload):
            result.append("TLS")
        if _looks_dns(payload, tcp=True):
            result.append("DNS")
    elif packet.transport == "UDP":
        if ports & DNS_PORTS:
            result.append("DNS")
        if _looks_dns(payload, tcp=False):
            result.append("DNS")

    if hint:
        result.append(hint)

    unique: list[str] = []
    for app in result:
        if app not in unique:
            unique.append(app)
    return unique


def _parse_as(
    app: str,
    packet: Packet,
    raw: bytes,
    start: int,
    end: int,
    payload: bytes,
    allow_generic: bool,
) -> tuple[Layer, str] | None:
    try:
        if app == "HTTP" and packet.transport == "TCP":
            return _parse_http(raw, start, end, payload, allow_generic)
        if app == "DNS":
            return _parse_dns(packet, raw, start, end, payload, allow_generic)
        if app == "TLS" and packet.transport == "TCP":
            return _parse_tls(packet, raw, start, end, payload, allow_generic)
    except (ValueError, IndexError, OverflowError):
        return None
    return None


# -------------------------------------------------------------------- HTTP
def _first_line(payload: bytes) -> bytes:
    crlf = payload.find(b"\r\n")
    lf = payload.find(b"\n")
    ends = [value for value in (crlf, lf) if value >= 0]
    if not ends:
        return payload
    return payload[: min(ends)]


def _request_line_parts(line: bytes) -> tuple[int, int, int, int, int] | None:
    first = line.find(b" ")
    if first <= 0:
        return None
    method = line[:first]
    if method not in _HTTP_METHODS:
        return None
    second = line.find(b" ", first + 1)
    if second < 0:
        return None
    version = line[second + 1 :]
    if not version.startswith(b"HTTP/"):
        return None
    return first, first + 1, second, second + 1, len(line)


def _response_line_parts(line: bytes) -> tuple[int, int, int, int] | None:
    if not line.startswith(b"HTTP/"):
        return None
    first = line.find(b" ")
    second = line.find(b" ", first + 1) if first >= 0 else -1
    if first < 0 or second < 0:
        return None
    if not line[first + 1 : second].isdigit():
        return None
    return first, first + 1, second, second + 1


def _looks_http(payload: bytes) -> bool:
    line = _first_line(payload)
    return bool(line) and (
        line.startswith(b"HTTP/") or _request_line_parts(line) is not None
    )


def _next_line(payload: bytes, pos: int) -> tuple[int, int]:
    """Return (line end, terminator length) for the line starting at pos."""
    crlf = payload.find(b"\r\n", pos)
    lf = payload.find(b"\n", pos)
    if crlf >= 0 and (lf < 0 or crlf <= lf):
        return crlf, 2
    if lf >= 0:
        return lf, 1
    return len(payload), 0


def _parse_http(
    raw: bytes,
    start: int,
    end: int,
    payload: bytes,
    allow_generic: bool,
) -> tuple[Layer, str] | None:
    capture_len = len(raw)
    line_end, term_len = _next_line(payload, 0)
    line = payload[:line_end]
    request = _request_line_parts(line)
    response = _response_line_parts(line)
    if request is None and response is None:
        if not allow_generic:
            return None
        layer = Layer("HTTP", [], start, end - start)
        _field(layer, capture_len, "Data", f"{len(payload)} bytes", start, len(payload))
        return layer, f"HTTP data  Len={len(payload)}"

    layer = Layer("HTTP", [], start, end - start)
    if request is not None:
        method_end, target_start, target_end, version_start, _ = request
        method = _text(line[:method_end])
        target = _text(line[target_start:target_end])
        version = _text(line[version_start:])
        _field(layer, capture_len, "Request Method", method, start, method_end)
        _field(
            layer,
            capture_len,
            "Request URI",
            target,
            start + target_start,
            target_end - target_start,
        )
        _field(
            layer,
            capture_len,
            "Request Version",
            version,
            start + version_start,
            len(line) - version_start,
        )
        summary = _text(line)
    else:
        assert response is not None
        version_end, code_start, code_end, reason_start = response
        version = _text(line[:version_end])
        code = _text(line[code_start:code_end])
        reason = _text(line[reason_start:])
        _field(
            layer,
            capture_len,
            "Response Version",
            version,
            start,
            version_end,
        )
        _field(
            layer,
            capture_len,
            "Status Code",
            code,
            start + code_start,
            code_end - code_start,
        )
        if reason:
            _field(
                layer,
                capture_len,
                "Reason Phrase",
                reason,
                start + reason_start,
                len(line) - reason_start,
            )
        summary = _text(line)

    headers_start = line_end + term_len
    header_pos = headers_start
    body_start = len(payload)
    children: list[Field] = []
    while header_pos < len(payload) and len(children) < 200:
        header_end, header_term = _next_line(payload, header_pos)
        if header_end == header_pos:
            body_start = min(len(payload), header_end + header_term)
            break
        header_line = payload[header_pos:header_end]
        colon = header_line.find(b":")
        if colon > 0:
            name = _text(header_line[:colon]).strip()
            value = _text(header_line[colon + 1 :]).strip()
            if name:
                children.append(
                    Field(
                        name,
                        value,
                        *(_safe_offset_length(
                            capture_len,
                            start + header_pos,
                            header_end - header_pos,
                        )),
                    )
                )
        if header_term == 0:
            body_start = len(payload)
            break
        header_pos = header_end + header_term

    if children:
        _field(
            layer,
            capture_len,
            "Headers",
            f"{len(children)} headers",
            start + headers_start,
            max(0, body_start - headers_start),
            children,
        )
    if body_start < len(payload):
        _field(
            layer,
            capture_len,
            "Body",
            f"{len(payload) - body_start} bytes",
            start + body_start,
            len(payload) - body_start,
        )
    return layer, summary


# --------------------------------------------------------------------- DNS
def _read_dns_name(data: bytes, pos: int) -> tuple[str, int]:
    """Decode a DNS name, following compression pointers.

    Returns the decoded name and the position immediately after the name at
    the original location.  Raises ValueError on malformed input.
    """
    labels: list[str] = []
    seen: set[int] = set()
    end: int | None = None
    depth = 0
    while True:
        if pos < 0 or pos >= len(data) or pos in seen:
            raise ValueError("bad DNS name")
        if depth > 16:
            raise ValueError("DNS compression loop")
        seen.add(pos)
        length = data[pos]
        if length == 0:
            pos += 1
            if end is None:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            pos = pointer
            depth += 1
            continue
        if length & 0xC0:
            raise ValueError("bad DNS label")
        pos += 1
        if pos + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(_text(data[pos : pos + length]))
        pos += length
    return (".".join(labels) if labels else "."), end


def _looks_dns(payload: bytes, tcp: bool) -> bool:
    data = payload
    if tcp:
        if len(payload) < 2:
            return False
        message_len = _u16(payload, 0)
        if message_len < 12:
            return False
        data = payload[2 : 2 + message_len]
    if len(data) < 12:
        return False
    qd = _u16(data, 4)
    an = _u16(data, 6)
    ns = _u16(data, 8)
    ar = _u16(data, 10)
    if qd > 64 or an > 256 or ns > 64 or ar > 64:
        return False
    if qd == 0:
        return True
    try:
        _, pos = _read_dns_name(data, 12)
    except ValueError:
        return False
    return pos + 4 <= len(data)


def _parse_dns(
    packet: Packet,
    raw: bytes,
    start: int,
    end: int,
    payload: bytes,
    allow_generic: bool,
) -> tuple[Layer, str] | None:
    capture_len = len(raw)
    layer = Layer("DNS", [], start, end - start)
    data = payload
    data_offset = start

    if packet.transport == "TCP":
        if len(payload) < 2:
            if not allow_generic:
                return None
            _field(layer, capture_len, "Data", f"{len(payload)} bytes", start, len(payload))
            return layer, f"DNS data  Len={len(payload)}"
        message_len = _u16(payload, 0)
        _field(layer, capture_len, "TCP Message Length", str(message_len), start, 2)
        if message_len < 12:
            if not allow_generic:
                return None
            _field(
                layer,
                capture_len,
                "Data",
                f"{len(payload) - 2} bytes",
                start + 2,
                len(payload) - 2,
            )
            return layer, f"DNS data  Len={len(payload) - 2}"
        available = min(message_len, max(0, len(payload) - 2))
        data = payload[2 : 2 + available]
        data_offset = start + 2

    if len(data) < 12:
        if not allow_generic:
            return None
        _field(layer, capture_len, "Data", f"{len(data)} bytes", data_offset, len(data))
        return layer, f"DNS data  Len={len(data)}"

    txid = _u16(data, 0)
    flags = _u16(data, 2)
    qd = _u16(data, 4)
    an = _u16(data, 6)
    ns = _u16(data, 8)
    ar = _u16(data, 10)
    if qd > 64 or an > 256 or ns > 64 or ar > 64:
        if not allow_generic:
            return None
        _field(layer, capture_len, "Data", f"{len(data)} bytes", data_offset, len(data))
        return layer, f"DNS data  Len={len(data)}"

    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    _field(layer, capture_len, "Transaction ID", _hex(txid, 4), data_offset, 2)
    _field(layer, capture_len, "Flags", _hex(flags, 4), data_offset + 2, 2)
    _field(layer, capture_len, "Response", "response" if qr else "query",
           data_offset + 2, 1)
    _field(layer, capture_len, "Opcode", _DNS_OPCODES.get(opcode, str(opcode)),
           data_offset + 2, 1)
    _field(layer, capture_len, "Authoritative", "yes" if aa else "no",
           data_offset + 2, 1)
    _field(layer, capture_len, "Truncated", "yes" if tc else "no",
           data_offset + 2, 1)
    _field(layer, capture_len, "Recursion Desired", "yes" if rd else "no",
           data_offset + 2, 1)
    _field(layer, capture_len, "Recursion Available", "yes" if ra else "no",
           data_offset + 3, 1)
    _field(layer, capture_len, "RCODE", _DNS_RCODES.get(rcode, str(rcode)),
           data_offset + 3, 1)
    _field(layer, capture_len, "Questions Count", str(qd), data_offset + 4, 2)
    _field(layer, capture_len, "Answers Count", str(an), data_offset + 6, 2)
    _field(layer, capture_len, "Authority Count", str(ns), data_offset + 8, 2)
    _field(layer, capture_len, "Additional Count", str(ar), data_offset + 10, 2)

    pos = 12
    first_name = ""
    first_type = 0
    questions: list[Field] = []
    try:
        for _ in range(qd):
            name_pos = pos
            name, pos = _read_dns_name(data, pos)
            if pos + 4 > len(data):
                raise ValueError("truncated DNS question")
            qtype = _u16(data, pos)
            qclass = _u16(data, pos + 2)
            if not first_name:
                first_name = name
                first_type = qtype
            item = Field("Question", name, data_offset + name_pos, pos - name_pos)
            _child(item, capture_len, "Name", name, data_offset + name_pos,
                   pos - name_pos)
            _child(item, capture_len, "Type", _DNS_TYPES.get(qtype, str(qtype)),
                   data_offset + pos, 2)
            _child(item, capture_len, "Class", _DNS_CLASSES.get(qclass, str(qclass)),
                   data_offset + pos + 2, 2)
            questions.append(item)
            pos += 4
    except ValueError:
        if not allow_generic:
            return None
        _field(layer, capture_len, "Data", f"{len(data)} bytes", data_offset, len(data))
        return layer, f"DNS data  Len={len(data)}"

    answers_start = pos
    answers: list[Field] = []
    for _ in range(an):
        try:
            name_pos = pos
            name, pos = _read_dns_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype = _u16(data, pos)
            rclass = _u16(data, pos + 2)
            ttl = int.from_bytes(data[pos + 4 : pos + 8], "big")
            rdlength = _u16(data, pos + 8)
            rdata = pos + 10
            if rdata + rdlength > len(data):
                break
            answer = Field(
                "Answer",
                name,
                data_offset + name_pos,
                (rdata + rdlength) - name_pos,
            )
            _child(answer, capture_len, "Name", name, data_offset + name_pos,
                   pos - name_pos)
            _child(answer, capture_len, "Type", _DNS_TYPES.get(rtype, str(rtype)),
                   data_offset + pos, 2)
            _child(answer, capture_len, "Class",
                   _DNS_CLASSES.get(rclass, str(rclass)), data_offset + pos + 2, 2)
            _child(answer, capture_len, "TTL", str(ttl), data_offset + pos + 4, 4)
            _child(answer, capture_len, "Data Length", str(rdlength),
                   data_offset + pos + 8, 2)
            if rtype == 1 and rdlength == 4:
                value = ".".join(str(byte) for byte in data[rdata : rdata + 4])
                _child(answer, capture_len, "Address", value,
                       data_offset + rdata, 4)
            elif rtype == 28 and rdlength == 16:
                try:
                    value = ipaddress.IPv6Address(
                        data[rdata : rdata + 16]
                    ).compressed
                except ValueError:
                    value = data[rdata : rdata + 16].hex()
                _child(answer, capture_len, "Address", value,
                       data_offset + rdata, 16)
            elif rtype == 5:
                try:
                    cname, _ = _read_dns_name(data, rdata)
                except ValueError:
                    cname = ""
                _child(answer, capture_len, "CNAME", cname or "(malformed)",
                       data_offset + rdata, rdlength)
            else:
                _child(answer, capture_len, "Data", data[rdata : rdata + rdlength].hex(),
                       data_offset + rdata, rdlength)
            answers.append(answer)
            pos = rdata + rdlength
        except ValueError:
            break

    if questions:
        _field(
            layer,
            capture_len,
            "Questions",
            f"{len(questions)} question(s)",
            data_offset + 12,
            max(0, answers_start - 12),
            questions,
        )
    if answers:
        _field(
            layer,
            capture_len,
            "Answers",
            f"{len(answers)} answer(s)",
            data_offset + answers_start,
            max(0, pos - answers_start),
            answers,
        )

    prefix = "Standard query" if qr == 0 else "Standard query response"
    parts = [prefix, _hex(txid, 4)]
    if first_name:
        parts.append(f"{_DNS_TYPES.get(first_type, str(first_type))} {first_name}")
    if qr and rcode:
        parts.append(_DNS_RCODES.get(rcode, f"RCODE={rcode}"))
    return layer, " ".join(parts)


# --------------------------------------------------------------------- TLS
def _looks_tls(payload: bytes) -> bool:
    if len(payload) < 6:
        return False
    content_type = payload[0]
    major = payload[1]
    minor = payload[2]
    length = _u16(payload, 3)
    if content_type not in _TLS_CONTENT_TYPES or major != 3 or minor > 4:
        return False
    if length > 18432:
        return False
    if content_type == 22:
        return payload[5] in _TLS_HANDSHAKE_TYPES
    return False


def _parse_tls(
    packet: Packet,
    raw: bytes,
    start: int,
    end: int,
    payload: bytes,
    allow_generic: bool,
) -> tuple[Layer, str] | None:
    capture_len = len(raw)
    if len(payload) < 5:
        return None
    content_type = payload[0]
    major = payload[1]
    minor = payload[2]
    record_len = _u16(payload, 3)
    trusted_port = bool({packet.sport, packet.dport} & TLS_PORTS)
    if (
        content_type not in _TLS_CONTENT_TYPES
        or major != 3
        or minor > 4
        or record_len > 18432
    ):
        return None
    if content_type == 22:
        if len(payload) < 6 or payload[5] not in _TLS_HANDSHAKE_TYPES:
            return None
    elif not trusted_port and not allow_generic:
        return None

    layer = Layer("TLS", [], start, end - start)
    _field(
        layer,
        capture_len,
        "Content Type",
        f"{content_type} ({_TLS_CONTENT_TYPES[content_type]})",
        start,
        1,
    )
    _field(layer, capture_len, "Record Version", _tls_version((major << 8) | minor),
           start + 1, 2)
    _field(layer, capture_len, "Record Length", str(record_len), start + 3, 2)

    body = payload[5:]
    summary = f"TLS {_TLS_CONTENT_TYPES[content_type]}  Len={record_len}"

    if content_type == 22 and len(body) >= 4:
        summary = _parse_tls_handshake(layer, raw, start + 5, body, capture_len)
    elif content_type == 21 and len(body) >= 2:
        level = _TLS_ALERT_LEVELS.get(body[0], str(body[0]))
        description = _TLS_ALERT_DESCRIPTIONS.get(body[1], str(body[1]))
        _field(layer, capture_len, "Alert Level", level, start + 5, 1)
        _field(layer, capture_len, "Alert Description", description, start + 6, 1)
        summary = f"TLS Alert ({level}, {description})"
    elif content_type == 23:
        summary = f"TLS Application Data  Len={record_len}"

    return layer, summary


def _parse_tls_handshake(
    layer: Layer,
    raw: bytes,
    hs_offset: int,
    data: bytes,
    capture_len: int,
) -> str:
    handshake_type = data[0]
    handshake_len = _u24(data, 1)
    name = _TLS_HANDSHAKE_TYPES.get(handshake_type, f"Handshake {handshake_type}")
    _field(layer, capture_len, "Handshake Type", name, hs_offset, 1)
    _field(layer, capture_len, "Handshake Length", str(handshake_len),
           hs_offset + 1, 3)
    body = data[4 : 4 + min(handshake_len, max(0, len(data) - 4))]

    if handshake_type == 1:
        summary = _parse_client_hello(layer, raw, hs_offset + 4, body, capture_len)
        return summary
    if handshake_type == 2:
        summary = _parse_server_hello(layer, raw, hs_offset + 4, body, capture_len)
        return summary
    return f"TLS Handshake ({name})"


def _parse_tls_extensions(
    layer: Layer,
    raw: bytes,
    extensions_offset: int,
    data: bytes,
    capture_len: int,
    client_hello: bool,
) -> tuple[str, list[str], list[str]]:
    sni = ""
    versions: list[str] = []
    alpn: list[str] = []
    if len(data) < 2:
        return sni, versions, alpn

    extensions_len = _u16(data, 0)
    available = min(extensions_len, max(0, len(data) - 2))
    extensions = data[2 : 2 + available]
    if not extensions:
        return sni, versions, alpn

    children: list[Field] = []
    pos = 0
    while pos + 4 <= len(extensions) and len(children) < 64:
        ext_type = _u16(extensions, pos)
        ext_len = _u16(extensions, pos + 2)
        ext_start = pos + 4
        if ext_start + ext_len > len(extensions):
            break
        ext_data = extensions[ext_start : ext_start + ext_len]
        ext_name = _TLS_EXTENSIONS.get(ext_type, f"ext_{ext_type}")
        value = f"{ext_len} bytes"
        if ext_type == 0:
            try:
                list_len = _u16(ext_data, 0)
                name_len = _u16(ext_data, 3)
                if ext_data[2] == 0 and name_len <= len(ext_data) - 5:
                    sni = _text(ext_data[5 : 5 + name_len])
                    value = sni
                elif list_len > 0:
                    value = "server name list"
            except (IndexError, ValueError):
                pass
        elif ext_type == 16:
            try:
                list_len = _u16(ext_data, 0)
                end = min(2 + list_len, len(ext_data))
                p = 2
                while p < end:
                    item_len = ext_data[p]
                    p += 1
                    if p + item_len > end:
                        break
                    alpn.append(_text(ext_data[p : p + item_len]))
                    p += item_len
                value = ", ".join(alpn) if alpn else "empty"
            except (IndexError, ValueError):
                pass
        elif ext_type == 43:
            parsed = _parse_supported_versions(ext_data, client_hello)
            if parsed:
                versions = parsed
                value = ", ".join(versions)
        item = Field(
            ext_name,
            value,
            *(_safe_offset_length(
                capture_len,
                extensions_offset + 2 + pos,
                4 + ext_len,
            )),
        )
        # Add the most useful decoded fields below the extension itself.
        if ext_type == 0 and sni:
            _child(item, capture_len, "Server Name", sni,
                   extensions_offset + 2 + ext_start + 5, len(sni))
        elif ext_type == 16 and alpn:
            _child(item, capture_len, "Protocols", ", ".join(alpn),
                   extensions_offset + 2 + ext_start, ext_len)
        elif ext_type == 43 and versions:
            _child(item, capture_len, "Supported Versions", ", ".join(versions),
                   extensions_offset + 2 + ext_start, ext_len)
        children.append(item)
        pos = ext_start + ext_len

    _field(
        layer,
        capture_len,
        "Extensions",
        f"{len(children)} extension(s)",
        extensions_offset,
        2 + available,
        children,
    )
    return sni, versions, alpn


def _parse_supported_versions(data: bytes, client_hello: bool) -> list[str]:
    versions: list[str] = []
    if client_hello:
        if len(data) < 1:
            return versions
        length = data[0]
        end = min(1 + length, len(data))
        pos = 1
        while pos + 2 <= end:
            value = _u16(data, pos)
            if not _is_grease(value):
                versions.append(_tls_version(value))
            pos += 2
    else:
        if len(data) >= 2:
            value = _u16(data, 0)
            if not _is_grease(value):
                versions.append(_tls_version(value))
    return versions


def _parse_client_hello(
    layer: Layer,
    raw: bytes,
    body_offset: int,
    data: bytes,
    capture_len: int,
) -> str:
    if len(data) < 35:
        return "TLS Client Hello"
    version = _u16(data, 0)
    session_len = _u8(data, 34)
    pos = 35 + session_len
    if pos + 2 > len(data):
        return "TLS Client Hello"
    cipher_len = _u16(data, pos)
    cipher_start = pos + 2
    cipher_end = min(cipher_start + cipher_len, len(data))
    pos = cipher_start + cipher_len
    if pos + 1 > len(data):
        return "TLS Client Hello"
    compression_len = _u8(data, pos)
    compression_start = pos + 1
    pos = compression_start + compression_len
    extensions_len = _u16(data, pos) if pos + 2 <= len(data) else 0

    _field(layer, capture_len, "Client Version", _tls_version(version),
           body_offset, 2)
    _field(layer, capture_len, "Random", "32 bytes", body_offset + 2, 32)
    _field(layer, capture_len, "Session ID Length", str(session_len),
           body_offset + 34, 1)
    if session_len:
        _field(layer, capture_len, "Session ID",
               data[35 : 35 + min(session_len, len(data) - 35)].hex(),
               body_offset + 35, session_len)

    cipher_children: list[Field] = []
    for index in range(0, min(cipher_len, cipher_end - cipher_start), 2):
        if cipher_start + index + 2 > len(data):
            break
        value = _u16(data, cipher_start + index)
        if _is_grease(value):
            continue
        cipher_children.append(
            Field(
                "Cipher Suite",
                _tls_cipher(value),
                *(_safe_offset_length(
                    capture_len, body_offset + cipher_start + index, 2
                )),
            )
        )
    _field(layer, capture_len, "Cipher Suites",
           f"{cipher_len // 2} suite(s)", body_offset + pos - cipher_len - 2,
           min(cipher_len + 2, len(data) - (pos - cipher_len - 2)),
           cipher_children)

    _field(layer, capture_len, "Compression Methods",
           f"{compression_len} method(s)", body_offset + compression_start - 1,
           min(compression_len + 1, len(data) - (compression_start - 1)))

    sni = ""
    if pos + 2 <= len(data) and extensions_len:
        extensions_offset = body_offset + pos
        sni, _, _ = _parse_tls_extensions(
            layer,
            raw,
            extensions_offset,
            data[pos : pos + min(extensions_len + 2, len(data) - pos)],
            capture_len,
            client_hello=True,
        )
    return f"Client Hello (SNI={sni})" if sni else "Client Hello"


def _parse_server_hello(
    layer: Layer,
    raw: bytes,
    body_offset: int,
    data: bytes,
    capture_len: int,
) -> str:
    if len(data) < 35:
        return "TLS Server Hello"
    version = _u16(data, 0)
    session_len = _u8(data, 34)
    pos = 35 + session_len
    if pos + 3 > len(data):
        return "TLS Server Hello"
    cipher = _u16(data, pos)
    pos += 2
    compression = _u8(data, pos)
    pos += 1
    _field(layer, capture_len, "Server Version", _tls_version(version),
           body_offset, 2)
    _field(layer, capture_len, "Random", "32 bytes", body_offset + 2, 32)
    _field(layer, capture_len, "Session ID Length", str(session_len),
           body_offset + 34, 1)
    if session_len:
        _field(layer, capture_len, "Session ID",
               data[35 : 35 + min(session_len, len(data) - 35)].hex(),
               body_offset + 35, session_len)
    _field(layer, capture_len, "Cipher Suite", _tls_cipher(cipher),
           body_offset + pos - 2, 2)
    _field(layer, capture_len, "Compression Method", _hex(compression),
           body_offset + pos - 1, 1)

    selected = ""
    if pos + 2 <= len(data):
        extensions_len = _u16(data, pos)
        if extensions_len:
            _, versions, _ = _parse_tls_extensions(
                layer,
                raw,
                body_offset + pos,
                data[pos : pos + min(extensions_len + 2, len(data) - pos)],
                capture_len,
                client_hello=False,
            )
            if versions:
                selected = versions[0]
    if selected:
        return f"Server Hello ({selected}, {_tls_cipher(cipher)})"
    return f"Server Hello ({_tls_cipher(cipher)})"
