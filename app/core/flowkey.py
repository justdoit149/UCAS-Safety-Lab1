"""Canonical flow keys shared by the dissector and the flow table."""

from __future__ import annotations

import ipaddress


def _strip_zone(value: str) -> str:
    """Drop an IPv6 zone id (``fe80::1%12``) before canonicalization."""
    return str(value).split("%", 1)[0].strip()


def normalize_ip(value: str) -> bytes | None:
    """Return a packed IP address, or None when *value* is not an IP literal."""
    try:
        return ipaddress.ip_address(_strip_zone(value)).packed
    except ValueError:
        return None


def normalize_ip_text(value: str) -> str:
    """Canonical text form used for process-map lookups."""
    try:
        return ipaddress.ip_address(_strip_zone(value)).compressed
    except ValueError:
        return _strip_zone(value).lower()


def endpoint_key(ip: str, port: int) -> tuple[bytes, int] | None:
    packed = normalize_ip(ip)
    if packed is None:
        return None
    return packed, int(port)


def flow_key_for(
    transport: str,
    ip_src: str,
    sport: int,
    ip_dst: str,
    dport: int,
) -> tuple | None:
    """Build ``(transport, endpoint, endpoint)`` with endpoints sorted.

    Sorting makes the key direction-independent, so both halves of a TCP
    conversation land in the same flow.  Packed addresses make different IPv6
    spellings compare equal.
    """
    if transport not in ("TCP", "UDP"):
        return None
    left = endpoint_key(ip_src, sport)
    right = endpoint_key(ip_dst, dport)
    if left is None or right is None:
        return None
    first, second = sorted((left, right))
    return (transport, first, second)


def endpoint_text(ip: str, port: int) -> str:
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"
