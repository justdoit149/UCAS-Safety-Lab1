"""Capture-filter presets and the user-space display-filter language.

Capture filters are compiled by libpcap (BPF) before the capture loop.  The
display filter here is a small recursive-descent parser that compiles an
expression into ``Packet -> bool``; it is evaluated by the table proxy model.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Optional

from app.core.models import Packet

Predicate = Callable[[Packet], bool]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# ---------------------------------------------------------------- BPF layer
CAPTURE_FILTER_PRESETS = [
    "（不过滤）",
    "tcp",
    "udp",
    "icmp",
    "icmp6",
    "ip",
    "ip6",
    "arp",
    "tcp port 80",
    "tcp port 443",
    "udp port 53",
    "host 192.168.1.1",
    "HTTP",
    "HTTPS",
    "DNS",
]

CAPTURE_FRIENDLY = {
    "HTTP": "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8888",
    "HTTPS": "tcp port 443 or tcp port 8443",
    "DNS": "udp port 53 or tcp port 53",
}

_DISPLAY_ONLY_WORDS = {"http", "https", "dns", "tls"}


class CaptureFilterHint(ValueError):
    """The user typed a display-filter word into the BPF filter box."""


def resolve_capture_filter(text: str) -> str:
    """Translate a friendly preset name into BPF.

    Empty text and the "no filter" preset mean no filter.  Only exact friendly
    names are translated; arbitrary user input is passed to libpcap untouched.
    """
    value = (text or "").strip()
    if not value or value in ("（不过滤）", "不过滤", "(不过滤)"):
        return ""
    friendly = CAPTURE_FRIENDLY.get(value)
    if friendly is not None:
        return friendly
    if value.lower() in _DISPLAY_ONLY_WORDS:
        raise CaptureFilterHint(
            f"“{value}”是显示过滤词，不能直接作为 BPF 抓包过滤。"
            "请在“显示过滤”中使用，或改写成 tcp port 80 / tcp port 443 / "
            "udp port 53 等 BPF 表达式。"
        )
    return value


# --------------------------------------------------------- display filter
DISPLAY_FILTER_PRESETS = [
    "http",
    "https",
    "dns",
    "tls",
    "tcp",
    "udp",
    "icmp",
    "ipv4",
    "ipv6",
    "arp",
    "tcp and port 80",
    "(tcp or udp) and not port 53",
    "not (http or tls)",
]


class FilterSyntaxError(ValueError):
    """A display-filter expression could not be parsed."""

    def __init__(self, message: str, position: int):
        self.message = message
        self.position = position
        super().__init__(f"位置 {position + 1}: {message}")


@dataclass(frozen=True)
class DisplayFilter:
    source: str
    predicate: Predicate

    def matches(self, packet: Packet) -> bool:
        try:
            return bool(self.predicate(packet))
        except Exception:
            # A predicate must never take the whole table down because one
            # malformed packet has an unexpected field value.
            return False


@dataclass(frozen=True)
class _Token:
    text: str
    position: int


def _tokenize(text: str) -> list[_Token]:
    return [
        _Token(match.group(0), match.start())
        for match in re.finditer(r"\(|\)|[^\s()]+", text)
    ]


def _transport_is(name: str) -> Predicate:
    upper = name.upper()

    def predicate(packet: Packet) -> bool:
        return (packet.transport or "").upper() == upper

    return predicate


def _ip_version_is(version: int) -> Predicate:
    def predicate(packet: Packet) -> bool:
        return packet.ip_version == version

    return predicate


def _app_is(*names: str) -> Predicate:
    wanted = {name.upper() for name in names}

    def predicate(packet: Packet) -> bool:
        return (packet.app or "").upper() in wanted

    return predicate


def _arp_is() -> Predicate:
    def predicate(packet: Packet) -> bool:
        return (
            (packet.transport or "").upper() == "ARP"
            or (packet.proto_label or "").upper() == "ARP"
        )

    return predicate


_PROTO_BUILDERS: dict[str, Callable[[], Predicate]] = {
    "tcp": lambda: _transport_is("TCP"),
    "udp": lambda: _transport_is("UDP"),
    "icmp": lambda: _transport_is("ICMP"),
    "icmp6": lambda: _transport_is("ICMPv6"),
    "ip": lambda: _ip_version_is(4),
    "ipv4": lambda: _ip_version_is(4),
    "ipv6": lambda: _ip_version_is(6),
    "ip6": lambda: _ip_version_is(6),
    "arp": _arp_is,
    "http": lambda: _app_is("HTTP"),
    "https": lambda: _app_is("TLS", "HTTPS"),
    "tls": lambda: _app_is("TLS", "HTTPS"),
    "dns": lambda: _app_is("DNS"),
}


def _and(left: Predicate, right: Predicate) -> Predicate:
    return lambda packet: left(packet) and right(packet)


def _or(left: Predicate, right: Predicate) -> Predicate:
    return lambda packet: left(packet) or right(packet)


def _host_predicate(target: IPAddress) -> Predicate:
    def predicate(packet: Packet) -> bool:
        for text in (packet.ip_src, packet.ip_dst):
            if not text:
                continue
            try:
                if ipaddress.ip_address(text) == target:
                    return True
            except ValueError:
                continue
        return False

    return predicate


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.tokens = _tokenize(text)
        self.index = 0

    # ------------------------------------------------------------- helpers
    def _peek(self) -> Optional[_Token]:
        if self.index < len(self.tokens):
            return self.tokens[self.index]
        return None

    def _advance(self) -> Optional[_Token]:
        token = self._peek()
        if token is not None:
            self.index += 1
        return token

    def _match(self, word: str) -> bool:
        token = self._peek()
        if token is not None and token.text.lower() == word:
            self.index += 1
            return True
        return False

    def _error(self, message: str, token: Optional[_Token] = None) -> None:
        position = token.position if token is not None else len(self.text)
        raise FilterSyntaxError(message, position)

    def _required(self, message: str) -> _Token:
        token = self._advance()
        if token is None:
            self._error(message)
        return token

    # -------------------------------------------------------------- grammar
    def parse(self) -> DisplayFilter:
        predicate = self._parse_or()
        token = self._peek()
        if token is not None:
            self._error(f"多余的内容 “{token.text}”", token)
        return DisplayFilter(self.text, predicate)

    def _parse_or(self) -> Predicate:
        left = self._parse_and()
        while self._match("or"):
            right = self._parse_and()
            left = _or(left, right)
        return left

    def _parse_and(self) -> Predicate:
        left = self._parse_not()
        while self._match("and"):
            right = self._parse_not()
            left = _and(left, right)
        return left

    def _parse_not(self) -> Predicate:
        if self._match("not"):
            operand = self._parse_not()
            return lambda packet: not operand(packet)
        return self._parse_primary()

    def _parse_primary(self) -> Predicate:
        if self._match("("):
            predicate = self._parse_or()
            if not self._match(")"):
                token = self._peek()
                self._error("缺少右括号 “)”", token)
            return predicate
        return self._parse_predicate()

    def _parse_predicate(self) -> Predicate:
        token = self._advance()
        if token is None:
            self._error("表达式不完整，缺少过滤条件")
        word = token.text.lower()

        builder = _PROTO_BUILDERS.get(word)
        if builder is not None:
            return builder()

        if word == "port":
            number = self._parse_port()
            return lambda packet: packet.sport == number or packet.dport == number

        if word == "host":
            target = self._parse_host()
            return _host_predicate(target)

        if word in ("src", "dst"):
            if self._match("port"):
                number = self._parse_port()
                if word == "src":
                    return lambda packet: packet.sport == number
                return lambda packet: packet.dport == number
            if self._match("host"):
                target = self._parse_host()
                if word == "src":
                    return lambda packet: _ip_equals(packet.ip_src, target)
                return lambda packet: _ip_equals(packet.ip_dst, target)
            self._error("src/dst 后面应为 port 或 host", self._peek())

        if word in ("and", "or", "not", ")"):
            self._error(f"此处不能使用 “{token.text}”", token)

        self._error(f"未知的过滤词 “{token.text}”", token)

    def _parse_port(self) -> int:
        token = self._advance()
        if token is None:
            self._error("port 后面需要端口号")
        try:
            number = int(token.text, 10)
        except ValueError:
            self._error(f"端口号必须是整数，得到 “{token.text}”", token)
        if not 0 <= number <= 65535:
            self._error(f"端口号超出范围 0-65535: {number}", token)
        return number

    def _parse_host(self) -> IPAddress:
        token = self._advance()
        if token is None:
            self._error("host 后面需要 IP 地址")
        try:
            return ipaddress.ip_address(token.text)
        except ValueError:
            self._error(f"无效的 IP 地址 “{token.text}”", token)


def _ip_equals(text: str, target: IPAddress) -> bool:
    if not text:
        return False
    try:
        return ipaddress.ip_address(text) == target
    except ValueError:
        return False


def compile_display_filter(text: str) -> DisplayFilter:
    """Compile a display filter, raising FilterSyntaxError with a position."""
    stripped = (text or "").strip()
    if not stripped:
        raise FilterSyntaxError("表达式为空", 0)
    return _Parser(stripped).parse()
