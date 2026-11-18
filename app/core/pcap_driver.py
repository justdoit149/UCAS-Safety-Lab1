"""ctypes wrapper for Npcap's wpcap.dll.

Covers device enumeration, live capture, BPF compilation/installation and
driver statistics.  Offline pcap files are added in a later milestone.
"""

from __future__ import annotations

import ctypes
import os
import socket
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char_p,
    c_int,
    c_ubyte,
    c_uint,
    c_void_p,
)
from dataclasses import dataclass
from typing import Optional

PCAP_ERRBUF_SIZE = 256
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF

PCAP_IF_LOOPBACK = 0x00000001
PCAP_IF_UP = 0x00000002
PCAP_IF_RUNNING = 0x00000004

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12

_AF_INET = 2
_AF_INET6 = 23


class NpcapNotFoundError(RuntimeError):
    """Raised when wpcap.dll cannot be loaded."""


class PcapError(RuntimeError):
    """Raised when a libpcap call fails."""


class _Timeval(Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _PcapAddr(Structure):
    pass


_PcapAddr._fields_ = [
    ("next", POINTER(_PcapAddr)),
    ("addr", c_void_p),
    ("netmask", c_void_p),
    ("broadaddr", c_void_p),
    ("dstaddr", c_void_p),
]


class _PcapIf(Structure):
    pass


_PcapIf._fields_ = [
    ("next", POINTER(_PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(_PcapAddr)),
    ("flags", c_uint),
]


class _PcapPkthdr(Structure):
    _fields_ = [
        ("ts", _Timeval),
        ("caplen", c_uint),
        ("len", c_uint),
    ]


class _PcapStat(Structure):
    _fields_ = [
        ("ps_recv", c_uint),
        ("ps_drop", c_uint),
        ("ps_ifdrop", c_uint),
    ]


class _BpfProgram(Structure):
    _fields_ = [
        ("bf_len", c_uint),
        ("bf_insns", c_void_p),
    ]


_lib: Optional[ctypes.WinDLL] = None


def _decode(value) -> str:
    if not value:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _configure(lib: ctypes.WinDLL) -> None:
    lib.pcap_findalldevs.argtypes = [POINTER(POINTER(_PcapIf)), c_char_p]
    lib.pcap_findalldevs.restype = c_int

    lib.pcap_freealldevs.argtypes = [POINTER(_PcapIf)]
    lib.pcap_freealldevs.restype = None

    lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    lib.pcap_open_live.restype = c_void_p

    lib.pcap_datalink.argtypes = [c_void_p]
    lib.pcap_datalink.restype = c_int

    lib.pcap_compile.argtypes = [
        c_void_p,
        POINTER(_BpfProgram),
        c_char_p,
        c_int,
        c_uint,
    ]
    lib.pcap_compile.restype = c_int

    lib.pcap_setfilter.argtypes = [c_void_p, POINTER(_BpfProgram)]
    lib.pcap_setfilter.restype = c_int

    lib.pcap_freecode.argtypes = [POINTER(_BpfProgram)]
    lib.pcap_freecode.restype = None

    lib.pcap_next_ex.argtypes = [
        c_void_p,
        POINTER(POINTER(_PcapPkthdr)),
        POINTER(POINTER(c_ubyte)),
    ]
    lib.pcap_next_ex.restype = c_int

    lib.pcap_stats.argtypes = [c_void_p, POINTER(_PcapStat)]
    lib.pcap_stats.restype = c_int

    lib.pcap_geterr.argtypes = [c_void_p]
    lib.pcap_geterr.restype = c_char_p

    lib.pcap_close.argtypes = [c_void_p]
    lib.pcap_close.restype = None

    lib.pcap_lib_version.argtypes = []
    lib.pcap_lib_version.restype = c_char_p


def _load_library() -> ctypes.WinDLL:
    """Load wpcap.dll once, trying the usual Npcap and WinPcap locations."""
    global _lib
    if _lib is not None:
        return _lib

    if os.name != "nt":
        raise NpcapNotFoundError("本程序依赖 Windows 上的 Npcap/wpcap.dll")

    candidates = []
    env_path = os.environ.get("NPCAP_DLL") or os.environ.get("WPCAP_DLL")
    if env_path:
        candidates.append(env_path)
    candidates.extend(
        [
            r"C:\Windows\System32\Npcap\wpcap.dll",
            "wpcap.dll",
            r"C:\Windows\System32\wpcap.dll",
        ]
    )

    errors = []
    for path in candidates:
        try:
            lib = ctypes.WinDLL(path)
            _configure(lib)
        except (OSError, AttributeError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        _lib = lib
        return lib

    detail = "\n".join(errors)
    raise NpcapNotFoundError(
        "未能加载 wpcap.dll。请先安装 Npcap（建议 1.90，安装时勾选 "
        "WinPcap 兼容模式），或设置 NPCAP_DLL 指向 wpcap.dll。\n"
        f"尝试过的路径:\n{detail}"
    )


def _sockaddr_to_text(ptr: int) -> Optional[str]:
    """Convert a libpcap sockaddr pointer to an IP string."""
    try:
        family = int.from_bytes(ctypes.string_at(ptr, 2), "little")
        if family == _AF_INET:
            raw = ctypes.string_at(ptr, 16)
            return socket.inet_ntop(socket.AF_INET, raw[4:8])
        if family == _AF_INET6:
            raw = ctypes.string_at(ptr, 28)
            return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    except (OSError, ValueError):
        return None
    return None


def _read_addresses(node: Optional[POINTER(_PcapAddr)]) -> tuple[str, ...]:
    result = []
    while node:
        addr = node.contents
        if addr.addr:
            text = _sockaddr_to_text(addr.addr)
            if text:
                result.append(text)
        node = addr.next
    return tuple(result)


@dataclass(frozen=True)
class Device:
    name: str
    description: str
    flags: int
    addresses: tuple[str, ...] = ()

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & PCAP_IF_LOOPBACK) or "loopback" in self.name.lower()

    @property
    def is_up(self) -> bool:
        return bool(self.flags & PCAP_IF_UP)

    @property
    def is_running(self) -> bool:
        return bool(self.flags & PCAP_IF_RUNNING)

    @property
    def is_virtual(self) -> bool:
        text = f"{self.name} {self.description}".lower()
        markers = (
            "vmware",
            "virtualbox",
            "tap-",
            "tap ",
            "tun",
            "vpn",
            "atrust",
            "hyper-v",
            "virtual",
        )
        return any(marker in text for marker in markers)

    @property
    def is_auxiliary(self) -> bool:
        """WAN Miniport / Bluetooth adapters: real devices but poor defaults."""
        text = self.description.lower()
        return "wan miniport" in text or "bluetooth" in text

    @property
    def display_name(self) -> str:
        label = self.description or self.name
        tags = []
        if self.is_loopback:
            tags.append("回环")
        elif self.is_virtual:
            tags.append("虚拟")
        elif self.is_auxiliary:
            tags.append("辅助")
        if tags:
            label = f"[{'/'.join(tags)}] {label}"
        if self.addresses:
            label = f"{label}  ({', '.join(self.addresses[:2])})"
        return label


def list_devices() -> list[Device]:
    """Enumerate capture devices through pcap_findalldevs."""
    lib = _load_library()
    alldevs = POINTER(_PcapIf)()
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    if lib.pcap_findalldevs(byref(alldevs), errbuf) != 0:
        raise PcapError(f"枚举网卡失败: {_decode(errbuf.value) or 'unknown error'}")

    devices = []
    try:
        node = alldevs
        while node:
            item = node.contents
            name = _decode(item.name)
            if name:
                devices.append(
                    Device(
                        name=name,
                        description=_decode(item.description),
                        flags=int(item.flags),
                        addresses=_read_addresses(item.addresses),
                    )
                )
            node = item.next
    finally:
        if alldevs:
            lib.pcap_freealldevs(alldevs)
    return devices


def libpcap_version() -> str:
    return _decode(_load_library().pcap_lib_version())


class PcapHandle:
    """A live libpcap handle owned by the capture thread."""

    def __init__(self, handle: int, device: str, datalink: int, lib: ctypes.WinDLL):
        self._handle = handle
        self._lib = lib
        self.device = device
        self.datalink = datalink
        self._closed = False

    @classmethod
    def open_live(
        cls,
        device: str,
        snaplen: int = 262144,
        promisc: bool = True,
        timeout_ms: int = 50,
    ) -> "PcapHandle":
        lib = _load_library()
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = lib.pcap_open_live(
            device.encode("utf-8"),
            int(snaplen),
            1 if promisc else 0,
            int(timeout_ms),
            errbuf,
        )
        if not handle:
            detail = _decode(errbuf.value) or "unknown error"
            raise PcapError(f"无法打开网卡 {device}: {detail}")
        return cls(handle, device, int(lib.pcap_datalink(handle)), lib)

    def set_filter(self, expression: str) -> None:
        """Compile a BPF expression and attach it to the capture handle.

        The kernel receives a copy of the compiled program, so the temporary
        ``bpf_program`` is freed immediately after ``pcap_setfilter``.
        """
        if self._closed:
            raise PcapError("handle 已关闭")
        expression = (expression or "").strip()
        if not expression:
            return

        program = _BpfProgram()
        result = self._lib.pcap_compile(
            self._handle,
            byref(program),
            expression.encode("utf-8"),
            1,
            PCAP_NETMASK_UNKNOWN,
        )
        if result != 0:
            raise PcapError(f"过滤器编译失败: {self.error()}")
        try:
            if self._lib.pcap_setfilter(self._handle, byref(program)) != 0:
                raise PcapError(f"过滤器安装失败: {self.error()}")
        finally:
            self._lib.pcap_freecode(byref(program))

    def error(self) -> str:
        if not self._handle:
            return "handle 已关闭"
        return _decode(self._lib.pcap_geterr(self._handle)) or "unknown libpcap error"

    def next_packet(self) -> Optional[tuple[float, int, int, bytes]]:
        """Return (timestamp, caplen, original_len, raw) or None on timeout/EOF."""
        if self._closed:
            raise PcapError("handle 已关闭")
        header = POINTER(_PcapPkthdr)()
        data = POINTER(c_ubyte)()
        rc = self._lib.pcap_next_ex(self._handle, byref(header), byref(data))
        if rc == 0 or rc == -2:
            return None
        if rc < 0:
            raise PcapError(f"读取数据包失败: {self.error()}")
        if not header:
            return None
        hdr = header.contents
        caplen = int(hdr.caplen)
        raw = ctypes.string_at(data, caplen) if caplen and data else b""
        timestamp = hdr.ts.tv_sec + hdr.ts.tv_usec / 1_000_000.0
        return timestamp, caplen, int(hdr.len), raw

    def stats(self) -> tuple[int, int, int]:
        """Return (received, dropped, interface_dropped)."""
        if self._closed:
            raise PcapError("handle 已关闭")
        stat = _PcapStat()
        if self._lib.pcap_stats(self._handle, byref(stat)) != 0:
            raise PcapError(f"读取抓包统计失败: {self.error()}")
        return int(stat.ps_recv), int(stat.ps_drop), int(stat.ps_ifdrop)

    def close(self) -> None:
        if self._handle and not self._closed:
            self._lib.pcap_close(self._handle)
            self._handle = None
            self._closed = True

    def __enter__(self) -> "PcapHandle":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
