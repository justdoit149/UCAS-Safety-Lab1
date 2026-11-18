"""Read and write classic pcap files.

Only the pcap format is handled here, not pcapng.  The implementation is pure
Python so opening a file does not depend on libpcap, and file paths with
non-ASCII characters (the common case on Chinese Windows) work naturally.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Iterable, Protocol

from app.core.models import Packet

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_NSEC = 0xA1B23C4D
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16
MAX_RECORD_LEN = 64 * 1024 * 1024


class PcapFormatError(ValueError):
    """The file is not a valid classic pcap file."""


class PcapWriteError(ValueError):
    """The packets cannot be represented as one pcap file."""


class PacketLike(Protocol):
    ts: float
    raw: bytes
    orig_len: int
    linktype: int


@dataclass(frozen=True)
class PcapRecord:
    ts: float
    orig_len: int
    raw: bytes

    @property
    def caplen(self) -> int:
        return len(self.raw)


@dataclass
class PcapFile:
    linktype: int
    records: list[PcapRecord]
    truncated: bool = False


def _read_exact(stream, size: int, what: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise PcapFormatError(f"文件截断：{what}需要 {size} 字节，实际 {len(data)} 字节")
    return data


def read_pcap(path: str | os.PathLike[str],
              max_records: int | None = None) -> PcapFile:
    """Read a classic pcap file.

    ``max_records`` limits how many records are loaded; when the file contains
    more, ``PcapFile.truncated`` is True.  This is used to respect the UI's
    packet-cache limit without reading a huge file into memory first.
    """
    if max_records is not None:
        max_records = max(0, int(max_records))
    try:
        with open(path, "rb") as stream:
            header = _read_exact(stream, PCAP_HEADER_LEN, "pcap 全局头")
            magic_le = struct.unpack("<I", header[:4])[0]
            magic_be = struct.unpack(">I", header[:4])[0]
            if magic_le in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC):
                endian = "<"
                magic = magic_le
            elif magic_be in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC):
                endian = ">"
                magic = magic_be
            else:
                raise PcapFormatError(
                    f"不是标准 pcap 文件：magic=0x{magic_le:08x}"
                )

            version_major, version_minor, _zone, _sigfigs, snaplen, network = (
                struct.unpack(endian + "HHiiii", header[4:])
            )
            if version_major != PCAP_VERSION_MAJOR:
                raise PcapFormatError(
                    f"不支持的 pcap 版本 {version_major}.{version_minor}"
                )
            if snaplen <= 0 or snaplen > MAX_RECORD_LEN:
                raise PcapFormatError(f"pcap snaplen 异常: {snaplen}")
            divider = 1_000_000_000.0 if magic == PCAP_MAGIC_NSEC else 1_000_000.0
            linktype = network

            records: list[PcapRecord] = []
            truncated = False
            while True:
                if max_records is not None and len(records) >= max_records:
                    # Do not read the next full record just to learn that the
                    # cache limit was reached; one byte is enough to know that
                    # more data follows.
                    truncated = bool(stream.read(1))
                    break
                record_header = stream.read(PCAP_RECORD_HEADER_LEN)
                if not record_header:
                    break
                if len(record_header) != PCAP_RECORD_HEADER_LEN:
                    raise PcapFormatError("文件截断：pcap 记录头不完整")
                ts_sec, ts_frac, caplen, orig_len = struct.unpack(
                    endian + "IIII", record_header
                )
                if caplen > MAX_RECORD_LEN:
                    raise PcapFormatError(f"记录长度异常: {caplen}")
                if caplen > snaplen:
                    raise PcapFormatError(
                        f"记录 caplen={caplen} 超过 snaplen={snaplen}"
                    )
                if ts_frac >= int(divider):
                    raise PcapFormatError("时间戳小数部分越界")
                raw = _read_exact(stream, caplen, "pcap 记录数据")
                records.append(
                    PcapRecord(
                        ts=ts_sec + ts_frac / divider,
                        orig_len=max(orig_len, caplen),
                        raw=raw,
                    )
                )
            return PcapFile(linktype=linktype, records=records,
                            truncated=truncated)
    except OSError as exc:
        raise PcapFormatError(f"无法读取 pcap 文件: {exc}") from exc


def _timestamp_parts(ts: float) -> tuple[int, int]:
    seconds = int(ts)
    microseconds = int(round((ts - seconds) * 1_000_000))
    if microseconds >= 1_000_000:
        seconds += 1
        microseconds -= 1_000_000
    if microseconds < 0:
        seconds -= 1
        microseconds += 1_000_000
    return seconds, microseconds


def write_pcap(path: str | os.PathLike[str],
               packets: Iterable[Packet | PacketLike],
               linktype: int | None = None,
               snaplen: int | None = None) -> int:
    """Write packets as a little-endian microsecond pcap file.

    Returns the number of records written.  All packets must share one
    link-layer type; a mixed selection is rejected instead of producing a file
    Wireshark would interpret incorrectly.
    """
    packet_list = list(packets)
    linktypes = {int(packet.linktype) for packet in packet_list}
    if len(linktypes) > 1:
        raise PcapWriteError(
            "选中的包来自不同链路类型，不能保存到同一个 pcap 文件: "
            + ", ".join(str(value) for value in sorted(linktypes))
        )
    if linktype is None:
        linktype = next(iter(linktypes), 1)
    if packet_list and linktypes and next(iter(linktypes)) != linktype:
        raise PcapWriteError("显式指定的 linktype 与包不一致")

    serialized: list[tuple[float, bytes, int, int]] = []
    for packet in packet_list:
        raw = bytes(packet.raw)
        caplen = len(raw)
        orig_len = max(int(packet.orig_len), caplen)
        if caplen > 0xFFFFFFFF or orig_len > 0xFFFFFFFF:
            raise PcapWriteError("包长度超过 pcap 记录头上限")
        if packet.ts < 0:
            raise PcapWriteError("包时间戳不能为负")
        serialized.append((packet.ts, raw, caplen, orig_len))
    needed = max((caplen for _ts, _raw, caplen, _orig in serialized),
                 default=0)

    if snaplen is None:
        snaplen = max(65535, needed)
    else:
        snaplen = min(int(snaplen), MAX_RECORD_LEN)
        if snaplen < needed:
            raise PcapWriteError(
                f"snaplen={snaplen} 小于最长包 {needed} 字节"
            )
    if snaplen <= 0:
        raise PcapWriteError("snaplen 必须大于 0")

    try:
        with open(path, "wb") as stream:
            stream.write(
                struct.pack(
                    "<IHHIIII",
                    PCAP_MAGIC_USEC,
                    PCAP_VERSION_MAJOR,
                    PCAP_VERSION_MINOR,
                    0,
                    0,
                    snaplen,
                    int(linktype),
                )
            )
            for ts, raw, caplen, orig_len in serialized:
                seconds, microseconds = _timestamp_parts(ts)
                stream.write(
                    struct.pack(
                        "<IIII",
                        seconds & 0xFFFFFFFF,
                        microseconds,
                        caplen,
                        orig_len,
                    )
                )
                stream.write(raw)
    except OSError as exc:
        raise PcapWriteError(f"无法写入 pcap 文件: {exc}") from exc
    return len(packet_list)
