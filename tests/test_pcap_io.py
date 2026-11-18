"""Tests for the pure-Python classic pcap reader and writer."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from app.core.models import Packet
from app.core.pcap_io import (
    PCAP_MAGIC_NSEC,
    PCAP_MAGIC_USEC,
    PcapFormatError,
    PcapWriteError,
    read_pcap,
    write_pcap,
)


def make_packet(
    raw: bytes = b"\x00\x11\x22\x33",
    *,
    ts: float = 1_700_000_000.25,
    orig_len: int | None = None,
    linktype: int = 1,
) -> Packet:
    return Packet(
        index=1,
        ts=ts,
        caplen=len(raw),
        orig_len=len(raw) if orig_len is None else orig_len,
        raw=raw,
        linktype=linktype,
    )


class PcapRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_write_and_read_roundtrip(self) -> None:
        path = os.path.join(self.tmp, "roundtrip.pcap")
        packets = [
            make_packet(b"\x01\x02\x03", ts=100.125),
            make_packet(b"\x04" * 64, ts=101.5, orig_len=128),
            make_packet(b"", ts=102.0),
        ]
        written = write_pcap(path, packets)
        self.assertEqual(written, 3)

        loaded = read_pcap(path)
        self.assertEqual(loaded.linktype, 1)
        self.assertFalse(loaded.truncated)
        self.assertEqual(len(loaded.records), 3)
        self.assertEqual(loaded.records[0].raw, b"\x01\x02\x03")
        self.assertAlmostEqual(loaded.records[0].ts, 100.125, places=6)
        self.assertEqual(loaded.records[1].orig_len, 128)
        self.assertEqual(loaded.records[2].raw, b"")
        with open(path, "rb") as stream:
            self.assertEqual(
                struct.unpack("<I", stream.read(4))[0], PCAP_MAGIC_USEC
            )

    def test_non_ascii_path(self) -> None:
        path = os.path.join(self.tmp, "抓包_测试.pcap")
        write_pcap(path, [make_packet()])
        loaded = read_pcap(path)
        self.assertEqual(len(loaded.records), 1)

    def test_empty_file_is_valid(self) -> None:
        path = os.path.join(self.tmp, "empty.pcap")
        self.assertEqual(write_pcap(path, []), 0)
        loaded = read_pcap(path)
        self.assertEqual(loaded.records, [])
        self.assertFalse(loaded.truncated)

    def test_max_records_stops_without_reading_extra_record(self) -> None:
        path = os.path.join(self.tmp, "many.pcap")
        write_pcap(path, [make_packet(bytes([i])) for i in range(5)])

        loaded = read_pcap(path, max_records=2)
        self.assertEqual(len(loaded.records), 2)
        self.assertTrue(loaded.truncated)

        exact = read_pcap(path, max_records=5)
        self.assertEqual(len(exact.records), 5)
        self.assertFalse(exact.truncated)

        none = read_pcap(path, max_records=0)
        self.assertEqual(none.records, [])
        self.assertTrue(none.truncated)

        negative = read_pcap(path, max_records=-1)
        self.assertEqual(negative.records, [])
        self.assertTrue(negative.truncated)

    def test_mixed_linktypes_are_rejected(self) -> None:
        path = os.path.join(self.tmp, "mixed.pcap")
        with self.assertRaises(PcapWriteError):
            write_pcap(path, [make_packet(linktype=1),
                              make_packet(linktype=113)])
        self.assertFalse(os.path.exists(path))

    def test_explicit_mismatched_linktype_is_rejected(self) -> None:
        path = os.path.join(self.tmp, "wrong-linktype.pcap")
        with self.assertRaises(PcapWriteError):
            write_pcap(path, [make_packet(linktype=1)], linktype=113)

    def test_snaplen_smaller_than_packet_is_rejected(self) -> None:
        path = os.path.join(self.tmp, "small-snaplen.pcap")
        with self.assertRaises(PcapWriteError):
            write_pcap(path, [make_packet(b"x" * 20)], snaplen=10)
        self.assertFalse(os.path.exists(path))

    def test_negative_timestamp_is_rejected(self) -> None:
        path = os.path.join(self.tmp, "negative-ts.pcap")
        with self.assertRaises(PcapWriteError):
            write_pcap(path, [make_packet(ts=-1.0)])
        self.assertFalse(os.path.exists(path))


class PcapParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_raw(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as stream:
            stream.write(data)
        return path

    @staticmethod
    def _global_header(endian: str, magic: int, snaplen: int = 65535,
                       linktype: int = 1) -> bytes:
        return struct.pack(
            endian + "IHHIIII", magic, 2, 4, 0, 0, snaplen, linktype
        )

    def test_big_endian_file(self) -> None:
        record = struct.pack(">IIII", 100, 500_000, 4, 4) + b"abcd"
        path = self._write_raw(
            "big.pcap",
            self._global_header(">", PCAP_MAGIC_USEC) + record,
        )
        loaded = read_pcap(path)
        self.assertAlmostEqual(loaded.records[0].ts, 100.5, places=6)
        self.assertEqual(loaded.records[0].raw, b"abcd")

    def test_nanosecond_timestamps(self) -> None:
        record = struct.pack("<IIII", 100, 123_456_789, 2, 2) + b"xy"
        path = self._write_raw(
            "nano.pcap",
            self._global_header("<", PCAP_MAGIC_NSEC) + record,
        )
        loaded = read_pcap(path)
        self.assertAlmostEqual(
            loaded.records[0].ts, 100.123456789, places=9
        )

    def test_bad_magic(self) -> None:
        path = self._write_raw("bad.pcap", b"\x00" * 64)
        with self.assertRaises(PcapFormatError):
            read_pcap(path)

    def test_truncated_global_header(self) -> None:
        path = self._write_raw("short.pcap", b"\xd4\xc3\xb2\xa1")
        with self.assertRaises(PcapFormatError):
            read_pcap(path)

    def test_truncated_record_data(self) -> None:
        header = self._global_header("<", PCAP_MAGIC_USEC)
        record = struct.pack("<IIII", 1, 0, 10, 10) + b"123"
        path = self._write_raw("cut.pcap", header + record)
        with self.assertRaises(PcapFormatError):
            read_pcap(path)

    def test_record_larger_than_snaplen(self) -> None:
        header = self._global_header("<", PCAP_MAGIC_USEC, snaplen=8)
        record = struct.pack("<IIII", 1, 0, 9, 9) + b"123456789"
        path = self._write_raw("snaplen.pcap", header + record)
        with self.assertRaises(PcapFormatError):
            read_pcap(path)

    def test_bad_timestamp_fraction(self) -> None:
        header = self._global_header("<", PCAP_MAGIC_USEC)
        record = struct.pack("<IIII", 1, 1_000_000, 1, 1) + b"x"
        path = self._write_raw("frac.pcap", header + record)
        with self.assertRaises(PcapFormatError):
            read_pcap(path)

    def test_missing_file(self) -> None:
        with self.assertRaises(PcapFormatError):
            read_pcap(os.path.join(self.tmp, "no-such-file.pcap"))


if __name__ == "__main__":
    unittest.main()
