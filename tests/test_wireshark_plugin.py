"""Integration tests for the optional Wireshark Lua dissector.

The tests generate a temporary pcap, load wireshark/lab1a.lua with tshark and
check the protocol tree, display filters, expert info and the flow-statistics
companion script.  They are skipped when Wireshark's tshark is not installed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.make_lab1a_pcap import build_demo_capture  # noqa: E402

PLUGIN = ROOT / "wireshark" / "lab1a.lua"
STATS = ROOT / "wireshark" / "lab1a_stats.lua"


def find_tshark() -> str | None:
    candidate = shutil.which("tshark")
    if candidate:
        return candidate
    common = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if common.exists():
        return str(common)
    return None


class TestWiresharkPlugin(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tshark = find_tshark()
        if cls.tshark is None:
            raise unittest.SkipTest("tshark not found")
        if not PLUGIN.exists():
            raise unittest.SkipTest("wireshark/lab1a.lua not found")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pcap = build_demo_capture(Path(cls._tmp.name) / "lab1a.pcap")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def run_tshark(self, *args: str) -> subprocess.CompletedProcess:
        command = [
            self.tshark,
            "-X",
            f"lua_script:{PLUGIN.relative_to(ROOT).as_posix()}",
        ]
        command.extend(args)
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    def test_protocol_tree_and_fields(self) -> None:
        result = self.run_tshark(
            "-r", str(self.pcap), "-Y", "frame.number == 4", "-V"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout
        self.assertIn("LAB1A 实验协议", output)
        self.assertIn("魔数: L1A1", output)
        self.assertIn("消息类型: 请求 (1)", output)
        self.assertIn("序号: 1", output)
        self.assertIn("载荷长度: 10", output)

    def test_display_filter_msg_type(self) -> None:
        result = self.run_tshark(
            "-r",
            str(self.pcap),
            "-Y",
            "lab1a.msg_type == 1",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "lab1a.msg_type",
            "-e",
            "lab1a.seq",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in result.stdout.splitlines() if line]
        self.assertEqual(
            rows,
            [
                ["4", "1", "1"],
                ["14", "1", "7"],
                ["19", "1", "4"],
                ["23", "1", "12"],
            ],
        )

    def test_expert_info_filters(self) -> None:
        result = self.run_tshark(
            "-r",
            str(self.pcap),
            "-Y",
            (
                "lab1a.bad_magic || lab1a.unknown_type || "
                "lab1a.length_mismatch || lab1a.short_header"
            ),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "_ws.expert.message",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout
        self.assertIn("魔数不是 L1A1", output)
        self.assertIn("消息类型未知", output)
        self.assertIn("载荷长度与头部声明不符", output)
        self.assertIn("头部不足 10 字节", output)

    def test_flow_statistics_script(self) -> None:
        command = [
            self.tshark,
            "-X",
            f"lua_script:{PLUGIN.relative_to(ROOT).as_posix()}",
            "-X",
            f"lua_script:{STATS.relative_to(ROOT).as_posix()}",
            "-r",
            str(self.pcap),
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("GUI not available", result.stderr)
        self.assertNotIn("Lua: Error", result.stderr)
        self.assertIn("TCP流", result.stdout)
        self.assertIn("合计: 5 包, 351 字节, 2 条 TCP 流", result.stdout)
        self.assertIn("0               3        208", result.stdout)
        self.assertIn("1               2        143", result.stdout)


if __name__ == "__main__":
    unittest.main()
