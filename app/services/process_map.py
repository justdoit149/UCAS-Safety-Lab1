"""Map local TCP endpoints to processes with psutil."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterable

import psutil

from app.core.flowkey import normalize_ip_text


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str

    @property
    def display(self) -> str:
        return f"{self.name}({self.pid})" if self.pid else self.name


class ProcessMap:
    """Snapshot of ``(local IP, local port) -> process``.

    ``net_connections`` can be slow and is not available for every process
    without elevation, so failures keep the previous snapshot instead of
    clearing the table.  The optional resolver makes the mapping unit-testable
    without spawning real sockets.
    """

    def __init__(
        self,
        name_resolver: Callable[[int], str | None] | None = None,
    ) -> None:
        self._name_resolver = name_resolver or self._psutil_name
        self._names: dict[int, str] = {}
        self._snapshot: dict[tuple[str, int], ProcessInfo] = {}
        self.last_refresh_ts = 0.0
        self.last_error = ""

    def _psutil_name(self, pid: int) -> str | None:
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception:
            return None

    def _name_for(self, pid: int) -> str | None:
        if pid in self._names:
            return self._names[pid]
        try:
            name = self._name_resolver(pid)
        except Exception:
            return None
        if name:
            self._names[pid] = name
            return name
        return None

    def refresh(self) -> int:
        """Take a new snapshot; returns the number of mapped TCP endpoints."""
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, psutil.Error) as exc:
            self.last_error = f"无法读取系统 TCP 连接: {exc}"
            return len(self._snapshot)
        except Exception as exc:  # pragma: no cover - defensive
            self.last_error = f"读取 TCP 连接失败: {exc!r}"
            return len(self._snapshot)

        self.last_error = ""
        count = self.update(connections)
        self.last_refresh_ts = time.time()
        return count

    def update(self, connections: Iterable[object]) -> int:
        """Build a snapshot from psutil-like connection objects."""
        snapshot: dict[tuple[str, int], ProcessInfo] = {}
        priorities: dict[tuple[str, int], int] = {}
        for connection in connections:
            try:
                laddr = connection.laddr
                pid = connection.pid
                status = str(getattr(connection, "status", "") or "")
            except Exception:
                continue
            if not laddr or not pid:
                continue
            try:
                ip, port = laddr[0], int(laddr[1])
            except (IndexError, TypeError, ValueError):
                continue
            key = (normalize_ip_text(str(ip)), port)
            name = self._name_for(int(pid))
            if name is None:
                continue
            priority = 2 if status == psutil.CONN_ESTABLISHED else 1
            if key in snapshot and priorities.get(key, 0) >= priority:
                continue
            snapshot[key] = ProcessInfo(pid=int(pid), name=name)
            priorities[key] = priority
        self._snapshot = snapshot
        return len(snapshot)

    def set_snapshot(
        self,
        mapping: dict[tuple[str, int], ProcessInfo],
    ) -> None:
        """Replace the snapshot directly (tests and scripted demos)."""
        self._snapshot = dict(mapping)
        self.last_refresh_ts = time.time()
        self.last_error = ""

    def lookup(self, ip: str, port: int) -> ProcessInfo | None:
        return self._snapshot.get((normalize_ip_text(ip), int(port)))

    @property
    def snapshot(self) -> dict[tuple[str, int], ProcessInfo]:
        return dict(self._snapshot)

    @property
    def endpoint_count(self) -> int:
        return len(self._snapshot)
