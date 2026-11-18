"""Bidirectional TCP/UDP flow aggregation."""

from __future__ import annotations

import time

from app.core.flowkey import endpoint_key, flow_key_for
from app.core.models import Flow, Packet


class FlowManager:
    """Build and track flows from dissected packets.

    The manager is intentionally not thread-safe: live capture dissects on the
    worker thread, but batches are handed to the UI thread before being added
    here.  That keeps the flow table, timeline and process map consistent.
    """

    UDP_EXPIRE_SECONDS = 120.0

    def __init__(self) -> None:
        self.flows: dict[tuple, Flow] = {}

    def clear(self) -> None:
        self.flows.clear()

    def add_packet(self, packet: Packet) -> Flow | None:
        key = flow_key_for(
            packet.transport,
            packet.ip_src,
            packet.sport,
            packet.ip_dst,
            packet.dport,
        )
        if key is None:
            return None
        packet.flow_key = key
        flow = self.flows.get(key)
        if flow is None:
            src_endpoint = endpoint_key(packet.ip_src, packet.sport)
            dst_endpoint = endpoint_key(packet.ip_dst, packet.dport)
            if src_endpoint is None or dst_endpoint is None:
                return None
            flow = Flow(
                key=key,
                protocol=packet.transport,
                src_ip=packet.ip_src,
                src_port=packet.sport,
                dst_ip=packet.ip_dst,
                dst_port=packet.dport,
                src_endpoint=src_endpoint,
                dst_endpoint=dst_endpoint,
                first_ts=packet.ts,
                last_ts=packet.ts,
            )
            self.flows[key] = flow
        elif flow.state == "EXPIRED":
            flow.state = "ACTIVE"
        flow.add_packet(packet)
        return flow

    def add_packets(self, packets: list[Packet]) -> None:
        for packet in packets:
            self.add_packet(packet)

    def apply_process_map(self, process_map) -> None:
        """Attach the latest known process to each flow endpoint.

        A missing lookup keeps the previous assignment: the connection that
        produced a flow may be gone by the time the packet capture is stopped,
        and erasing the label would lose the useful mapping.
        """
        for flow in self.flows.values():
            src = process_map.lookup(flow.src_ip, flow.src_port)
            dst = process_map.lookup(flow.dst_ip, flow.dst_port)
            if src is not None:
                flow.proc_src = src
            if dst is not None:
                flow.proc_dst = dst

    def expire_stale(self, reference_ts: float | None = None) -> None:
        if not self.flows:
            return
        if reference_ts is None:
            reference_ts = max(flow.last_ts for flow in self.flows.values())
        cutoff = reference_ts - self.UDP_EXPIRE_SECONDS
        for flow in self.flows.values():
            if (
                flow.protocol == "UDP"
                and flow.state != "EXPIRED"
                and flow.last_ts < cutoff
            ):
                flow.state = "EXPIRED"

    def flows_sorted(
        self,
        reference_ts: float | None = None,
    ) -> list[Flow]:
        self.expire_stale(reference_ts)
        return sorted(
            self.flows.values(),
            key=lambda flow: (flow.last_ts, flow.first_ts),
            reverse=True,
        )

    def flows_for_process(
        self,
        pid: int,
        *,
        tcp_only: bool = True,
    ) -> list[Flow]:
        matches = []
        for flow in self.flows_sorted():
            if tcp_only and flow.protocol != "TCP":
                continue
            if int(pid) in flow.process_pids:
                matches.append(flow)
        return matches

    @property
    def latest_ts(self) -> float:
        if not self.flows:
            return time.time()
        return max(flow.last_ts for flow in self.flows.values())
