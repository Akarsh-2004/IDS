from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FlowState:
    src_ip: str
    dst_ip: str
    protocol: str
    service: str
    started_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    syn_errors: int = 0
    reject_errors: int = 0
    same_service_hits: int = 0
    guest_login_hits: int = 0


class FlowWindowBuilder:
    def __init__(self, window_sec: int = 5) -> None:
        self.window_sec = window_sec
        self.flows: dict[str, FlowState] = {}
        self.recent_by_dst: dict[str, deque[tuple[float, str]]] = {}

    @staticmethod
    def flow_key(pkt: dict[str, Any]) -> str:
        return f"{pkt['src_ip']}:{pkt['src_port']}->{pkt['dst_ip']}:{pkt['dst_port']}/{pkt['protocol']}"

    def update(self, pkt: dict[str, Any]) -> dict[str, Any]:
        key = self.flow_key(pkt)
        now = pkt.get("ts", time.time())
        state = self.flows.get(key)
        if not state:
            state = FlowState(
                src_ip=pkt["src_ip"],
                dst_ip=pkt["dst_ip"],
                protocol=pkt["protocol"],
                service=pkt["service"],
            )
            self.flows[key] = state
        state.packet_count += 1
        state.last_seen = now
        state.src_bytes += int(pkt.get("size", 0))
        if pkt.get("direction") == "dst_to_src":
            state.dst_bytes += int(pkt.get("size", 0))
        if pkt.get("tcp_flag") == "S0":
            state.syn_errors += 1
        if pkt.get("tcp_flag") == "REJ":
            state.reject_errors += 1
        if pkt.get("is_guest_login"):
            state.guest_login_hits += 1

        dst_deque = self.recent_by_dst.setdefault(state.dst_ip, deque())
        dst_deque.append((now, state.service))
        cutoff = now - self.window_sec
        while dst_deque and dst_deque[0][0] < cutoff:
            dst_deque.popleft()
        same_service = sum(1 for _, svc in dst_deque if svc == state.service)
        state.same_service_hits = same_service

        duration = max(state.last_seen - state.started_at, 1e-6)
        return {
            "flow_key": key,
            "duration": duration,
            "protocol_type": state.protocol,
            "service": state.service,
            "flag": pkt.get("tcp_flag", "SF"),
            "src_bytes": state.src_bytes,
            "dst_bytes": state.dst_bytes,
            "count": len(dst_deque),
            "srv_count": state.same_service_hits,
            "serror_rate": state.syn_errors / max(state.packet_count, 1),
            "rerror_rate": state.reject_errors / max(state.packet_count, 1),
            "same_srv_rate": state.same_service_hits / max(len(dst_deque), 1),
            "src_ip": state.src_ip,
            "dst_ip": state.dst_ip,
        }
