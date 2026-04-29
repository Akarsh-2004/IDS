from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

try:
    from scapy.all import IP, TCP, UDP, rdpcap, sniff  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = None
    rdpcap = sniff = None


def _map_service(dst_port: int) -> str:
    port_map = {20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 443: "https"}
    return port_map.get(dst_port, "other")


def _flag_from_tcp(tcp_flags: str) -> str:
    if "R" in tcp_flags:
        return "REJ"
    if "S" in tcp_flags and "A" not in tcp_flags:
        return "S0"
    return "SF"


def packet_to_dict(packet: Any) -> dict[str, Any] | None:
    if IP is None or not packet.haslayer(IP):
        return None
    ip = packet[IP]
    proto = "tcp"
    src_port = 0
    dst_port = 0
    tcp_flag = "SF"
    if TCP and packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flag = _flag_from_tcp(str(tcp.flags))
        proto = "tcp"
    elif UDP and packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        proto = "udp"
    else:
        proto = str(getattr(ip, "proto", "ip"))
    return {
        "ts": float(getattr(packet, "time", time.time())),
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "service": _map_service(dst_port),
        "size": int(len(packet)),
        "tcp_flag": tcp_flag,
        "direction": "src_to_dst",
    }


def capture_live(interface: str, stop_check: Callable[[], bool], emit_packet: Callable[[dict[str, Any]], None]) -> None:
    if sniff is None:
        raise RuntimeError("Live capture unavailable. Install scapy/Npcap and rerun.")

    def on_packet(packet: Any) -> None:
        if stop_check():
            return
        mapped = packet_to_dict(packet)
        if mapped:
            emit_packet(mapped)

    sniff(
        iface=interface,
        prn=on_packet,
        store=False,
        stop_filter=lambda _: stop_check(),
    )


def capture_pcap_tail(pcap_path: Path, stop_check: Callable[[], bool], emit_packet: Callable[[dict[str, Any]], None]) -> None:
    if rdpcap is None:
        raise RuntimeError("PCAP capture unavailable. Install scapy and rerun.")
    seen_packets = 0
    while not stop_check():
        if not pcap_path.exists():
            time.sleep(1.0)
            continue
        packets = rdpcap(str(pcap_path))
        new_packets = packets[seen_packets:]
        for packet in new_packets:
            if stop_check():
                return
            mapped = packet_to_dict(packet)
            if mapped:
                emit_packet(mapped)
        seen_packets = len(packets)
        time.sleep(1.0)
