from pathlib import Path
from threading import Event

import pytest

from realtime.capture import capture_pcap_tail

scapy = pytest.importorskip("scapy.all")


def test_realtime_replay_from_pcap(tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pkt = scapy.IP(src="10.1.1.1", dst="10.2.2.2") / scapy.TCP(sport=12345, dport=80, flags="S")
    scapy.wrpcap(str(pcap_path), [pkt, pkt])

    out = []
    stop = Event()

    def emit(packet: dict) -> None:
        out.append(packet)
        if len(out) >= 2:
            stop.set()

    capture_pcap_tail(pcap_path, stop_check=stop.is_set, emit_packet=emit)
    assert len(out) >= 2
    assert out[0]["service"] == "http"
