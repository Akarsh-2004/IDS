import random
from pathlib import Path

from scapy.all import IP, TCP, UDP, wrpcap


def main() -> None:
    src_pool = [f"10.0.0.{i}" for i in range(2, 80)]
    dst_pool = [f"192.168.1.{i}" for i in range(2, 80)]
    packets = []

    # Benign-ish browsing traffic.
    for _ in range(140):
        src = random.choice(src_pool)
        dst = random.choice(dst_pool)
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 53])
        packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA"))

    # SYN flood style burst to one target (high serror-like behavior).
    target = "192.168.1.200"
    for i in range(220):
        src = f"172.16.{i % 8}.{(i % 200) + 20}"
        sport = random.randint(1024, 65535)
        packets.append(IP(src=src, dst=target) / TCP(sport=sport, dport=80, flags="S"))

    # Port scan behavior against one host.
    scanner = "10.9.9.9"
    scan_target = "192.168.1.210"
    for port in range(20, 220):
        packets.append(IP(src=scanner, dst=scan_target) / TCP(sport=random.randint(20000, 65535), dport=port, flags="S"))

    # Rejected/Reset traffic burst.
    for _ in range(140):
        src = random.choice(src_pool)
        dst = random.choice(dst_pool)
        packets.append(IP(src=src, dst=dst) / TCP(sport=random.randint(2000, 65535), dport=23, flags="R"))

    # UDP noise.
    for _ in range(100):
        src = random.choice(src_pool)
        dst = random.choice(dst_pool)
        packets.append(IP(src=src, dst=dst) / UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 123, 161])))

    random.shuffle(packets)
    out_path = Path("demo_malicious_traffic.pcap")
    wrpcap(str(out_path), packets)
    print(out_path.resolve())
    print(f"packets={len(packets)}")


if __name__ == "__main__":
    main()
