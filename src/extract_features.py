import argparse
from pathlib import Path
from collections import defaultdict, Counter
import dpkt
import socket
import pandas as pd
from tqdm import tqdm

def inet_to_str(inet: bytes) -> str:
    if not inet:
        return "unknown"
    try:
        if len(inet) == 4:
            return socket.inet_ntop(socket.AF_INET, inet)
        if len(inet) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet)
    except (OSError, ValueError):
        pass
    return "unknown"

def find_ipv4(buf: bytes, max_scan: int = 256):
    """
    Buffer içinde IPv4 header başlangıcını doğrulayarak bulur.
    version=4, IHL, total_len mantıklı olmalı.
    """
    limit = min(len(buf) - 20, max_scan)
    for off in range(0, max(0, limit + 1)):
        b0 = buf[off]
        if (b0 >> 4) != 4:
            continue
        ihl = (b0 & 0x0F) * 4
        if ihl < 20 or ihl > 60:
            continue
        if off + ihl > len(buf):
            continue
        tot = int.from_bytes(buf[off+2:off+4], "big")
        if tot < ihl or tot > (len(buf) - off):
            continue
        try:
            return dpkt.ip.IP(buf[off:off+tot])
        except Exception:
            continue
    return None

def tcp_from_payload(payload: bytes):
    """
    dpkt TCP parse edemezse ham TCP header'dan sport/dport/flags okur.
    TCP header min 20B.
    """
    if payload is None:
        return None
    if isinstance(payload, (bytearray, bytes)) and len(payload) >= 20:
        sport = int.from_bytes(payload[0:2], "big")
        dport = int.from_bytes(payload[2:4], "big")
        flags = payload[13]
        return sport, dport, flags
    return None

def open_pcap(path: Path):
    f = open(path, "rb")
    try:
        reader = dpkt.pcapng.Reader(f)
        return f, reader, "pcapng"
    except (ValueError, dpkt.dpkt.UnpackError):
        f.seek(0)
        reader = dpkt.pcap.Reader(f)
        return f, reader, "pcap"

def extract(pcap_path: Path, out_dir: Path, window_sec: int = 60):
    out_dir.mkdir(parents=True, exist_ok=True)

    win = defaultdict(lambda: {
        "total_pkts": 0, "total_bytes": 0,
        "ip_pkts": 0, "non_ip_pkts": 0,
        "tcp_pkts": 0, "udp_pkts": 0, "icmp_pkts": 0,
        "tcp_syn": 0, "tcp_rst": 0,
        "uniq_src_ips": set(), "uniq_dst_ips": set(),
        "uniq_dst_ports": set(), "uniq_src_ports": set(),
        "pkt_sizes_sum": 0,
    })

    host = defaultdict(lambda: {
        "pkts": 0, "bytes": 0,
        "tcp_pkts": 0, "udp_pkts": 0,
        "tcp_syn": 0, "tcp_rst": 0,
        "uniq_dst_ips": set(), "uniq_dst_ports": set(),
        "pkt_sizes_sum": 0,
    })

    ip_seen = 0
    tcp_seen = 0
    proto_counts = Counter()

    f, reader, kind = open_pcap(pcap_path)
    try:
        for ts, buf in tqdm(reader, desc=f"Reading {pcap_path.name} ({kind})"):
            w = int(ts // window_sec) * window_sec

            win[w]["total_pkts"] += 1
            win[w]["total_bytes"] += len(buf)
            win[w]["pkt_sizes_sum"] += len(buf)

            ip = None

            # 1) Ethernet parse dene
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
            except Exception:
                pass

            # 2) Değilse buffer içinde doğrulayarak IPv4 ara
            if ip is None:
                ip = find_ipv4(buf)

            if not isinstance(ip, dpkt.ip.IP):
                win[w]["non_ip_pkts"] += 1
                continue

            win[w]["ip_pkts"] += 1
            ip_seen += 1

            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            win[w]["uniq_src_ips"].add(src_ip)
            win[w]["uniq_dst_ips"].add(dst_ip)

            proto = ip.p
            proto_counts[proto] += 1

            # host-level her IP paketinde çalışsın
            key = (w, src_ip)
            host[key]["pkts"] += 1
            host[key]["bytes"] += len(buf)
            host[key]["pkt_sizes_sum"] += len(buf)
            host[key]["uniq_dst_ips"].add(dst_ip)

            # TCP
            if proto == 6:
                payload = bytes(ip.data) if not isinstance(ip.data, (bytes, bytearray)) else ip.data

                # dpkt ile dene
                sport = dport = flags = None
                try:
                    tcp = ip.data if isinstance(ip.data, dpkt.tcp.TCP) else dpkt.tcp.TCP(payload)
                    sport, dport, flags = tcp.sport, tcp.dport, tcp.flags
                except Exception:
                    # ham header fallback
                    parsed = tcp_from_payload(payload)
                    if parsed is not None:
                        sport, dport, flags = parsed

                if sport is not None and dport is not None and flags is not None:
                    win[w]["tcp_pkts"] += 1
                    tcp_seen += 1
                    win[w]["uniq_src_ports"].add(int(sport))
                    win[w]["uniq_dst_ports"].add(int(dport))

                    # SYN=0x02, RST=0x04
                    if (flags & 0x02) != 0:
                        win[w]["tcp_syn"] += 1
                    if (flags & 0x04) != 0:
                        win[w]["tcp_rst"] += 1

                    host[key]["tcp_pkts"] += 1
                    host[key]["uniq_dst_ports"].add(int(dport))
                    if (flags & 0x02) != 0:
                        host[key]["tcp_syn"] += 1
                    if (flags & 0x04) != 0:
                        host[key]["tcp_rst"] += 1

            # UDP
            elif proto == 17:
                try:
                    udp = ip.data if isinstance(ip.data, dpkt.udp.UDP) else dpkt.udp.UDP(bytes(ip.data))
                    win[w]["udp_pkts"] += 1
                    win[w]["uniq_src_ports"].add(int(udp.sport))
                    win[w]["uniq_dst_ports"].add(int(udp.dport))
                    host[key]["udp_pkts"] += 1
                    host[key]["uniq_dst_ports"].add(int(udp.dport))
                except Exception:
                    pass

            # ICMP
            elif proto == 1:
                win[w]["icmp_pkts"] += 1

    finally:
        f.close()

    # boş kalırsa çökmesin
    if not win:
        (out_dir / "window_features.csv").write_text("window_start,total_pkts,total_bytes\n", encoding="utf-8")
        (out_dir / "host_window_features.csv").write_text("", encoding="utf-8")
        print("No packets found in capture (empty).")
        return

    win_rows = []
    for w, d in win.items():
        total = d["total_pkts"] or 1
        win_rows.append({
            "window_start": w,
            "total_pkts": d["total_pkts"],
            "total_bytes": d["total_bytes"],
            "ip_pkts": d["ip_pkts"],
            "non_ip_pkts": d["non_ip_pkts"],
            "tcp_pkts": d["tcp_pkts"],
            "udp_pkts": d["udp_pkts"],
            "icmp_pkts": d["icmp_pkts"],
            "tcp_syn": d["tcp_syn"],
            "tcp_rst": d["tcp_rst"],
            "uniq_src_ips": len(d["uniq_src_ips"]),
            "uniq_dst_ips": len(d["uniq_dst_ips"]),
            "uniq_src_ports": len(d["uniq_src_ports"]),
            "uniq_dst_ports": len(d["uniq_dst_ports"]),
            "avg_pkt_size": d["pkt_sizes_sum"] / total,
            "syn_ratio": (d["tcp_syn"] / d["tcp_pkts"]) if d["tcp_pkts"] else 0.0,
            "rst_ratio": (d["tcp_rst"] / d["tcp_pkts"]) if d["tcp_pkts"] else 0.0,
        })

    pd.DataFrame(win_rows).sort_values("window_start").to_csv(out_dir / "window_features.csv", index=False)

    host_rows = []
    for (w, src_ip), d in host.items():
        total = d["pkts"] or 1
        tcp_pkts = d["tcp_pkts"] or 0
        host_rows.append({
            "window_start": w,
            "src_ip": src_ip,
            "pkts": d["pkts"],
            "bytes": d["bytes"],
            "tcp_pkts": d["tcp_pkts"],
            "udp_pkts": d["udp_pkts"],
            "tcp_syn": d["tcp_syn"],
            "tcp_rst": d["tcp_rst"],
            "uniq_dst_ips": len(d["uniq_dst_ips"]),
            "uniq_dst_ports": len(d["uniq_dst_ports"]),
            "avg_pkt_size": d["pkt_sizes_sum"] / total,
            "syn_ratio": (d["tcp_syn"] / tcp_pkts) if tcp_pkts else 0.0,
            "rst_ratio": (d["tcp_rst"] / tcp_pkts) if tcp_pkts else 0.0,
        })

    pd.DataFrame(host_rows).sort_values(["window_start","src_ip"]).to_csv(out_dir / "host_window_features.csv", index=False)

    print("OK  Features written:")
    print("-", out_dir / "window_features.csv")
    print("-", out_dir / "host_window_features.csv")
    print(f"Parsed summary: ip_pkts={ip_seen}, tcp_pkts={tcp_seen}, proto_counts={dict(proto_counts)}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", default="reports/outputs")
    ap.add_argument("--window", type=int, default=60)
    args = ap.parse_args()
    extract(Path(args.pcap), Path(args.out), window_sec=args.window)

if __name__ == "__main__":
    main()
