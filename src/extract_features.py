import argparse
from pathlib import Path
from collections import defaultdict
import dpkt
import socket
import pandas as pd
from tqdm import tqdm

def inet_to_str(inet: bytes) -> str:
    # IPv4 = 4 byte, IPv6 = 16 byte
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
        "total_pkts": 0,
        "total_bytes": 0,
        "tcp_pkts": 0,
        "udp_pkts": 0,
        "icmp_pkts": 0,
        "tcp_syn": 0,
        "tcp_rst": 0,
        "uniq_src_ips": set(),
        "uniq_dst_ips": set(),
        "uniq_dst_ports": set(),
        "uniq_src_ports": set(),
        "pkt_sizes_sum": 0,
    })

    host = defaultdict(lambda: {
        "pkts": 0,
        "bytes": 0,
        "tcp_pkts": 0,
        "udp_pkts": 0,
        "tcp_syn": 0,
        "tcp_rst": 0,
        "uniq_dst_ips": set(),
        "uniq_dst_ports": set(),
        "pkt_sizes_sum": 0,
    })

    f, reader, kind = open_pcap(pcap_path)
    try:
        for ts, buf in tqdm(reader, desc=f"Reading {pcap_path.name} ({kind})"):
            w = int(ts // window_sec) * window_sec

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.UnpackError, Exception):
                continue

            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)

            proto = getattr(ip, "p", None) or getattr(ip, "nxt", None)
            src_port = None
            dst_port = None

            win[w]["total_pkts"] += 1
            win[w]["total_bytes"] += len(buf)
            win[w]["pkt_sizes_sum"] += len(buf)
            win[w]["uniq_src_ips"].add(src_ip)
            win[w]["uniq_dst_ips"].add(dst_ip)

            if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_port, dst_port = tcp.sport, tcp.dport
                win[w]["tcp_pkts"] += 1
                win[w]["uniq_src_ports"].add(src_port)
                win[w]["uniq_dst_ports"].add(dst_port)

                if tcp.flags & dpkt.tcp.TH_SYN:
                    win[w]["tcp_syn"] += 1
                if tcp.flags & dpkt.tcp.TH_RST:
                    win[w]["tcp_rst"] += 1

            elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                src_port, dst_port = udp.sport, udp.dport
                win[w]["udp_pkts"] += 1
                win[w]["uniq_src_ports"].add(src_port)
                win[w]["uniq_dst_ports"].add(dst_port)

            elif proto in (dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_ICMP6):
                win[w]["icmp_pkts"] += 1

            key = (w, src_ip)
            host[key]["pkts"] += 1
            host[key]["bytes"] += len(buf)
            host[key]["pkt_sizes_sum"] += len(buf)
            host[key]["uniq_dst_ips"].add(dst_ip)

            if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                host[key]["tcp_pkts"] += 1
                if dst_port is not None:
                    host[key]["uniq_dst_ports"].add(dst_port)
                if ip.data.flags & dpkt.tcp.TH_SYN:
                    host[key]["tcp_syn"] += 1
                if ip.data.flags & dpkt.tcp.TH_RST:
                    host[key]["tcp_rst"] += 1

            elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                host[key]["udp_pkts"] += 1
                if dst_port is not None:
                    host[key]["uniq_dst_ports"].add(dst_port)

    finally:
        f.close()

    win_rows = []
    for w, d in win.items():
        total = d["total_pkts"] or 1
        win_rows.append({
            "window_start": w,
            "total_pkts": d["total_pkts"],
            "total_bytes": d["total_bytes"],
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

    df_win = pd.DataFrame(win_rows).sort_values("window_start")
    df_win.to_csv(out_dir / "window_features.csv", index=False)

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

    df_host = pd.DataFrame(host_rows).sort_values(["window_start", "src_ip"])
    df_host.to_csv(out_dir / "host_window_features.csv", index=False)

    print("OK ✅ Features written:")
    print("-", out_dir / "window_features.csv")
    print("-", out_dir / "host_window_features.csv")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Path to .pcap or .pcapng")
    ap.add_argument("--out", default="reports/outputs", help="Output folder")
    ap.add_argument("--window", type=int, default=60, help="Window size in seconds")
    args = ap.parse_args()

    extract(Path(args.pcap), Path(args.out), window_sec=args.window)

if __name__ == "__main__":
    main()


