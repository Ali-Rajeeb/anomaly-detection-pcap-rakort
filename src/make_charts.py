import argparse
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)

def plot_window_timeseries(df: pd.DataFrame, out: Path):
    df = df.copy()
    if "time_tr" in df.columns:
        t = pd.to_datetime(df["time_tr"], errors="coerce")
    else:
        t = pd.to_datetime(df["window_start"], unit="s", utc=True, errors="coerce").dt.tz_convert("Europe/Istanbul")

    df["t"] = t
    df = df.sort_values("t")

    # 1) total_bytes
    plt.figure()
    plt.plot(df["t"], df["total_bytes"])
    an = df[df["is_anomaly"] == True]
    if len(an) > 0:
        plt.scatter(an["t"], an["total_bytes"])
    plt.xticks(rotation=25, ha="right")
    plt.xlabel("Time (TR)")
    plt.ylabel("Total Bytes / window")
    plt.title("Window Traffic (bytes) + anomalies")
    plt.tight_layout()
    plt.savefig(out / "window_bytes_timeseries.png", dpi=160)
    plt.close()

    # 2) total_pkts
    plt.figure()
    plt.plot(df["t"], df["total_pkts"])
    an = df[df["is_anomaly"] == True]
    if len(an) > 0:
        plt.scatter(an["t"], an["total_pkts"])
    plt.xticks(rotation=25, ha="right")
    plt.xlabel("Time (TR)")
    plt.ylabel("Total Packets / window")
    plt.title("Window Traffic (pkts) + anomalies")
    plt.tight_layout()
    plt.savefig(out / "window_pkts_timeseries.png", dpi=160)
    plt.close()

    # 3) anomaly_score
    plt.figure()
    plt.plot(df["t"], df["anomaly_score"])
    an = df[df["is_anomaly"] == True]
    if len(an) > 0:
        plt.scatter(an["t"], an["anomaly_score"])
    plt.xticks(rotation=25, ha="right")
    plt.xlabel("Time (TR)")
    plt.ylabel("Anomaly Score (higher = more anomalous)")
    plt.title("Window Anomaly Score + anomalies")
    plt.tight_layout()
    plt.savefig(out / "window_anomaly_score.png", dpi=160)
    plt.close()

def plot_top_hosts(df: pd.DataFrame, out: Path, topn: int = 10):
    df = df.copy()

    # En çok anomali sayısı üreten hostlar
    g = df[df["is_anomaly"] == True].groupby("src_ip").size().sort_values(ascending=False).head(topn)
    if len(g) == 0:
        return

    plt.figure()
    plt.bar(g.index.astype(str), g.values)
    plt.xticks(rotation=35, ha="right")
    plt.xlabel("Source IP")
    plt.ylabel("Anomaly Count")
    plt.title(f"Top {topn} Source IPs by anomaly count")
    plt.tight_layout()
    plt.savefig(out / "top_hosts_by_anomalies.png", dpi=160)
    plt.close()

def plot_portscan_heatmap(df: pd.DataFrame, out: Path, top_hosts: int = 6):
    # Portscan flagged satırları varsa sadece onlardan heatmap
    p = df[df.get("rule_portscan", False) == True].copy()
    if len(p) == 0:
        return

    # En çok portscan üreten hostları seç
    top = p.groupby("src_ip").size().sort_values(ascending=False).head(top_hosts).index.tolist()
    p = p[p["src_ip"].isin(top)]

    # Her host için uniq_dst_ports dağılımı (window bazında)
    pivot = p.pivot_table(index="src_ip", values="uniq_dst_ports", aggfunc="max").sort_values("uniq_dst_ports", ascending=False)

    plt.figure()
    plt.imshow(pivot.values, aspect="auto")
    plt.yticks(range(len(pivot.index)), pivot.index)
    plt.xticks([0], ["max uniq dst ports"])
    plt.xlabel("Metric")
    plt.title("Port-scan candidates (max uniq dst ports per src_ip)")
    plt.tight_layout()
    plt.savefig(out / "portscan_candidates.png", dpi=160)
    plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--detections", default="reports/outputs/detections", help="Folder with anomaly CSVs")
    ap.add_argument("--figdir", default="reports/figures", help="Output figures folder")
    args = ap.parse_args()

    det = Path(args.detections)
    fig = Path(args.figdir)
    ensure_dir(fig)

    win_path = det / "window_anomalies.csv"
    host_path = det / "host_anomalies.csv"

    if win_path.exists():
        win = read_csv(win_path)
        plot_window_timeseries(win, fig)

    if host_path.exists():
        host = read_csv(host_path)
        plot_top_hosts(host, fig)
        plot_portscan_heatmap(host, fig)

    print("OK ✅ Charts generated in", fig)

if __name__ == "__main__":
    main()
