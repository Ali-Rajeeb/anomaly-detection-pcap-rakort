import argparse
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

HOST_FEATURES = [
    "pkts", "bytes", "tcp_pkts", "udp_pkts",
    "tcp_syn", "tcp_rst", "uniq_dst_ips", "uniq_dst_ports",
    "avg_pkt_size", "syn_ratio", "rst_ratio"
]

WIN_FEATURES = [
    "total_pkts", "total_bytes", "tcp_pkts", "udp_pkts", "icmp_pkts",
    "tcp_syn", "tcp_rst", "uniq_src_ips", "uniq_dst_ips", "uniq_src_ports", "uniq_dst_ports",
    "avg_pkt_size", "syn_ratio", "rst_ratio"
]

def load_csv(folder: Path, name: str) -> pd.DataFrame:
    p = folder / name
    if not p.exists():
        raise FileNotFoundError(f"Missing file: {p}")
    return pd.read_csv(p)

def add_time_cols(df: pd.DataFrame) -> pd.DataFrame:
    # window_start: unix seconds (pktmon pcapng genelde epoch verir)
    # utc -> Istanbul yerel saat göstermek istersen:
    dt_utc = pd.to_datetime(df["window_start"], unit="s", utc=True, errors="coerce")
    df["time_utc"] = dt_utc
    try:
        df["time_tr"] = dt_utc.dt.tz_convert("Europe/Istanbul")
    except Exception:
        df["time_tr"] = dt_utc
    return df

def fit_and_score_isoforest(train_df: pd.DataFrame, test_df: pd.DataFrame, feat_cols: list[str],
                            fp_target: float, seed: int = 42):
    X_train = train_df[feat_cols].fillna(0.0).to_numpy()
    X_test  = test_df[feat_cols].fillna(0.0).to_numpy()

    model = IsolationForest(
        n_estimators=250,
        random_state=seed,
        n_jobs=-1
    )
    model.fit(X_train)

    # sklearn score_samples: daha büyük = daha normal
    train_norm_score = model.score_samples(X_train)
    test_norm_score  = model.score_samples(X_test)

    # anomaly_score: daha büyük = daha anormal
    train_anom = -train_norm_score
    test_anom  = -test_norm_score

    # FP kalibrasyonu: train üzerinde en üst fp_target kısmını "anomali" say
    thr = np.quantile(train_anom, 1.0 - fp_target)

    return test_anom, thr, model

def add_rules_host(train_host: pd.DataFrame, test_host: pd.DataFrame):
    # Port-scan için çok konservatif eşikler: eğitim verisinin 99.9 persentili
    q_ports = float(np.quantile(train_host["uniq_dst_ports"].fillna(0), 0.999))
    q_syn   = float(np.quantile(train_host["tcp_syn"].fillna(0), 0.999))

    port_thr = max(30.0, q_ports)   # min 30 port / pencere
    syn_thr  = max(20.0, q_syn)     # min 80 SYN / pencere

    test_host["rule_portscan"] = (
        (test_host["uniq_dst_ports"].fillna(0) >= port_thr) &
        (test_host["tcp_syn"].fillna(0) >= syn_thr) &
        (test_host["syn_ratio"].fillna(0) >= 0.60)
    )

    test_host["rule_portscan_reason"] = np.where(
        test_host["rule_portscan"],
        f"uniq_dst_ports>={port_thr:.0f} & tcp_syn>={syn_thr:.0f} & syn_ratio>=0.60",
        ""
    )
    return test_host, {"port_thr": port_thr, "syn_thr": syn_thr}

def add_rules_window(train_win: pd.DataFrame, test_win: pd.DataFrame):
    # Trafik spike: yine konservatif -> 99.9 persentil
    q_bytes = float(np.quantile(train_win["total_bytes"].fillna(0), 0.999))
    q_pkts  = float(np.quantile(train_win["total_pkts"].fillna(0), 0.999))

    bytes_thr = max(5_000_000.0, q_bytes)  # min 5MB/60s gibi düşün
    pkts_thr  = max(20_000.0, q_pkts)

    test_win["rule_traffic_spike"] = (
        (test_win["total_bytes"].fillna(0) >= bytes_thr) |
        (test_win["total_pkts"].fillna(0) >= pkts_thr)
    )

    test_win["rule_traffic_reason"] = np.where(
        test_win["rule_traffic_spike"],
        f"total_bytes>={bytes_thr:.0f} OR total_pkts>={pkts_thr:.0f}",
        ""
    )
    return test_win, {"bytes_thr": bytes_thr, "pkts_thr": pkts_thr}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True, help="Folder with train features (normal baseline)")
    ap.add_argument("--test", required=True, help="Folder with test features")
    ap.add_argument("--out", default="reports/outputs/detections", help="Output folder")
    ap.add_argument("--fp", type=float, default=0.05, help="Target false positive rate on TRAIN (0.05 = 5%)")
    args = ap.parse_args()

    train_dir = Path(args.train)
    test_dir  = Path(args.test)
    out_dir   = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- WINDOW LEVEL ----
    train_win = load_csv(train_dir, "window_features.csv")
    test_win  = load_csv(test_dir,  "window_features.csv")
    train_win = add_time_cols(train_win)
    test_win  = add_time_cols(test_win)

    win_scores, win_thr, _ = fit_and_score_isoforest(train_win, test_win, WIN_FEATURES, fp_target=args.fp)
    test_win["anomaly_score"] = win_scores
    test_win["model_anomaly"] = test_win["anomaly_score"] > win_thr

    test_win, win_rule_info = add_rules_window(train_win, test_win)

    # Final anomali: model + (çok konservatif) kural
    test_win["is_anomaly"] = test_win["model_anomaly"] | test_win["rule_traffic_spike"]

    test_win.to_csv(out_dir / "window_anomalies.csv", index=False)

    # ---- HOST LEVEL ----
    train_host = load_csv(train_dir, "host_window_features.csv")
    test_host  = load_csv(test_dir,  "host_window_features.csv")
    train_host = add_time_cols(train_host)
    test_host  = add_time_cols(test_host)

    host_scores, host_thr, _ = fit_and_score_isoforest(train_host, test_host, HOST_FEATURES, fp_target=args.fp)
    test_host["anomaly_score"] = host_scores
    test_host["model_anomaly"] = test_host["anomaly_score"] > host_thr

    test_host, host_rule_info = add_rules_host(train_host, test_host)

    test_host["is_anomaly"] = test_host["model_anomaly"] | test_host["rule_portscan"]
    test_host.to_csv(out_dir / "host_anomalies.csv", index=False)

    # ---- Summary ----
    summary = {
        "fp_target_train": args.fp,
        "thresholds": {
            "window_model_threshold": float(win_thr),
            "host_model_threshold": float(host_thr),
        },
        "rules": {
            "window": win_rule_info,
            "host": host_rule_info,
        },
        "counts_test": {
            "window_total": int(len(test_win)),
            "window_anomalies": int(test_win["is_anomaly"].sum()),
            "host_total": int(len(test_host)),
            "host_anomalies": int(test_host["is_anomaly"].sum()),
        }
    }

    (out_dir / "summary.json").write_text(pd.Series(summary).to_json(indent=2, force_ascii=False), encoding="utf-8")

    print("OK  Detection outputs written:")
    print("-", out_dir / "window_anomalies.csv")
    print("-", out_dir / "host_anomalies.csv")
    print("-", out_dir / "summary.json")
    print("")
    print("FP control : model thresholds are calibrated on TRAIN to ~", args.fp * 100, "%")

if __name__ == "__main__":
    main()



