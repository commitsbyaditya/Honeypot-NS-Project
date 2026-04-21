import argparse
import json
import os
import sys
from typing import Dict, List

import pandas as pd


SEVERITY_MAP = {
    "ssh_normal": "low",
    "ssh_brute_force": "high",
    "ssh_reconnaissance": "medium",
    "portscan_stealth": "medium",
    "portscan_aggressive": "high",
    "portscan_sweep": "low",
    "dns_normal": "low",
    "dns_tunneling": "critical",
    "dns_amplification": "high",
    "arp_spoofing": "high",
    "arp_poisoning": "critical",
    "icmp_flood": "high",
    "icmp_ping_of_death": "critical",
}

DEFAULT_TYPE_SEVERITY = {
    "ssh": "medium",
    "portscan": "medium",
    "dns": "high",
    "arp": "high",
    "icmp": "high",
}

TYPE_LABEL = {
    "ssh": "SSH",
    "portscan": "Port Scan",
    "dns": "DNS",
    "arp": "ARP",
    "icmp": "ICMP",
}


def _safe_float(value, default=0.0):
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _load_df(repo_root: str) -> pd.DataFrame:
    data_path = os.path.join(repo_root, "data", "attack_logs.csv")
    if not os.path.exists(data_path):
        return pd.DataFrame()

    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    try:
        from ml.data_loader import load_mixed_csv

        df = load_mixed_csv(data_path, verbose=False)
    except Exception:
        df = pd.read_csv(data_path)

    if df.empty:
        return df

    if "ip_address" not in df.columns and "src_ip" in df.columns:
        df["ip_address"] = df["src_ip"]

    if "attack_type" not in df.columns:
        df["attack_type"] = "ssh"

    if "session_duration" not in df.columns:
        df["session_duration"] = 0.0

    if "packet_count" not in df.columns:
        df["packet_count"] = 0

    if "timestamp" not in df.columns:
        df["timestamp"] = ""

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["session_duration"] = pd.to_numeric(df["session_duration"], errors="coerce").fillna(0)
    df["packet_count"] = pd.to_numeric(df["packet_count"], errors="coerce").fillna(0)

    if "predicted_label" not in df.columns:
        df["predicted_label"] = ""

    if "severity" not in df.columns:
        df["severity"] = ""

    return df


def _derive_severity(row: pd.Series) -> str:
    sev = str(row.get("severity", "")).strip().lower()
    if sev:
        return sev

    label = str(row.get("predicted_label", "")).strip()
    if label in SEVERITY_MAP:
        return SEVERITY_MAP[label]

    attack_type = str(row.get("attack_type", "")).strip().lower()
    return DEFAULT_TYPE_SEVERITY.get(attack_type, "medium")


def _display_attack_name(attack_type: str) -> str:
    return TYPE_LABEL.get(str(attack_type).strip().lower(), str(attack_type).strip() or "Unknown")


def sessions_command(args: argparse.Namespace) -> Dict:
    df = _load_df(args.repo_root)
    if df.empty:
        return {"sessions": [], "total": 0}

    work = df.copy()

    if args.attack_type and args.attack_type.lower() != "all":
        work = work[work["attack_type"].astype(str).str.lower() == args.attack_type.lower()]

    if args.search:
        search = args.search.lower()
        id_col = work.index.astype(str)
        ip_col = work["ip_address"].astype(str).str.lower()
        attack_col = work["attack_type"].astype(str).str.lower()
        pred_col = work.get("predicted_label", pd.Series([""] * len(work))).astype(str).str.lower()
        mask = (
            id_col.str.contains(search, regex=False)
            | ip_col.str.contains(search, regex=False)
            | attack_col.str.contains(search, regex=False)
            | pred_col.str.contains(search, regex=False)
        )
        work = work[mask]

    sort_key = args.sort_key if args.sort_key in work.columns else "timestamp"
    ascending = args.sort_order.lower() == "asc"

    if sort_key == "timestamp":
        work = work.sort_values(sort_key, ascending=ascending, na_position="last")
    else:
        work = work.sort_values(sort_key, ascending=ascending)

    limited = work.head(args.limit)

    sessions: List[Dict] = []
    for idx, row in limited.iterrows():
        timestamp = row.get("timestamp")
        if pd.isna(timestamp):
            timestamp_out = ""
        else:
            timestamp_out = pd.Timestamp(timestamp).isoformat()

        attack_type_raw = str(row.get("attack_type", "")).strip().lower()
        sessions.append(
            {
                "id": f"SES-{idx + 1:06d}",
                "timestamp": timestamp_out,
                "srcIp": str(row.get("ip_address", "")),
                "attackType": _display_attack_name(attack_type_raw),
                "attackTypeRaw": attack_type_raw,
                "duration": round(_safe_float(row.get("session_duration", 0.0)), 2),
                "packetsCount": int(_safe_float(row.get("packet_count", 0))),
                "severity": _derive_severity(row),
                "detected": attack_type_raw != "",
                "predictedLabel": str(row.get("predicted_label", "")),
            }
        )

    return {"sessions": sessions, "total": int(len(work))}


def stats_command(args: argparse.Namespace) -> Dict:
    df = _load_df(args.repo_root)
    if df.empty:
        return {
            "totalAttacks": 0,
            "detectionRate": 0,
            "avgResponseTime": 0,
            "activeThreats": 0,
            "attackDistribution": [],
            "topAttackerIPs": [],
            "recentSessions": [],
        }

    work = df.copy()
    work["severity_resolved"] = work.apply(_derive_severity, axis=1)

    total = len(work)
    detected = len(work[work["attack_type"].astype(str).str.strip() != ""])
    detection_rate = round((detected / total) * 100, 2) if total else 0.0

    avg_response = round(float(work["session_duration"].mean()), 2) if total else 0.0

    one_hour_ago = pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(hours=1)
    active = work[
        (work["timestamp"].notna())
        & (work["timestamp"] >= one_hour_ago)
        & (work["severity_resolved"].isin(["high", "critical"]))
    ]
    active_threats = int(active["ip_address"].nunique())

    distribution = (
        work["attack_type"]
        .astype(str)
        .str.lower()
        .replace("", "unknown")
        .value_counts()
        .to_dict()
    )

    attack_distribution = [
        {"name": _display_attack_name(k), "value": int(v)} for k, v in distribution.items()
    ]

    top_ips = work["ip_address"].astype(str).value_counts().head(5)
    top_attacker_ips = [{"ip": ip, "count": int(count)} for ip, count in top_ips.items()]

    recent = work.sort_values("timestamp", ascending=False).head(10)
    recent_sessions = []
    for idx, row in recent.iterrows():
        timestamp = row.get("timestamp")
        timestamp_out = "" if pd.isna(timestamp) else pd.Timestamp(timestamp).isoformat()
        attack_type_raw = str(row.get("attack_type", "")).strip().lower()
        recent_sessions.append(
            {
                "id": f"SES-{idx + 1:06d}",
                "timestamp": timestamp_out,
                "srcIp": str(row.get("ip_address", "")),
                "attackType": _display_attack_name(attack_type_raw),
                "severity": _derive_severity(row),
                "duration": round(_safe_float(row.get("session_duration", 0.0)), 2),
            }
        )

    return {
        "totalAttacks": int(total),
        "detectionRate": detection_rate,
        "avgResponseTime": avg_response,
        "activeThreats": active_threats,
        "attackDistribution": attack_distribution,
        "topAttackerIPs": top_attacker_ips,
        "recentSessions": recent_sessions,
    }


def health_command(args: argparse.Namespace) -> Dict:
    data_path = os.path.join(args.repo_root, "data", "attack_logs.csv")
    model_path = os.path.join(args.repo_root, "models", "attack_model.pkl")
    return {
        "repoRoot": args.repo_root,
        "dataFile": data_path,
        "dataExists": os.path.exists(data_path),
        "modelFile": model_path,
        "modelExists": os.path.exists(model_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["sessions", "stats", "health"])
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--search", default="")
    parser.add_argument("--attack-type", default="all")
    parser.add_argument("--sort-key", default="timestamp")
    parser.add_argument("--sort-order", default="desc")
    parser.add_argument("--limit", type=int, default=200)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "sessions":
        payload = sessions_command(args)
    elif args.command == "stats":
        payload = stats_command(args)
    else:
        payload = health_command(args)

    print(json.dumps(payload, default=str))


if __name__ == "__main__":
    main()
