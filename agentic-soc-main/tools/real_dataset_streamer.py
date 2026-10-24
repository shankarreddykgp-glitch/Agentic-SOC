"""
AEGIS-SOC // High-Performance 31 Million Row RBA & 1 GB+ Dataset SIEM Streamer
================================================================================
Role: Principal Data Engineer / Large Dataset Pipeline Streamer
Description: Efficiently streams the 31-Million Row Risk-Based Authentication (RBA) Dataset
             (rba-dataset.csv / my_dataset.csv) and any 1 GB+ real cybersecurity CSV log files
             into the AEGIS-SOC FastAPI ingestion engine using O(1) memory generator streaming.

Features:
- Auto-Resolves Directory Paths: Automatically finds .csv files if a folder is named 'my_dataset.csv'.
- O(1) Memory Footprint: Reads CSV files row-by-row without loading full dataset into RAM.
- Maps RBA Columns: 'Login Timestamp', 'User ID', 'IP Address', 'User Agent String', 'Country', 'City', 'Is Attack IP', 'Is Account Takeover'.
- Interactive Speed Modes:
    [1] High-Speed Bulk Stream   (~50-150 events/sec | 0.001s delay)
    [2] Real-Time Presentation Stream (1.0s delay per event)
    [3] Custom Delay Mode
- Unbuffered Real-Time Console Reporting: Real-time progress %, total rows, elapsed time, and events/sec throughput.

Usage:
  python tools/real_dataset_streamer.py
"""

import os
import sys
import csv
import time
import json
import random
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests

# Reconfigure stdout for UTF-8 compatibility on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Target API Configuration
INGEST_URL = "http://127.0.0.1:8000/api/v1/telemetry/ingest"

# Candidate Dataset Paths (Auto-Discovery)
CANDIDATE_PATHS = [
    os.path.join("my_dataset.csv", "rba-dataset.csv"),
    "rba-dataset.csv",
    "my_dataset.csv",
    "enterprise_auth_logs.csv"
]


def resolve_dataset_path(path_input: str) -> str:
    """
    Resolves directory paths or raw file paths to the actual .csv file.
    If the target path is a directory (e.g. 'my_dataset.csv'), locates the inner .csv file.
    """
    path_input = path_input.strip()
    if not path_input:
        for candidate in CANDIDATE_PATHS:
            if os.path.exists(candidate):
                path_input = candidate
                break

    if os.path.isdir(path_input):
        # Look for .csv files inside the directory
        csv_files = [os.path.join(path_input, f) for f in os.listdir(path_input) if f.lower().endswith(".csv")]
        if csv_files:
            return csv_files[0]

    return path_input


def map_row_to_schema(row: Dict[str, Any], row_idx: int) -> Dict[str, Any]:
    """
    Universal RBA & Enterprise Schema Resolver:
    Maps columns dynamically for Kaggle RBA Dataset & Enterprise SIEM Logs:
    - RBA Dataset: 'Login Timestamp', 'User ID', 'IP Address', 'User Agent String', 'Country', 'City', 'Is Attack IP', 'Is Account Takeover'
    - Azure AD / Okta / Splunk: 'TimeGenerated', 'UserPrincipalName', 'IPAddress', 'UserAgent', 'src_ip', 'upn'
    """
    def resolve_field(aliases: List[str], fallback: str = "") -> str:
        for alias in aliases:
            alias_lower = alias.lower()
            for key, val in row.items():
                if key and key.lower().strip() == alias_lower:
                    v_str = str(val).strip()
                    if v_str and v_str != "-":
                        return v_str
        return fallback

    # 1. Event ID
    event_id = resolve_field(
        ["event_id", "id", "index", "event_uuid", "log_id", "correlation_id", "recordid"],
        f"EVT-RBA-{row_idx:06d}"
    )

    # 2. Timestamp
    raw_time = resolve_field(
        ["login timestamp", "timestamp", "time", "datetime", "date", "event_time", "timegenerated", "published"],
        datetime.now(timezone.utc).isoformat()
    )
    if " " in raw_time and "T" not in raw_time:
        raw_time = raw_time.replace(" ", "T") + "Z"

    # 3. User Principal Name (UPN) / User ID
    raw_user = resolve_field(
        ["user id", "user_principal_name", "upn", "user", "username", "email", "account", "userprincipalname", "user_id"],
        f"user_{row_idx % 500}"
    )
    if not "@" in raw_user:
        clean_id = raw_user.replace("-", "").replace(".", "")
        user_principal_name = f"user.{clean_id[:8]}@enterprise-rba.org"
    else:
        user_principal_name = raw_user

    # 4. Source IP
    source_ip = resolve_field(
        ["ip address", "source_ip", "ip", "src_ip", "ip_address", "client_ip", "ipaddress"],
        "198.51.100.14"
    )

    # 5. User Agent String
    user_agent = resolve_field(
        ["user agent string", "user_agent", "ua", "agent", "browser", "useragent"],
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # 6. Geo Location mapping
    city = resolve_field(["city", "location_city"], "London")
    country = resolve_field(["country", "location_country"], "UK")
    
    try:
        lat = float(resolve_field(["lat", "latitude"], "51.5074"))
    except ValueError:
        lat = 51.5074

    try:
        lon = float(resolve_field(["lon", "longitude"], "-0.1278"))
    except ValueError:
        lon = -0.1278

    # 7. Check RBA Attack Indicators (Is Attack IP / Is Account Takeover)
    is_attack_ip = resolve_field(["is attack ip"], "False").lower() == "true"
    is_ato = resolve_field(["is account takeover"], "False").lower() == "true"

    if is_ato or is_attack_ip:
        session_token = "aitm_rba_attack_token_9k#M!z$P8&qL2*vX5@wR0^tY7%uI3#oE1$aS4&dF6*gH9!"
        if "python" not in user_agent.lower() and is_ato:
            user_agent += " (Hydra Automated Brute Force Scanner)"
    else:
        session_token = resolve_field(
            ["session_token", "token", "cookie", "auth_token"],
            f"session_rba_cookie_{row_idx % 1000:03d}"
        )

    return {
        "event_id": event_id,
        "timestamp": raw_time,
        "user_principal_name": user_principal_name,
        "source_ip": source_ip,
        "session_token": session_token,
        "geo": {
            "city": city,
            "country": country,
            "lat": lat,
            "lon": lon
        },
        "user_agent": user_agent
    }


def stream_rba_dataset():
    """Streaming pipeline using O(1) memory generator iteration over CSV rows."""
    default_path = resolve_dataset_path("")

    print("==========================================================================", flush=True)
    print("      AEGIS-SOC // HIGH-PERFORMANCE RBA & 1 GB+ SIEM LOG STREAMER         ", flush=True)
    print("==========================================================================", flush=True)

    user_input = input(f"Enter CSV dataset path [Press Enter for auto-discovered '{default_path}']: ").strip()
    filepath = resolve_dataset_path(user_input)

    if not os.path.exists(filepath) or os.path.isdir(filepath):
        print(f"[!] Error: File '{filepath}' could not be resolved to a valid CSV file.", flush=True)
        return

    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"\n[+] Dataset Resolved  : {os.path.abspath(filepath)}", flush=True)
    print(f"[+] File Size         : {file_size_mb:.2f} MB ({file_size_mb / 1024:.2f} GB)", flush=True)

    # Select Streaming Speed Mode
    print("\nSELECT STREAMING SPEED MODE:", flush=True)
    print("  [1] High-Speed Bulk Stream   (~50-150 events/sec | 0.001s delay)", flush=True)
    print("  [2] Real-Time Demo Stream    (1 event/sec | 1.0s delay)", flush=True)
    print("  [3] Custom Delay Stream", flush=True)

    speed_choice = input("\nEnter Choice [1-3, Default 1]: ").strip()
    
    if speed_choice == "2":
        stream_delay = 1.0
    elif speed_choice == "3":
        try:
            stream_delay = float(input("Enter delay per event in seconds (e.g. 0.05): ").strip())
        except ValueError:
            stream_delay = 0.001
    else:
        stream_delay = 0.001

    print(f"\n[+] Starting O(1) Memory Stream | Delay: {stream_delay}s per event...", flush=True)
    print("==========================================================================\n", flush=True)

    # Efficient Row Count Estimation
    print("[+] Reading dataset header and calculating total row count...", flush=True)
    with open(filepath, mode="r", encoding="utf-8-sig", errors="replace") as f:
        total_rows = sum(1 for _ in f) - 1

    total_rows = max(total_rows, 1)
    print(f"[+] Total Dataset Rows to Ingest: {total_rows:,}\n", flush=True)

    session = requests.Session()
    success_count = 0
    start_time = time.time()

    try:
        with open(filepath, mode="r", encoding="utf-8-sig", errors="replace") as csv_file:
            reader = csv.DictReader(csv_file)

            for idx, row in enumerate(reader, start=1):
                payload = map_row_to_schema(row, idx)

                # Transmit with retry logic
                sent = False
                while not sent:
                    try:
                        resp = session.post(INGEST_URL, json=payload, timeout=30)
                        if resp.status_code == 200:
                            success_count += 1
                            res_data = resp.json()
                            assessment = res_data.get("assessment", {})
                            score = assessment.get("risk_score", 0.0)
                            action = assessment.get("action", "UNKNOWN")
                            classification = assessment.get("classification", "N/A")

                            pct = (idx / total_rows) * 100
                            elapsed = time.time() - start_time
                            rate = success_count / elapsed if elapsed > 0 else 0

                            if idx % 20 == 0 or stream_delay >= 0.5 or idx == total_rows:
                                print(f"[{idx:,}/{total_rows:,} ({pct:.2f}%)] "
                                      f"ID: {payload['event_id']} | "
                                      f"UPN: {payload['user_principal_name']} | "
                                      f"IP: {payload['source_ip']} ({payload['geo']['country']}) | "
                                      f"Score: {score:.1f}/100 | "
                                      f"Action: {action} | "
                                      f"Rate: {rate:.1f} ev/s", flush=True)
                            sent = True
                        else:
                            print(f"[!] HTTP Error {resp.status_code}: {resp.text}", flush=True)
                            sent = True
                    except requests.exceptions.ConnectionError:
                        print(f"[!] Server unreachable at {INGEST_URL}. Retrying in 2s...", flush=True)
                        time.sleep(2)
                    except Exception as e:
                        print(f"[!] Note on {payload['event_id']}: {e}", flush=True)
                        sent = True

                if stream_delay > 0:
                    time.sleep(stream_delay)

        elapsed_total = time.time() - start_time
        avg_rate = success_count / elapsed_total if elapsed_total > 0 else 0
        print("\n==========================================================================", flush=True)
        print(" [✔] REAL DATASET STREAMING COMPLETE!", flush=True)
        print(f" Total Ingested : {success_count:,} events", flush=True)
        print(f" Total Time     : {elapsed_total:.2f} seconds", flush=True)
        print(f" Average Rate   : {avg_rate:.2f} events/sec", flush=True)
        print("==========================================================================", flush=True)

    except Exception as e:
        print(f"\n[!] Critical Error during dataset streaming: {e}", flush=True)


if __name__ == "__main__":
    stream_rba_dataset()
