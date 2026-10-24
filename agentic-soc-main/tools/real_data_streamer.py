"""
AEGIS-SOC // Real-Data Streamer & SIEM Forwarder
=================================================
Role: Principal Enterprise Security Forwarder
Description: Reads external SIEM/IdP authentication logs (CSV or JSON format) 
             or uses an embedded enterprise mock dataset to stream real telemetry 
             into the AEGIS-SOC REST API (http://127.0.0.1:8000/api/v1/telemetry/ingest).

Usage:
  python tools/real_data_streamer.py [--file path/to/logs.csv] [--delay 1.5]
"""

import os
import sys
import time
import json
import csv
import argparse
from datetime import datetime, timezone
import requests

# Base Target API Endpoint
DEFAULT_INGEST_URL = "http://127.0.0.1:8000/api/v1/telemetry/ingest"

# Enterprise Fallback Dataset (Realistic Anonymized Authentication Logs)
EMBEDDED_SIEM_DATASET = [
    {
        "event_id": "SIEM-AZURE-9001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "ceo.executive@enterprise-aegis.com",
        "source_ip": "198.51.100.14",
        "session_token": "bearer_standard_azure_ad_session_token_091823",
        "geo": {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    {
        "event_id": "SIEM-OKTA-9002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "ceo.executive@enterprise-aegis.com",
        "source_ip": "203.0.113.88",
        "session_token": "aitm_phishing_proxy_stolen_cookie_881736219482710481",
        "geo": {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    {
        "event_id": "SIEM-SPLUNK-9003",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "sysadmin.lead@enterprise-aegis.com",
        "source_ip": "198.51.100.45",
        "session_token": "token_9k#M!z$P8&qL2*vX5@wR0^tY7%uI3#oE1$aS4&dF6*gH9!jK2@lM5#nB8$vC0^xZ",
        "geo": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
        "user_agent": "Mozilla/5.0 ExpressVPN / Anonymous Egress Proxy Anomaly"
    },
    {
        "event_id": "SIEM-CROWD-9004",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "devops.bot@enterprise-aegis.com",
        "source_ip": "198.51.100.112",
        "session_token": "session_bot_token_99123",
        "geo": {"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
        "user_agent": "Python-urllib/3.11 / Nmap Scripting Engine / Hydra v9.4 (Automated Scanner)"
    }
]


def stream_event_payload(url: str, payload: dict) -> bool:
    """Sends a single TelemetryEvent JSON payload to the AEGIS-SOC REST API."""
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            res_json = response.json()
            assessment = res_json.get("assessment", {})
            action = assessment.get("action", "UNKNOWN")
            score = assessment.get("risk_score", 0.0)
            upn = assessment.get("user_principal_name") or assessment.get("principal", "N/A")
            
            print(f"[FORWARDED OK] Event: {payload['event_id']} | User: {upn} | Score: {score:.1f}/100 | Action: {action}")
            return True
        else:
            print(f"[ERROR {response.status_code}] Failed to ingest {payload['event_id']}: {response.text}")
            return False
    except Exception as e:
        print(f"[CONNECTION ERROR] Target backend {url} unreachable: {e}")
        return False


def load_file_telemetry(file_path: str) -> list:
    """Reads telemetry events from a local CSV or JSON file."""
    events = []
    if not os.path.exists(file_path):
        print(f"[WARNING] File '{file_path}' not found. Falling back to embedded dataset.")
        return EMBEDDED_SIEM_DATASET

    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext == ".json":
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                events = data if isinstance(data, list) else [data]
        elif ext == ".csv":
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Parse CSV row into TelemetryEvent structure
                    event = {
                        "event_id": row.get("event_id", f"CSV-{time.time()}"),
                        "timestamp": row.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "user_principal_name": row.get("user_principal_name") or row.get("principal"),
                        "source_ip": row.get("source_ip", "0.0.0.0"),
                        "session_token": row.get("session_token", "default_token"),
                        "geo": {
                            "city": row.get("city", "Unknown"),
                            "country": row.get("country", "Unknown"),
                            "lat": float(row.get("lat", 0.0)),
                            "lon": float(row.get("lon", 0.0))
                        },
                        "user_agent": row.get("user_agent", "Standard Browser")
                    }
                    events.append(event)
    except Exception as e:
        print(f"[PARSING ERROR] Failed to parse '{file_path}': {e}. Using fallback dataset.")
        return EMBEDDED_SIEM_DATASET

    return events


def main():
    parser = argparse.ArgumentParser(description="AEGIS-SOC External Telemetry Streamer & SIEM Forwarder")
    parser.add_argument("--url", default=DEFAULT_INGEST_URL, help="AEGIS-SOC REST API Ingest URL")
    parser.add_argument("--file", default=None, help="Path to external CSV or JSON authentication log file")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between HTTP POST transmissions (seconds)")
    args = parser.parse_args()

    print("===============================================================")
    print("   AEGIS-SOC // ENTERPRISE SIEM TELEMETRY STREAM FORWARDER     ")
    print("===============================================================")
    print(f"Target API Endpoint : {args.url}")
    print(f"Transmission Delay  : {args.delay} second(s)")
    print(f"Source Log Input    : {args.file or 'EMBEDDED SAMPLE DATASET (Fallback)'}")
    print("===============================================================\n")

    events = load_file_telemetry(args.file) if args.file else EMBEDDED_SIEM_DATASET

    print(f"[STREAMING STARTED] Forwarding {len(events)} telemetry payloads to REST API...\n")

    success_count = 0
    for idx, event in enumerate(events, 1):
        # Update timestamp to present time for real-time calculation accuracy
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        print(f"[{idx}/{len(events)}] Transmitting telemetry from {event['source_ip']}...")
        if stream_event_payload(args.url, event):
            success_count += 1
        time.sleep(args.delay)

    print("\n===============================================================")
    print(f"   STREAMING COMPLETE: {success_count}/{len(events)} Events Ingested Successfully")
    print("===============================================================")


if __name__ == "__main__":
    main()
