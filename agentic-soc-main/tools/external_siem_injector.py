"""
AEGIS-SOC // External SIEM & Telemetry Forwarder CLI
=====================================================
Role: External Enterprise SIEM Injector (Splunk / Azure AD / Okta / CrowdStrike Log Forwarder)
Description: Interactive CLI tool demonstrating decoupled REST API ingestion.
             Allows security analysts to push live attack vectors into 
             http://127.0.0.1:8000/api/v1/telemetry/ingest from a second terminal window.

Usage:
  python tools/external_siem_injector.py
"""

import sys
import time
import json
import random
from datetime import datetime, timezone
import requests

# Reconfigure stdout for UTF-8 on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Base Target API Endpoint
INGEST_URL = "http://127.0.0.1:8000/api/v1/telemetry/ingest"


def print_banner():
    print("==========================================================================")
    print("      AEGIS-SOC // ENTERPRISE EXTERNAL SIEM LOG FORWARDER CLI             ")
    print("==========================================================================")
    print(" Target Endpoint: http://127.0.0.1:8000/api/v1/telemetry/ingest           ")
    print(" Decoupled Mode : Active (Simulates Azure AD / Okta / Splunk Log Push)    ")
    print("==========================================================================")


def send_telemetry_payload(event_type_label: str, payload: dict):
    """Sends JSON TelemetryEvent to REST API and formats server response."""
    print(f"\n[FORWARDING] Building {event_type_label} payload...")
    print(f"Target UPN : {payload['user_principal_name']}")
    print(f"Source IP  : {payload['source_ip']} ({payload['geo']['city']}, {payload['geo']['country']})")
    print(f"Event ID   : {payload['event_id']}")

    try:
        start_time = time.time()
        response = requests.post(INGEST_URL, json=payload, timeout=10)
        elapsed_ms = (time.time() - start_time) * 1000

        if response.status_code == 200:
            res_data = response.json()
            assessment = res_data.get("assessment", {})
            action = assessment.get("action", "UNKNOWN")
            score = assessment.get("risk_score", 0.0)
            mitre = assessment.get("mitre_technique", "N/A")
            classification = assessment.get("classification", "N/A")

            print(f"\n[SERVER RESPONSE] HTTP 200 OK ({elapsed_ms:.1f}ms)")
            print(f"|- Status Code     : 200 OK")
            print(f"|- Classification  : {classification} ({mitre})")
            print(f"|- Algorithmic Risk: {score:.1f} / 100")
            print(f"|- Triage Action   : {action}")

            soar_logs = assessment.get("soar_execution_logs")
            if soar_logs:
                print("\n[SOAR MUTATIONS EXECUTED]")
                for log in soar_logs:
                    print(f"  * {log.get('action')}: {log.get('details')}")

            reasoning = assessment.get("reasoning")
            if reasoning:
                print(f"\n[GEMINI REASONING] {reasoning}")

        else:
            print(f"\n[SERVER ERROR] HTTP {response.status_code}: {response.text}")

    except Exception as e:
        print(f"\n[CONNECTION FAILURE] Could not reach AEGIS-SOC API at {INGEST_URL}: {e}")
        print("Make sure 'python server.py' is running on port 8000!")


def build_benign_event() -> dict:
    """Option 1: Normal user login (<50 risk score)."""
    return {
        "event_id": f"EXT-BENIGN-{random.randint(10000, 99999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "benign.user@enterprise.com",
        "source_ip": "198.51.100.14",
        "session_token": f"cookie{random.randint(10, 99)}",
        "geo": {"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }


def build_aitm_event() -> dict:
    """Option 2: AiTM Phishing & Impossible Travel (>80 risk score)."""
    return {
        "event_id": f"EXT-AITM-{random.randint(10000, 99999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "alex.hunter@enterprise.com",
        "source_ip": "203.0.113.88",
        "session_token": "aitm_phishing_proxy_cookie_9k#M!z$P8&qL2*vX5@wR0^tY7%uI3#oE1$aS4&dF6*gH9!jK2@lM5#nB8$vC0^xZ",
        "geo": {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }


def build_ato_event() -> dict:
    """Option 3: Brute Force ATO with Automated UA Scanner (>80 risk score)."""
    return {
        "event_id": f"EXT-ATO-{random.randint(10000, 99999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "sysadmin.lead@enterprise.com",
        "source_ip": "198.51.100.199",
        "session_token": f"bottoken{random.randint(10, 99)}",
        "geo": {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
        "user_agent": "Python-urllib/3.11 / Nmap Scripting Engine / Hydra v9.4 (Automated Brute Force Scanner)"
    }


def build_proxy_hitl_event() -> dict:
    """Option 4: Ambiguous Anonymizer Proxy (50-80 risk score - HITL Test)."""
    return {
        "event_id": f"EXT-HITL-{random.randint(10000, 99999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_principal_name": "sarah.connor@cyberdyne.org",
        "source_ip": "198.51.100.45",
        "session_token": "session123",
        "geo": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
        "user_agent": "Mozilla/5.0 ExpressVPN / Untrusted Anonymous Proxy Egress Header"
    }


def main():
    print_banner()

    while True:
        print("\nSELECT EXTERNAL TELEMETRY INJECTION OPTION:")
        print("  [1] Inject External Benign Login             (Score < 50 // Autonomous Monitor)")
        print("  [2] Inject External AiTM Phishing Attack    (Score > 80 // Autonomous Block)")
        print("  [3] Inject External Brute Force (ATO)       (Score > 80 // Autonomous Block)")
        print("  [4] Inject Ambiguous Proxy Threat (HITL)    (Score 50-80 // Analyst Review)")
        print("  [5] Exit Forwarder CLI")

        try:
            choice = input("\nEnter Choice [1-5]: ").strip()
            
            if choice == "1":
                payload = build_benign_event()
                send_telemetry_payload("Benign Login", payload)
            elif choice == "2":
                payload = build_aitm_event()
                send_telemetry_payload("AiTM Phishing Attack", payload)
            elif choice == "3":
                payload = build_ato_event()
                send_telemetry_payload("ATO Brute Force", payload)
            elif choice == "4":
                payload = build_proxy_hitl_event()
                send_telemetry_payload("Ambiguous Proxy (HITL Test)", payload)
            elif choice == "5":
                print("\n[SHUTDOWN] Exiting SIEM Forwarder CLI. Goodbye!")
                sys.exit(0)
            else:
                print("\n[INVALID] Please select a valid option from 1 to 5.")

        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Terminated by user. Exiting!")
            sys.exit(0)


if __name__ == "__main__":
    main()
