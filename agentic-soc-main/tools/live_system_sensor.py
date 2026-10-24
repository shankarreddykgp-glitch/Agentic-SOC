"""
AEGIS-SOC // Live Real-World Sensor & Machine Telemetry Collector
================================================================================
Description: Captures ACTUAL real-time network, IP, GeoIP, and OS telemetry from
             your physical machine and streams it into the AEGIS-SOC FastAPI engine.
"""

import sys
import os
import time
import socket
import platform
import requests
from datetime import datetime, timezone

# Add root folder to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

INGEST_URL = "http://127.0.0.1:8000/api/v1/telemetry/ingest"


def fetch_real_public_geoip():
    """
    Fetches ACTUAL real public IP address and physical GPS location 
    from live internet GeoIP servers (ipify & ip-api).
    """
    try:
        # 1. Fetch real public IP
        ip_resp = requests.get("https://api.ipify.org?format=json", timeout=4)
        public_ip = ip_resp.json().get("ip", "127.0.0.1") if ip_resp.status_code == 200 else "127.0.0.1"

        # 2. Fetch real physical location for this public IP
        geo_resp = requests.get(f"http://ip-api.com/json/{public_ip}", timeout=4)
        if geo_resp.status_code == 200:
            gdata = geo_resp.json()
            return {
                "ip": public_ip,
                "city": gdata.get("city", "Unknown City"),
                "country": gdata.get("country", "Unknown Country"),
                "lat": float(gdata.get("lat", 51.5074)),
                "lon": float(gdata.get("lon", -0.1278)),
                "isp": gdata.get("isp", "Local ISP")
            }
    except Exception as e:
        print(f"[!] GeoIP Lookup Note: {e}")

    # Fallback local machine info
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return {
        "ip": local_ip,
        "city": "Local Network",
        "country": "Local System",
        "lat": 51.5074,
        "lon": -0.1278,
        "isp": "Local LAN"
    }


def capture_and_stream_real_telemetry(user_email: str = "operator.real@enterprise.org", delay_seconds: float = 3.0):
    print("==========================================================================")
    print("      AEGIS-SOC // LIVE REAL-WORLD MACHINE TELEMETRY SENSOR              ")
    print("==========================================================================")
    print(f"[+] Local System Hostname : {socket.gethostname()}")
    print(f"[+] Operating System      : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"[+] Monitoring Target UPN : {user_email}")
    print("==========================================================================")
    print("[*] Fetching ACTUAL real-time public IP & GeoIP location from live internet...")

    session = requests.Session()
    event_counter = 1

    while True:
        try:
            # Fetch live real-time network info from physical machine
            real_geo = fetch_real_public_geoip()
            
            # Construct real system User-Agent string
            real_user_agent = f"Mozilla/5.0 ({platform.system()} NT 10.0; {platform.machine()}) AEGIS-LiveSensor/2.0"

            # Create real telemetry payload
            payload = {
                "event_id": f"LIVE-REAL-{event_counter:06d}",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "user_principal_name": user_email,
                "source_ip": real_geo["ip"],
                "session_token": f"cookie_live_real_auth_session_{event_counter:03d}",
                "geo": {
                    "city": real_geo["city"],
                    "country": real_geo["country"],
                    "lat": real_geo["lat"],
                    "lon": real_geo["lon"]
                },
                "user_agent": real_user_agent
            }

            # Send live telemetry to FastAPI backend
            resp = session.post(INGEST_URL, json=payload, timeout=5)
            if resp.status_code == 200:
                res_data = resp.json()
                assessment = res_data.get("assessment", {})
                score = assessment.get("risk_score", 0.0)
                action = assessment.get("action", "UNKNOWN")
                classification = assessment.get("classification", "N/A")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Event #{event_counter:,} | "
                      f"Real IP: {real_geo['ip']} ({real_geo['city']}, {real_geo['country']}) | "
                      f"Score: {score:.1f}/100 | Action: {action} | Class: {classification}", flush=True)
            else:
                print(f"[!] Server HTTP Error {resp.status_code}: {resp.text}", flush=True)

        except requests.exceptions.ConnectionError:
            print(f"[!] AEGIS-SOC server at {INGEST_URL} unreachable. Retrying in 3s...", flush=True)
        except Exception as e:
            print(f"[!] Sensor Loop Error: {e}", flush=True)

        event_counter += 1
        time.sleep(delay_seconds)


if __name__ == "__main__":
    target_upn = sys.argv[1] if len(sys.argv) > 1 else "operator.real@enterprise.org"
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    capture_and_stream_real_telemetry(user_email=target_upn, delay_seconds=interval)
