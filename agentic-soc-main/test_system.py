"""
Integration Test Suite for Autonomous SOC (Agentic-SOC)
Verifies:
1. Shannon entropy and Haversine velocity calculations.
2. ChromaDB Vector Store Threat Memory pre-seeding and T1090 proxy anomaly queries.
3. SOAR mitigation engine static methods including dispatch_security_notification_email.
4. LangGraph stateful multi-agent swarm Triage Matrix (>80 block, 50-80 HITL, <50 safe) with Gemini LLM reasoning.
5. FastAPI REST API endpoints using TestClient, including /api/v1/audit/approve-hitl (APPROVED & DISMISSED decisions).
"""

import sys
import unittest
from datetime import datetime
from fastapi.testclient import TestClient

from core.math_engine import calculate_shannon_entropy, calculate_travel_velocity
from core.vector_store import ThreatIntelligenceMemory
from core.mitigation_engine import EnterpriseSOAREnforcer
from agents.graph_pipeline import LangGraphEnterprisePipeline
from server import app


class TestAgenticSOCSystem(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.pipeline = LangGraphEnterprisePipeline()
        self.vector_store = ThreatIntelligenceMemory()

    def test_01_shannon_entropy(self):
        """Test mathematical entropy calculation for low vs high randomness strings."""
        low_entropy = calculate_shannon_entropy("aaaaaaaaaaaa")
        high_entropy = calculate_shannon_entropy("9k#M!z$P8&qL2*vX5@wR0^tY7%uI3#oE1")
        
        self.assertEqual(low_entropy, 0.0)
        self.assertGreater(high_entropy, 3.85)
        print(f"[PASS] Shannon Entropy Test: Low={low_entropy}, High={high_entropy}")

    def test_02_haversine_velocity(self):
        """Test travel velocity calculation between London and Tokyo in 0.5 hours."""
        velocity = calculate_travel_velocity(51.5074, -0.1278, 35.6762, 139.6503, 0.5)
        self.assertGreater(velocity, 800.0)
        print(f"[PASS] Haversine Velocity Test: London to Tokyo in 30 mins = {velocity} km/h (Impossible travel > 800 km/h)")

    def test_03_vector_store_rag(self):
        """Test ChromaDB threat intelligence memory vector queries including T1090."""
        aitm_res = self.vector_store.query_threat_intel("Adversary-in-the-Middle (AiTM) phishing attack proxying authentication")
        self.assertEqual(aitm_res["mitre_id"], "T1539")

        proxy_res = self.vector_store.query_threat_intel("Suspicious proxy egress anonymizer VPN shift")
        self.assertIn(proxy_res["mitre_id"], ["T1090", "T1539", "T1550.004"])
        print(f"[PASS] Vector RAG Store Query Test: Match 1={aitm_res['mitre_id']}, Match 2={proxy_res['mitre_id']}")

    def test_04_soar_mitigation_engine(self):
        """Test SOAR mitigation enforcer static methods including email dispatch."""
        revoke_log = EnterpriseSOAREnforcer.revoke_identity_session("test.user@enterprise.com")
        block_log = EnterpriseSOAREnforcer.block_perimeter_ip("198.51.100.99")
        email_log = EnterpriseSOAREnforcer.dispatch_security_notification_email("test.user@enterprise.com", {"classification": "AiTM Phishing"})

        self.assertEqual(revoke_log["status"], "SUCCESS")
        self.assertEqual(block_log["status"], "SUCCESS")
        self.assertEqual(email_log["status"], "SUCCESS")
        print("[PASS] Enterprise SOAR Engine Test: Revoke, Block & Email Notification logs generated successfully.")

    def test_05_langgraph_swarm_pipeline(self):
        """Test stateful multi-agent swarm Triage Matrix logic."""
        benign_evt = {
            "event_id": "TEST-BENIGN-01",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_principal_name": "user.benign@enterprise.com",
            "source_ip": "198.51.100.10",
            "session_token": "normal_session_12345",
            "geo": {"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        res_benign = self.pipeline.process_event(benign_evt)
        self.assertEqual(res_benign["action"], "AUTONOMOUS_MONITOR")
        self.assertLess(res_benign["algorithmic_risk_score"], 50.0)

        prev_evt = benign_evt.copy()
        aitm_evt = {
            "event_id": "TEST-AITM-01",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_principal_name": "user.benign@enterprise.com",
            "source_ip": "203.0.113.50",
            "session_token": "normal_session_12345",
            "geo": {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        res_aitm = self.pipeline.process_event(current_event=aitm_evt, previous_event=prev_evt)
        self.assertEqual(res_aitm["action"], "AUTONOMOUS_CRITICAL_BLOCK")
        self.assertGreater(res_aitm["algorithmic_risk_score"], 80.0)

        print("[PASS] LangGraph Swarm Triage Matrix Test: Benign & Critical Block verified.")

    def test_06_approve_hitl_endpoint_decisions(self):
        """Test POST /api/v1/audit/approve-hitl endpoint for APPROVED and DISMISSED decisions."""
        hitl_evt = {
            "event_id": "TEST-HITL-DECISION-1",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_principal_name": "analyst.test@enterprise.com",
            "source_ip": "198.51.100.88",
            "session_token": "token_abc_123",
            "geo": {"city": "Berlin", "country": "DE", "lat": 52.52, "lon": 13.405},
            "user_agent": "Mozilla/5.0 ExpressVPN / Proxy Anomaly"
        }
        ingest_res = self.client.post("/api/v1/telemetry/ingest", json=hitl_evt)
        self.assertEqual(ingest_res.status_code, 200)

        app_res = self.client.post(
            "/api/v1/audit/approve-hitl",
            json={
                "event_id": "TEST-HITL-DECISION-1",
                "decision": "APPROVED",
                "notes": "Approved by automated integration test."
            }
        )
        self.assertEqual(app_res.status_code, 200)
        app_data = app_res.json()
        self.assertEqual(app_data["status"], "SUCCESS")
        self.assertEqual(app_data["updated_assessment"]["action"], "HUMAN_AUTHORIZED_BLOCK")
        self.assertEqual(len(app_data["updated_assessment"]["soar_execution_logs"]), 3)

        hitl_evt2 = hitl_evt.copy()
        hitl_evt2["event_id"] = "TEST-HITL-DECISION-2"
        self.client.post("/api/v1/telemetry/ingest", json=hitl_evt2)

        dism_res = self.client.post(
            "/api/v1/audit/approve-hitl",
            json={
                "event_id": "TEST-HITL-DECISION-2",
                "decision": "DISMISSED",
                "notes": "Dismissed as false positive."
            }
        )
        self.assertEqual(dism_res.status_code, 200)
        dism_data = dism_res.json()
        self.assertEqual(dism_data["status"], "SUCCESS")
        self.assertEqual(dism_data["updated_assessment"]["action"], "DISMISSED_FALSE_POSITIVE")

        print("[PASS] Interactive HITL Decision Endpoint Test: APPROVED (HUMAN_AUTHORIZED_BLOCK) & DISMISSED (DISMISSED_FALSE_POSITIVE) routes verified.")


if __name__ == "__main__":
    unittest.main()
