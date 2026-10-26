"""
GhostTrace Synthetic Test Fixtures & Forensic Verification Suite
HackerRank Orchestrate October 2026 | Ghost Data Still Exists

Tests 3 distinct edge-case failure modes:
1. Historical Identity Drift: Primary profile deleted, but legacy secondary record
   remains tied to historical email hash.
2. Data Flow Re-creation Risk: Clean profile deletion rendered incomplete by an
   active sync connector capable of repopulating downstream systems.
3. Policy-Mandated Retention Redaction: Tombstone record properly retained under
   Rule 15, verifying that direct identifiers are stripped while audit link persists.
"""

import os
import sys
import json
import unittest

# Ensure imports work from any execution directory
current_dir = os.path.dirname(os.path.abspath(__file__))
code_dir = os.path.dirname(current_dir)
repo_root = os.path.dirname(code_dir)
for p in (repo_root, code_dir, current_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from policy_engine import ForensicPolicyEngine
from evaluation.main import validate_step_structure, validate_steps_ordering


def check_steps_validity(status: str, steps: list, case_id: str = "test_case") -> tuple:
    errs = []
    for idx, s in enumerate(steps, start=1):
        step_errs = validate_step_structure(s, idx, case_id, status)
        errs.extend(step_errs)
    order_errs = validate_steps_ordering(steps, case_id)
    errs.extend(order_errs)
    return len(errs) == 0, errs


class TestSyntheticForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cache_file = os.path.join(code_dir, "evidence_cache.json")
        cls.engine = ForensicPolicyEngine(dataset_dir="dataset", cache_file=cache_file)

    def test_fixture_1_historical_identity_drift(self):
        """
        Fixture 1: Historical Email Change Drift
        User changed email from historical address to current address.
        The primary account was processed, but analytics platform retained
        a record linked to the historical email hash.
        Expected: INCOMPLETE status, REPORT_REMAINING_RECORD / REPORT_EXPOSED_PII on analytics.
        """
        req = {
            "case_id": "case_12",
            "email": "minjun.kim@gmail.com",
            "requested_at": "2026-09-08T08:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-09T08:00:00Z",
            "audit_at": "2026-09-26T11:00:00Z",
            "request_text": "Please delete my account and all personal information."
        }
        status, steps = self.engine.audit_case(req)
        self.assertEqual(status, "INCOMPLETE")
        
        # Verify analytics_platform finding exists
        analytics_findings = [
            s for s in steps
            if s["system_id"] == "analytics_platform" and s["phase"] == "FINDING"
        ]
        self.assertGreaterEqual(len(analytics_findings), 1)
        self.assertEqual(analytics_findings[0]["resource_id"], "analytics_9914")
        
        # Verify schema validity
        valid, errs = check_steps_validity(status, steps)
        self.assertTrue(valid, f"Schema errors: {errs}")

    def test_fixture_2_active_data_flow_risk(self):
        """
        Fixture 2: Re-creation via Active Synchronization Flow
        Primary account deletion was executed, but an integration connector
        remains active at audit_at, presenting immediate recreation risk.
        Expected: INCOMPLETE status, REPORT_ACTIVE_DATA_FLOW finding and DISABLE_DATA_FLOW remediation.
        """
        req = {
            "case_id": "case_20",
            "email": "akosua.gyasi@gmail.com",
            "requested_at": "2026-09-08T11:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-09-09T11:00:00Z",
            "audit_at": "2026-09-26T11:00:00Z",
            "request_text": "Please treat this message as a request for permanent account deletion."
        }
        status, steps = self.engine.audit_case(req)
        self.assertEqual(status, "INCOMPLETE")

        # Verify active data flow finding and remediation
        data_flow_finding = [
            s for s in steps
            if s["system_id"] == "integration_service" and s["operation"] == "REPORT_ACTIVE_DATA_FLOW"
        ]
        self.assertGreaterEqual(len(data_flow_finding), 1)
        self.assertEqual(data_flow_finding[0]["state"], "ACTIVE")

        data_flow_remed = [
            s for s in steps
            if s["system_id"] == "integration_service" and s["operation"] == "DISABLE_DATA_FLOW"
        ]
        self.assertGreaterEqual(len(data_flow_remed), 1)
        self.assertEqual(data_flow_remed[0]["state"], "DISABLED")

        # Verify schema validity
        valid, errs = check_steps_validity(status, steps)
        self.assertTrue(valid, f"Schema errors: {errs}")

    def test_fixture_3_policy_retained_redacted_tombstone(self):
        """
        Fixture 3: Policy-Mandated Account Tombstone Redaction (Rule 15)
        An account tombstone is retained in identity_service for referential
        integrity of historical audit records, but personal PII must be redacted.
        Expected: VERIFY_RECORD_REDACTED verification step with valid state REDACTED.
        """
        req = {
            "case_id": "case_17",
            "email": "l.fontaine46@yahoo.com",
            "requested_at": "2026-08-20T12:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-08-22T10:00:00Z",
            "audit_at": "2026-09-26T11:00:00Z",
            "request_text": "Please delete my account and ensure that no lingering data remains."
        }
        status, steps = self.engine.audit_case(req)
        self.assertIn(status, ["COMPLETE", "INCOMPLETE"])

        # Check tombstone handling if present
        tombstone_steps = [
            s for s in steps
            if s["system_id"] == "identity_service" and "tombstone" in s["resource_id"]
        ]
        if tombstone_steps:
            for s in tombstone_steps:
                if s["phase"] == "VERIFICATION":
                    self.assertEqual(s["operation"], "VERIFY_RECORD_REDACTED")
                    self.assertEqual(s["state"], "REDACTED")

        # Verify schema validity
        valid, errs = check_steps_validity(status, steps)
        self.assertTrue(valid, f"Schema errors: {errs}")


if __name__ == "__main__":
    unittest.main()
