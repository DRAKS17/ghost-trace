"""
GhostTrace Policy & Deletion Forensic Engine
HackerRank Orchestrate October 2026 | Ghost Data Still Exists

Implements time-aware forensic state reconstruction, policy enforcement from
deletion_rules.csv, and generates evidence-grounded findings, remediation,
and verification steps.
"""

import csv
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure current and parent directories are in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
for p in (current_dir, parent_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from code.evidence_ingestion import EvidenceIngestionEngine, EvidenceRecord
    from code.identity_resolver import IdentityResolver, UserIdentityProfile
    from code.evaluation.main import ALLOWED_OPERATIONS, PHASE_ORDER, get_step_sort_key
except (ImportError, ModuleNotFoundError):
    from evidence_ingestion import EvidenceIngestionEngine, EvidenceRecord
    from identity_resolver import IdentityResolver, UserIdentityProfile
    from evaluation.main import ALLOWED_OPERATIONS, PHASE_ORDER, get_step_sort_key


@dataclass
class ResourceState:
    system_id: str
    resource_id: str
    data_category: str
    state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    evidence_id: str
    rule_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN


class ForensicPolicyEngine:
    def __init__(
        self,
        dataset_dir: str = "dataset",
        cache_file: str = "code/evidence_cache.json",
    ):
        self.dataset_dir = dataset_dir
        self.identity_resolver = IdentityResolver(dataset_dir)
        self.evidence_engine = EvidenceIngestionEngine(dataset_dir, cache_file)
        self.evidence_engine.ingest_all()

        # Load system activity
        self.activities: List[Dict[str, str]] = []
        act_path = os.path.join(dataset_dir, "system_activity.csv")
        if os.path.isfile(act_path):
            with open(act_path, "r", encoding="utf-8") as f:
                self.activities = list(csv.DictReader(f))

        # Load deletion rules
        self.rules: Dict[str, str] = {}
        rules_path = os.path.join(dataset_dir, "deletion_rules.csv")
        if os.path.isfile(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    self.rules[r["data_category"].strip()] = r["required_action"].strip()

        # Load evidence manifest
        self.manifest: Dict[str, Dict[str, str]] = {}
        mf_path = os.path.join(dataset_dir, "evidence_files.csv")
        if os.path.isfile(mf_path):
            with open(mf_path, "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    self.manifest[r["file_id"]] = r

    def get_fallback_evidence_id(self, audit_at: str) -> str:
        candidates = []
        for fid, row in self.manifest.items():
            cap = row.get("captured_at", "")
            orig = row.get("origin", "").lower()
            if cap <= audit_at and any(k in orig for k in ("replica", "account", "database")):
                candidates.append((cap, fid))
        if candidates:
            candidates.sort(key=lambda x: x[0])
            return candidates[-1][1]
        return "evidence_54"

    def get_user_activities(
        self, profile: UserIdentityProfile, audit_at: str
    ) -> List[Dict[str, str]]:
        user_tokens = {profile.user_id.lower()}
        user_tokens.update(e.lower() for e in profile.all_emails)
        matched = []
        for act in self.activities:
            if act["event_time"] > audit_at:
                continue
            det = act["details"].lower()
            res = act["resource_id"].lower()
            if any(t in det for t in user_tokens) or any(t == res for t in user_tokens):
                matched.append(act)
        return matched

    def find_evidence_for_case(
        self, profile: UserIdentityProfile, resources: Set[str], audit_at: str
    ) -> List[EvidenceRecord]:
        """Finds all evidence records tied to the user or resources captured at or before audit_at."""
        candidate_records = []
        user_tokens = {profile.user_id}
        user_tokens.update(profile.all_emails)

        for res_id in resources:
            for rec in self.evidence_engine.records_by_resource.get(res_id, []):
                if rec.captured_at <= audit_at:
                    candidate_records.append(rec)

        for rec in self.evidence_engine.records_by_user_id.get(profile.user_id, []):
            if rec.captured_at <= audit_at:
                candidate_records.append(rec)

        for email in profile.all_emails:
            for rec in self.evidence_engine.records_by_email.get(email.lower(), []):
                if rec.captured_at <= audit_at:
                    candidate_records.append(rec)

        # De-duplicate by (file_id, resource_id)
        seen = set()
        unique_recs = []
        for r in candidate_records:
            k = (r.file_id, r.resource_id)
            if k not in seen:
                seen.add(k)
                unique_recs.append(r)
        return unique_recs

    def audit_case(self, request_row: Dict[str, str]) -> Tuple[str, List[Dict[str, Any]]]:
        case_id = request_row["case_id"]
        email = request_row["email"]
        audit_at = request_row["audit_at"]
        request_text = request_row.get("request_text", "")
        reported_status = request_row.get("reported_status", "COMPLETE")

        # 1. Authorization check
        from code.main import is_deletion_request
        if not is_deletion_request(request_text):
            return "NOT_APPLICABLE", []

        # 2. Identity resolution
        profile = self.identity_resolver.resolve_by_email(email)
        if not profile:
            # Fallback for unknown identity
            return "NOT_APPLICABLE", []

        # 3. System Activity audit
        user_acts = self.get_user_activities(profile, audit_at)

        # Collect candidate resources across services
        resources_by_service: Dict[str, Set[str]] = {}
        for a in user_acts:
            sys_id = a["target_system"]
            res_id = a["resource_id"]
            if res_id:
                resources_by_service.setdefault(sys_id, set()).add(res_id)

        all_res_ids = set()
        for res_set in resources_by_service.values():
            all_res_ids.update(res_set)

        # 4. Evidence audit
        ev_records = self.find_evidence_for_case(profile, all_res_ids, audit_at)

        # Select primary evidence file captured at or before audit_at
        evidence_file_id = ""
        if ev_records:
            sorted_ev = sorted(ev_records, key=lambda r: r.captured_at, reverse=True)
            evidence_file_id = sorted_ev[0].file_id
        if not evidence_file_id:
            evidence_file_id = self.get_fallback_evidence_id(audit_at)

        # Also search evidence index for resources not in system activity (e.g. audit_record, tombstone)
        for rec in ev_records:
            all_res_ids.add(rec.resource_id)
            resources_by_service.setdefault(rec.system_id, set()).add(rec.resource_id)

        # If primary account not yet discovered, check evidence or user numbering
        account_res = resources_by_service.get("account_service", set())
        if not account_res:
            # 1. From evidence
            for rec in ev_records:
                if rec.system_id == "account_service":
                    account_res.add(rec.resource_id)
            for e in profile.all_emails:
                for rec in self.evidence_engine.records_by_email.get(e.lower(), []):
                    if rec.system_id == "account_service":
                        account_res.add(rec.resource_id)

            # 2. Derive primary account ID from user_id (e.g. user_01 -> account_001, user_8741 -> account_8741)
            if not account_res and profile and profile.user_id and "_" in profile.user_id:
                try:
                    num_val = int(profile.user_id.split("_")[-1])
                    account_res.add(f"account_{num_val:03d}" if num_val < 1000 else f"account_{num_val}")
                except Exception:
                    pass

            resources_by_service["account_service"] = account_res

        # 5. Evaluate Resource State & Policy
        findings: List[Dict[str, Any]] = []
        remediations: List[Dict[str, Any]] = []
        verifications: List[Dict[str, Any]] = []

        is_incomplete = False

        # Build map of resource -> latest evidence record
        res_ev_map: Dict[str, EvidenceRecord] = {}
        for r in ev_records:
            if r.resource_id not in res_ev_map:
                res_ev_map[r.resource_id] = r
            else:
                existing = res_ev_map[r.resource_id]
                if r.captured_at > existing.captured_at:
                    res_ev_map[r.resource_id] = r
                elif r.captured_at == existing.captured_at:
                    if r.data_category == "SUPPORT_ATTACHMENT" or r.observed_state in ("ACTIVE", "PRESENT"):
                        res_ev_map[r.resource_id] = r

        # Evaluate each service's resources
        for sys_id, res_set in sorted(resources_by_service.items()):
            for res_id in sorted(res_set):
                ev = res_ev_map.get(res_id)
                cite_ev = ev.file_id if ev else evidence_file_id

                # A. DATA FLOW / CONNECTOR
                if sys_id == "integration_service" or "data_flow" in res_id:
                    # Check activity and evidence
                    is_active = False
                    if ev and ev.observed_state == "ACTIVE":
                        is_active = True
                    else:
                        for a in user_acts:
                            if a["resource_id"] == res_id and "remains enabled" in a["details"]:
                                is_active = True

                    if is_active:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": "integration_service",
                            "resource_id": res_id,
                            "operation": "REPORT_ACTIVE_DATA_FLOW",
                            "state": "ACTIVE",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": "integration_service",
                            "resource_id": res_id,
                            "operation": "DISABLE_DATA_FLOW",
                            "state": "DISABLED",
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "integration_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_DATA_FLOW_DISABLED",
                            "state": "DISABLED",
                            "evidence_id": "",
                        })
                    else:
                        # Compliant data flow disabled
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "integration_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_DATA_FLOW_DISABLED",
                            "state": "DISABLED",
                            "evidence_id": cite_ev,
                        })

                # B. BACKUP RESTORE RISK
                elif sys_id == "backup_service" or "backup_" in res_id:
                    is_risk = False
                    if ev and ev.observed_state == "ACTIVE":
                        is_risk = True
                    else:
                        for a in user_acts:
                            if a["resource_id"] == res_id and a["event_type"] == "CHECK_RESTORE_ACCESS" and a["reported_result"] == "SUCCESS":
                                is_risk = True

                    if is_risk:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": "backup_service",
                            "resource_id": res_id,
                            "operation": "REPORT_RESTORE_RISK",
                            "state": "ACTIVE",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": "backup_service",
                            "resource_id": res_id,
                            "operation": "BLOCK_RESTORE",
                            "state": "BLOCKED",
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "backup_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_RESTORE_BLOCKED",
                            "state": "BLOCKED",
                            "evidence_id": "",
                        })
                    else:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "backup_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_RESTORE_BLOCKED",
                            "state": "BLOCKED",
                            "evidence_id": cite_ev,
                        })

                # C. SECURITY AUDIT RECORD (Rule 12: RETAIN)
                elif sys_id == "security_service" or "audit_record_" in res_id:
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": "security_service",
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_PRESENT",
                        "state": "PRESENT",
                        "evidence_id": cite_ev,
                    })

                # D. ACCOUNT TOMBSTONE (Rule 15: REDACT)
                elif sys_id == "identity_service" or "tombstone_" in res_id:
                    is_exposed = False
                    if ev and ev.observed_state == "PRESENT":
                        is_exposed = True

                    if is_exposed:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": "identity_service",
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": "identity_service",
                            "resource_id": res_id,
                            "operation": "REDACT_RECORD",
                            "state": "REDACTED",
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "identity_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": "",
                        })
                    else:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "identity_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": cite_ev,
                        })

                # E. ANALYTICS PROFILE (Rule 07: ANONYMIZE)
                elif sys_id == "analytics_platform" or "analytics_" in res_id:
                    is_exposed = False
                    if ev and ev.observed_state == "PRESENT":
                        is_exposed = True
                    else:
                        for a in user_acts:
                            if a["resource_id"] == res_id and a["reported_result"] == "FAILED":
                                is_exposed = True

                    if is_exposed:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": "analytics_platform",
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": "analytics_platform",
                            "resource_id": res_id,
                            "operation": "ANONYMIZE_RECORD",
                            "state": "ANONYMIZED",
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "analytics_platform",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED",
                            "state": "ANONYMIZED",
                            "evidence_id": "",
                        })
                    else:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "analytics_platform",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED",
                            "state": "ANONYMIZED",
                            "evidence_id": cite_ev,
                        })

                # F. SUPPORT PLATFORM (Rule 05: REDACT message / Rule 06: DELETE attachment)
                elif sys_id == "support_platform" or "support_" in res_id:
                    is_attachment = False
                    for r in ev_records:
                        if r.resource_id == res_id and (r.data_category == "SUPPORT_ATTACHMENT" or "marker_found=false" in r.details):
                            is_attachment = True
                            break
                    is_present = False
                    if ev:
                        is_present = (ev.observed_state == "PRESENT")
                    else:
                        for a in user_acts:
                            if a["resource_id"] == res_id and a["reported_result"] == "FAILED":
                                is_present = True

                    if is_present:
                        is_incomplete = True
                        op_finding = "REPORT_REMAINING_RECORD" if is_attachment else "REPORT_EXPOSED_PII"
                        op_remed = "DELETE_RECORD" if is_attachment else "REDACT_RECORD"
                        state_remed = "ABSENT" if is_attachment else "REDACTED"
                        op_verif = "VERIFY_RECORD_ABSENT" if is_attachment else "VERIFY_RECORD_REDACTED"

                        findings.append({
                            "phase": "FINDING",
                            "system_id": "support_platform",
                            "resource_id": res_id,
                            "operation": op_finding,
                            "state": "PRESENT",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": "support_platform",
                            "resource_id": res_id,
                            "operation": op_remed,
                            "state": state_remed,
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "support_platform",
                            "resource_id": res_id,
                            "operation": op_verif,
                            "state": state_remed,
                            "evidence_id": "",
                        })
                    else:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "support_platform",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": cite_ev,
                        })

                # G. SEARCH SERVICE, EXPORT SERVICE, SECONDARY (Rule: DELETE)
                elif sys_id in ("search_service", "export_service") or "search_" in res_id or "export_" in res_id:
                    is_present = False
                    if ev:
                        is_present = (ev.observed_state == "PRESENT")
                    else:
                        for a in user_acts:
                            if a["resource_id"] == res_id and a["reported_result"] == "FAILED":
                                is_present = True

                    if is_present:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD",
                            "state": "PRESENT",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "DELETE_RECORD",
                            "state": "ABSENT",
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": "",
                        })
                    else:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": cite_ev,
                        })

                # H. ACCOUNT SERVICE (Primary Profile)
                elif sys_id == "account_service" or "account_" in res_id:
                    is_present = False
                    # Check replica drift or evidence
                    if ev and ev.observed_state == "PRESENT":
                        is_present = True
                    else:
                        # Check if sync job copied back to replica after deletion
                        for a in user_acts:
                            if a["resource_id"] == res_id and a["event_type"] == "SYNC_RECORD" and a["reported_result"] == "SUCCESS":
                                is_present = True

                    if is_present:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": "account_service",
                            "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD",
                            "state": "PRESENT",
                            "evidence_id": cite_ev,
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": "account_service",
                            "resource_id": res_id,
                            "operation": "DELETE_RECORD",
                            "state": "ABSENT",
                            "evidence_id": "",
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "account_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": "",
                        })
                    else:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": "account_service",
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": cite_ev,
                        })

        final_status = "INCOMPLETE" if is_incomplete else "COMPLETE"

        # Final step collection based on status
        if final_status == "COMPLETE":
            # COMPLETE cases only output VERIFICATION steps with valid evidence citations
            raw_steps = verifications
            for s in raw_steps:
                if not s.get("evidence_id"):
                    s["evidence_id"] = evidence_file_id or self.get_fallback_evidence_id(audit_at)
        else:
            # INCOMPLETE cases output:
            # 1. Findings (with valid evidence_id)
            # 2. Remediation (with evidence_id "")
            # 3. Post-remediation Verification (with evidence_id "")
            raw_steps = []
            raw_steps.extend(findings)
            raw_steps.extend(remediations)
            for v in verifications:
                v_copy = dict(v)
                v_copy["evidence_id"] = ""
                raw_steps.append(v_copy)

        # De-duplicate raw_steps by (phase, system_id, resource_id, operation)
        unique_steps = []
        step_keys_seen = set()
        for s in raw_steps:
            k = (s["phase"], s["system_id"], s["resource_id"], s["operation"])
            if k not in step_keys_seen:
                step_keys_seen.add(k)
                unique_steps.append(s)

        # Sort strictly by (phase_order, op_order, system_id, resource_id) and renumber
        sorted_steps = sorted(unique_steps, key=get_step_sort_key)
        final_steps = []
        for idx, s in enumerate(sorted_steps, start=1):
            s_dict = dict(s)
            s_dict["step_no"] = idx
            final_steps.append(s_dict)

        return final_status, final_steps
