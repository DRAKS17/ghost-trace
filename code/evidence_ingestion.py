"""
GhostTrace Multi-Modal Evidence Ingestion Engine
HackerRank Orchestrate October 2026 | Ghost Data Still Exists

Parses all 94 evidence files across 5 distinct modalities:
- SQL Snapshots (SQLite in-memory execution)
- JSON Snapshot Bundles & Service Resource Exports
- Structured & Observability Log Streams
- PDF Documents (pypdf text extraction)
- PNG Admin Screenshots (winocr native OCR)

Builds a standardized Evidence Index and persists a cache for rapid querying.
"""

import asyncio
import csv
import glob
import json
import os
import re
import sqlite3
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    from PIL import Image
    import winocr
except ImportError:
    winocr = None

# Ensure current and parent directories are in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
for p in (current_dir, parent_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from code.identity_resolver import IdentityResolver
except (ImportError, ModuleNotFoundError):
    from identity_resolver import IdentityResolver


@dataclass
class EvidenceRecord:
    file_id: str
    captured_at: str
    origin: str
    system_id: str
    resource_id: str
    data_category: str
    observed_state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    details: str = ""


class EvidenceIngestionEngine:
    def __init__(self, dataset_dir: str = "dataset", cache_file: str = "code/evidence_cache.json"):
        self.dataset_dir = dataset_dir
        self.cache_file = cache_file
        self.evidence_files: Dict[str, Dict[str, str]] = {}
        self.records: List[EvidenceRecord] = []
        self.records_by_resource: Dict[str, List[EvidenceRecord]] = {}
        self.records_by_user_id: Dict[str, List[EvidenceRecord]] = {}
        self.records_by_email: Dict[str, List[EvidenceRecord]] = {}
        self.identity_resolver = IdentityResolver(dataset_dir)

    def load_manifest(self):
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        if not os.path.isfile(manifest_path):
            return
        with open(manifest_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                self.evidence_files[r["file_id"]] = {
                    "file_id": r["file_id"],
                    "file_path": os.path.join(self.dataset_dir, r["file_path"].replace("/", os.sep)),
                    "origin": r["origin"],
                    "captured_at": r["captured_at"],
                }

    def index_record(self, record: EvidenceRecord):
        self.records.append(record)
        if record.resource_id:
            self.records_by_resource.setdefault(record.resource_id, []).append(record)
        if record.user_id:
            self.records_by_user_id.setdefault(record.user_id, []).append(record)
        if record.email:
            self.records_by_email.setdefault(record.email.lower(), []).append(record)

    def parse_sql(self, file_id: str, path: str, captured_at: str, origin: str):
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                sql_script = f.read()
            conn = sqlite3.connect(":memory:")
            conn.executescript(sql_script)

            cursor = conn.cursor()
            tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

            for tbl in tables:
                col_info = cursor.execute(f"PRAGMA table_info({tbl})").fetchall()
                cols = [c[1] for c in col_info]
                rows = cursor.execute(f"SELECT * FROM {tbl}").fetchall()

                for row in rows:
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get("resource_id", "")
                    if not res_id:
                        continue

                    uid = row_dict.get("user_id") or row_dict.get("customer_reference") or row_dict.get("subject_reference") or row_dict.get("subject_ref") or row_dict.get("customer_ref")
                    email = row_dict.get("email") or row_dict.get("owner_email") or row_dict.get("requester_email") or row_dict.get("customer_email")
                    phone = row_dict.get("phone") or row_dict.get("owner_phone") or row_dict.get("requester_phone")
                    email_hash = row_dict.get("email_hash") or row_dict.get("hash")
                    record_json = row_dict.get("record_json")

                    if record_json:
                        try:
                            parsed_json = json.loads(record_json)
                            uid = uid or parsed_json.get("user_id") or parsed_json.get("customer_reference") or parsed_json.get("subject_reference")
                            email = email or parsed_json.get("email") or parsed_json.get("owner_email") or parsed_json.get("customer_email")
                            phone = phone or parsed_json.get("phone")
                            email_hash = email_hash or parsed_json.get("email_hash")
                        except Exception:
                            pass

                    if email_hash and not uid and self.identity_resolver and str(email_hash) in self.identity_resolver.email_hash_to_user_id:
                        uid = self.identity_resolver.email_hash_to_user_id[str(email_hash)]

                    # Determine system and state
                    system_id = "account_service"
                    state = "PRESENT"
                    cat = "USER_PROFILE"

                    if "search" in tbl or "search" in res_id:
                        system_id = "search_service"
                        cat = "SEARCH_INDEX_ENTRY"
                    elif "analytics" in tbl or "analytics" in res_id:
                        system_id = "analytics_platform"
                        cat = "ANALYTICS_PROFILE"
                        state = "ANONYMIZED" if (not email and not phone and not uid) else "PRESENT"
                    elif "support" in tbl or "support" in res_id:
                        system_id = "support_platform"
                        cat = "SUPPORT_MESSAGE"
                        state = "REDACTED" if (not email and not phone) else "PRESENT"
                    elif "export" in tbl or "export" in res_id:
                        system_id = "export_service"
                        cat = "USER_EXPORT"
                    elif "backup" in tbl or "backup" in res_id:
                        system_id = "backup_service"
                        cat = "BACKUP_ARCHIVE"
                        restore_allowed = row_dict.get("restore_allowed", 1)
                        state = "ACTIVE" if restore_allowed in (1, "1", True) else "BLOCKED"
                    elif "connector" in tbl or "data_flow" in res_id:
                        system_id = "integration_service"
                        cat = "DATA_FLOW"
                        enabled = row_dict.get("enabled", 1)
                        state = "ACTIVE" if enabled in (1, "1", True) else "DISABLED"
                    elif "audit" in tbl or "audit_record" in res_id:
                        system_id = "security_service"
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif "tombstone" in tbl or "tombstone" in res_id:
                        system_id = "identity_service"
                        cat = "ACCOUNT_TOMBSTONE"
                        state = "REDACTED" if (not email and not phone) else "PRESENT"

                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=system_id,
                            resource_id=res_id,
                            data_category=cat,
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            phone=str(phone) if phone else None,
                            details=f"SQL table {tbl} in {path}",
                        )
                    )
            conn.close()
        except Exception as e:
            pass

    def parse_json(self, file_id: str, path: str, captured_at: str, origin: str):
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            # 1. Snapshot bundle format
            if isinstance(data, dict) and "snapshots" in data:
                for s in data["snapshots"]:
                    store = s.get("data_store", "account_service")
                    collection = s.get("collection", "")
                    for rec in s.get("records", []):
                        res_id = rec.get("resource_id", "")
                        uid = rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id")
                        email = rec.get("email")
                        phone = rec.get("phone")
                        email_hash = rec.get("email_hash")
                        if email_hash and not uid and self.identity_resolver and str(email_hash) in self.identity_resolver.email_hash_to_user_id:
                            uid = self.identity_resolver.email_hash_to_user_id[str(email_hash)]

                        state = "PRESENT"
                        cat = "USER_PROFILE"
                        if "deleted" in collection or "tombstone" in res_id:
                            store = "identity_service"
                            cat = "ACCOUNT_TOMBSTONE"
                            state = "REDACTED" if (not email and not phone) else "PRESENT"
                        elif "audit" in collection or "audit_record" in res_id:
                            store = "security_service"
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"

                        self.index_record(
                            EvidenceRecord(
                                file_id=file_id,
                                captured_at=captured_at,
                                origin=origin,
                                system_id=store,
                                resource_id=res_id,
                                data_category=cat,
                                observed_state=state,
                                user_id=str(uid) if uid else None,
                                email=str(email).lower() if email else None,
                                phone=str(phone) if phone else None,
                                details=f"Snapshot bundle collection {collection}",
                            )
                        )

            # 2. Direct collection records format (e.g. evidence_56, evidence_59, connector configs)
            elif isinstance(data, dict) and "records" in data:
                collection = data.get("collection", "")
                source = data.get("source", "")
                for rec in data["records"]:
                    res_id = rec.get("resource_id", "")
                    uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                    email = rec.get("email") or rec.get("owner_email") or rec.get("requester_email") or rec.get("customer_email")
                    phone = rec.get("phone") or rec.get("owner_phone") or rec.get("requester_phone")
                    email_hash = rec.get("email_hash")
                    if email_hash and not uid and self.identity_resolver and str(email_hash) in self.identity_resolver.email_hash_to_user_id:
                        uid = self.identity_resolver.email_hash_to_user_id[str(email_hash)]

                    system_id = "account_service"
                    cat = "USER_PROFILE"
                    state = "PRESENT"

                    if "analytics" in collection or "analytics" in res_id:
                        system_id = "analytics_platform"
                        cat = "ANALYTICS_PROFILE"
                        state = "ANONYMIZED" if (not email and not phone and not uid) else "PRESENT"
                    elif "export" in collection or "export" in res_id:
                        system_id = "export_service"
                        cat = "USER_EXPORT"
                        state = "PRESENT"
                    elif "connector" in collection or "data_flow" in res_id:
                        system_id = "integration_service"
                        cat = "DATA_FLOW"
                        enabled = rec.get("enabled", True)
                        state = "ACTIVE" if enabled else "DISABLED"
                    elif "support" in collection or "support" in res_id:
                        system_id = "support_platform"
                        cat = "SUPPORT_MESSAGE"
                        state = "REDACTED" if (not email and not phone) else "PRESENT"

                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=system_id,
                            resource_id=res_id,
                            data_category=cat,
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            phone=str(phone) if phone else None,
                            details=f"Direct collection {collection} in {source}",
                        )
                    )

            # 3. Service resource export format (e.g. evidence_92)
            elif isinstance(data, dict) and "service_exports" in data:
                se = data["service_exports"]
                # account_service
                for p in se.get("account_service", {}).get("profile_lookups", []):
                    res_id = p.get("resource_id")
                    status_code = p.get("status_code")
                    state = "ABSENT" if status_code == 404 else "PRESENT"
                    prof = p.get("profile", {}) or {}
                    uid = prof.get("customer_reference") or prof.get("user_id")
                    email = prof.get("email")
                    phone = prof.get("phone")
                    email_hash = prof.get("email_hash")
                    if email_hash and not uid and self.identity_resolver and str(email_hash) in self.identity_resolver.email_hash_to_user_id:
                        uid = self.identity_resolver.email_hash_to_user_id[str(email_hash)]
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="account_service",
                            resource_id=res_id,
                            data_category="USER_PROFILE",
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            phone=str(phone) if phone else None,
                            details=f"Profile lookup status_code={status_code}",
                        )
                    )
                # analytics_platform
                for p in se.get("analytics_platform", {}).get("profiles", []):
                    res_id = p.get("resource_id")
                    email = p.get("email")
                    uid = p.get("customer_reference")
                    state = "PRESENT" if (email or uid) else "ANONYMIZED"
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="analytics_platform",
                            resource_id=res_id,
                            data_category="ANALYTICS_PROFILE",
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            details="Analytics export profile",
                        )
                    )
                # backup_service
                for b in se.get("backup_service", {}).get("restore_entries", []):
                    res_id = b.get("resource_id")
                    uid = b.get("customer_reference")
                    email = b.get("customer_email")
                    allowed = b.get("restore_allowed", False)
                    state = "ACTIVE" if allowed else "BLOCKED"
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="backup_service",
                            resource_id=res_id,
                            data_category="BACKUP_ARCHIVE",
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            details=f"Backup restore_allowed={allowed}",
                        )
                    )
                # integration_service
                for c in se.get("integration_service", {}).get("connectors", []):
                    res_id = c.get("resource_id")
                    uid = c.get("customer_reference")
                    email = c.get("customer_email")
                    enabled = c.get("enabled", False)
                    state = "ACTIVE" if enabled else "DISABLED"
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="integration_service",
                            resource_id=res_id,
                            data_category="DATA_FLOW",
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            details=f"Connector enabled={enabled}",
                        )
                    )
                # search_service
                for q in se.get("search_service", {}).get("index_queries", []):
                    res_id = q.get("resource_id")
                    hits = q.get("hits", {})
                    total = hits.get("total", 0)
                    email = q.get("query")
                    docs = hits.get("documents", [])
                    if docs:
                        email = docs[0].get("email") or email
                    state = "PRESENT" if total > 0 else "ABSENT"
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="search_service",
                            resource_id=res_id,
                            data_category="SEARCH_INDEX_ENTRY",
                            observed_state=state,
                            email=str(email).lower() if email else None,
                            details=f"Search index_query total_hits={total}",
                        )
                    )
                # security_service
                for a in se.get("security_service", {}).get("audit_records", []):
                    res_id = a.get("resource_id")
                    uid = a.get("subject_reference")
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="security_service",
                            resource_id=res_id,
                            data_category="SECURITY_AUDIT_LOG",
                            observed_state="PRESENT",
                            user_id=str(uid) if uid else None,
                            details="Security audit record",
                        )
                    )
                # support_platform
                for t in se.get("support_platform", {}).get("tickets", []):
                    res_id = t.get("resource_id")
                    uid = t.get("customer_reference")
                    email = t.get("requester_email")
                    state = "PRESENT" if email else "REDACTED"
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="support_platform",
                            resource_id=res_id,
                            data_category="SUPPORT_MESSAGE",
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            details="Support ticket export",
                        )
                    )
                # export_service
                for ex in se.get("export_service", {}).get("exports", []):
                    res_id = ex.get("resource_id")
                    email = ex.get("owner_email")
                    uid = ex.get("customer_reference")
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="export_service",
                            resource_id=res_id,
                            data_category="USER_EXPORT",
                            observed_state="PRESENT",
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            details="User export file",
                        )
                    )
        except Exception as e:
            pass

    def parse_txt(self, file_id: str, path: str, captured_at: str, origin: str):
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("- "):
                        continue
                    parts = [p.strip() for p in line[2:].split("|")]
                    if len(parts) >= 6:
                        ts, sys_id, res_id, cat, status, ident = parts[:6]
                        uid = ident if ident.startswith("user_") else None
                        email = ident.lower() if "@" in ident else None

                        state = "PRESENT"
                        if status == "NOT_FOUND":
                            state = "ABSENT"
                        elif status in ("ANONYMIZED", "REDACTED"):
                            state = status
                        elif status == "FOUND" or status == "IDENTIFIABLE":
                            state = "PRESENT"
                        elif status == "ACTIVE":
                            state = "ACTIVE"
                        elif status == "BLOCKED":
                            state = "BLOCKED"
                        elif status == "DISABLED":
                            state = "DISABLED"

                        self.index_record(
                            EvidenceRecord(
                                file_id=file_id,
                                captured_at=captured_at,
                                origin=origin,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category=cat,
                                observed_state=state,
                                user_id=uid,
                                email=email,
                                details=f"Handover line status={status}",
                            )
                        )
        except Exception as e:
            pass

    def parse_log(self, file_id: str, path: str, captured_at: str, origin: str):
        if not os.path.isfile(path):
            return
        try:
            # First pass: collect trace context (lookup_key, correlation_key, etc.)
            traces: Dict[str, Dict[str, Any]] = {}
            lines_parsed = []

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue

                    # Handle JSON log lines (which may start with timestamp e.g. "2026-09-16T08:52:59Z {json}")
                    if "{" in line_str and line_str.endswith("}"):
                        try:
                            json_str = line_str[line_str.index("{"):]
                            kv = json.loads(json_str)
                        except Exception:
                            kv = {}
                    else:
                        tokens = line_str.split()
                        kv = {}
                        for tok in tokens:
                            if "=" in tok:
                                k, v = tok.split("=", 1)
                                kv[k] = v.strip('"')

                    tid = kv.get("trace_id")
                    if tid:
                        t_data = traces.setdefault(tid, {})
                        for key in ("lookup_key", "match_key", "matched_value", "subject_key", "correlation_key", "subject_reference", "subject_ref", "customer_reference", "customer_ref", "email", "requester_email", "customer_email"):
                            if key in kv and kv[key]:
                                val = kv[key].strip('"')
                                t_data[key] = val
                                if self.identity_resolver and val in self.identity_resolver.email_hash_to_user_id:
                                    t_data["subject_reference"] = self.identity_resolver.email_hash_to_user_id[val]
                    lines_parsed.append(kv)

            # Second pass: process completed/scan events
            for kv in lines_parsed:
                res_id = kv.get("resource_id")
                if not res_id:
                    continue
                event = kv.get("event", "")
                if event.endswith("_started") or event.startswith("export_"):
                    continue
                service = kv.get("service", "") or kv.get("logger", "")
                tid = kv.get("trace_id")
                t_ctx = traces.get(tid, {}) if tid else {}

                # Resolve identifiers
                uid = kv.get("subject_reference") or kv.get("subject_ref") or kv.get("customer_reference") or kv.get("customer_ref") or t_ctx.get("subject_reference") or t_ctx.get("subject_ref") or t_ctx.get("customer_reference") or t_ctx.get("customer_ref")
                email = kv.get("email") or kv.get("requester_email") or kv.get("customer_email") or kv.get("matched_value") or kv.get("lookup_key") or kv.get("subject_key") or t_ctx.get("email") or t_ctx.get("lookup_key") or t_ctx.get("subject_key") or t_ctx.get("matched_value")
                corr_key = kv.get("correlation_key") or t_ctx.get("correlation_key")

                if corr_key:
                    corr_str = str(corr_key).strip('"')
                    if corr_str.startswith("user_"):
                        uid = uid or corr_str
                    elif "@" in corr_str:
                        email = email or corr_str
                    elif self.identity_resolver and corr_str in self.identity_resolver.email_hash_to_user_id:
                        uid = uid or self.identity_resolver.email_hash_to_user_id[corr_str]

                if uid and not email and self.identity_resolver and uid in self.identity_resolver.profiles_by_user_id:
                    email = self.identity_resolver.profiles_by_user_id[uid].current_email

                if email and "@" not in str(email):
                    if str(email).startswith("user_"):
                        uid = uid or str(email)
                    email = None

                state = "PRESENT"
                cat = "USER_PROFILE"

                if "profile_lookup_completed" in event:
                    service = "account_service"
                    cat = "USER_PROFILE"
                    state = "ABSENT" if str(kv.get("http_status")) == "404" or str(kv.get("rows")) == "0" else "PRESENT"
                elif "index_query_completed" in event or "index_query" in event:
                    service = "search_service"
                    cat = "SEARCH_INDEX_ENTRY"
                    state = "PRESENT" if kv.get("result") == "hit" or str(kv.get("total_hits", 0)) not in ("0", 0) else "ABSENT"
                elif "message_pii_scan" in event or "support_ticket_read_completed" in event or "support_ticket" in event or "contact_query_completed" in event or "deletion_marker_check" in event or "support" in service:
                    service = "support_platform"
                    cat = "SUPPORT_MESSAGE"
                    if "support_" in res_id:
                        cat = "SUPPORT_MESSAGE" if "message" in event or "ticket" in event or "contact" in event else "SUPPORT_ATTACHMENT"
                    state = "PRESENT" if (email or kv.get("matched_value") or kv.get("rows") == "1" or kv.get("marker_found") == "false") else "REDACTED"
                elif "connector_config_read_completed" in event or "connector_heartbeat" in event or "connector" in event:
                    service = "integration_service"
                    cat = "DATA_FLOW"
                    state = "ACTIVE" if str(kv.get("enabled")).lower() == "true" or kv.get("enabled") is True else "DISABLED"
                elif "restore_policy_read_completed" in event or "restore_candidate_evaluated" in event or "restore_policy" in event:
                    service = "backup_service"
                    cat = "BACKUP_ARCHIVE"
                    state = "ACTIVE" if str(kv.get("restore_allowed")).lower() == "true" or str(kv.get("deletion_block")).lower() == "false" or str(kv.get("eligible")).lower() == "true" else "BLOCKED"
                elif "audit_record_read_completed" in event or "audit_record" in event:
                    service = "security_service"
                    cat = "SECURITY_AUDIT_LOG"
                    state = "PRESENT"
                elif "analytics_profile_read_completed" in event or "contact_lookup_completed" in event or "analytics" in service:
                    service = "analytics_platform"
                    cat = "ANALYTICS_PROFILE"
                    has_id = bool(email or (corr_key and not str(corr_key).startswith("null") and str(corr_key) != "null") or (kv.get("email") and kv.get("email") != "null"))
                    state = "PRESENT" if has_id else "ANONYMIZED"
                else:
                    continue

                if service and res_id:
                    self.index_record(
                        EvidenceRecord(
                            file_id=file_id,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=service,
                            resource_id=res_id,
                            data_category=cat,
                            observed_state=state,
                            user_id=str(uid) if uid else None,
                            email=str(email).lower() if email else None,
                            details=f"Log event {event} (corr_key={corr_key})",
                        )
                    )
        except Exception as e:
            pass

    def parse_pdf(self, file_id: str, path: str, captured_at: str, origin: str):
        if not pypdf or not os.path.isfile(path):
            return
        try:
            reader = pypdf.PdfReader(path)
            full_text = " ".join(p.extract_text() or "" for p in reader.pages)

            # Extract user_ids
            uids = re.findall(r"user_\d+", full_text)
            # Extract emails
            emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", full_text)
            # Extract support references
            res_matches = re.findall(r"(support_\d+|account_\d+|audit_record_\d+)", full_text)

            res_id = res_matches[0] if res_matches else f"doc_{file_id}"
            uid = uids[0] if uids else None
            email = emails[0].lower() if emails else None

            system_id = "support_platform" if "support_" in res_id else "security_service"
            cat = "SUPPORT_ATTACHMENT" if "support_" in res_id else "SECURITY_AUDIT_LOG"

            self.index_record(
                EvidenceRecord(
                    file_id=file_id,
                    captured_at=captured_at,
                    origin=origin,
                    system_id=system_id,
                    resource_id=res_id,
                    data_category=cat,
                    observed_state="PRESENT",
                    user_id=uid,
                    email=email,
                    details=f"PDF document: {os.path.basename(path)}",
                )
            )
        except Exception as e:
            pass

    async def parse_png_async(self, file_id: str, path: str, captured_at: str, origin: str):
        if not winocr or not os.path.isfile(path):
            return
        try:
            img = Image.open(path)
            result = await winocr.recognize_pil(img, lang="en")
            text = result.text

            uids = re.findall(r"user_\d+", text)
            emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text)
            res_matches = re.findall(r"(account_\d+|support_\d+|search_\d+|analytics_\d+|backup_\d+|data_flow_\d+|audit_record_\d+|tombstone_\d+)", text)

            uid = uids[0] if uids else None
            email = emails[0].lower() if emails else None
            res_id = res_matches[0] if res_matches else None

            if res_id:
                sys_id = "account_service"
                cat = "USER_PROFILE"
                if "search" in res_id:
                    sys_id = "search_service"
                    cat = "SEARCH_INDEX_ENTRY"
                elif "analytics" in res_id:
                    sys_id = "analytics_platform"
                    cat = "ANALYTICS_PROFILE"
                elif "support" in res_id:
                    sys_id = "support_platform"
                    cat = "SUPPORT_MESSAGE"
                elif "backup" in res_id:
                    sys_id = "backup_service"
                    cat = "BACKUP_ARCHIVE"
                elif "data_flow" in res_id:
                    sys_id = "integration_service"
                    cat = "DATA_FLOW"
                elif "audit" in res_id:
                    sys_id = "security_service"
                    cat = "SECURITY_AUDIT_LOG"

                self.index_record(
                    EvidenceRecord(
                        file_id=file_id,
                        captured_at=captured_at,
                        origin=origin,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category=cat,
                        observed_state="PRESENT",
                        user_id=uid,
                        email=email,
                        details=f"Image OCR: {os.path.basename(path)}",
                    )
                )
        except Exception as e:
            pass

    def ingest_all(self, force_refresh: bool = False):
        if not force_refresh and os.path.isfile(self.cache_file):
            self.load_cache()
            return

        self.load_manifest()

        # Ingest text, sql, json, logs, pdfs
        png_tasks = []
        for file_id, meta in self.evidence_files.items():
            path = meta["file_path"]
            captured_at = meta["captured_at"]
            origin = meta["origin"]
            ext = os.path.splitext(path)[1].lower()

            if ext == ".sql":
                self.parse_sql(file_id, path, captured_at, origin)
            elif ext == ".json":
                self.parse_json(file_id, path, captured_at, origin)
            elif ext == ".log":
                self.parse_log(file_id, path, captured_at, origin)
            elif ext == ".txt":
                self.parse_txt(file_id, path, captured_at, origin)
            elif ext == ".pdf":
                self.parse_pdf(file_id, path, captured_at, origin)
            elif ext == ".png":
                png_tasks.append((file_id, path, captured_at, origin))

        # Process PNGs asynchronously if winocr is available
        if png_tasks and winocr:
            async def run_all_pngs():
                tasks = [self.parse_png_async(f, p, c, o) for f, p, c, o in png_tasks]
                await asyncio.gather(*tasks)
            try:
                asyncio.run(run_all_pngs())
            except Exception:
                pass

        self.save_cache()

    def save_cache(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.cache_file)), exist_ok=True)
        data = [asdict(r) for r in self.records]
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def load_cache(self):
        with open(self.cache_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
            for item in raw:
                r = EvidenceRecord(**item)
                self.index_record(r)
