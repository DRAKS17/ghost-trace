# GhostTrace — AI Judge Interview Preparation Guide
**HackerRank Orchestrate October 2026 | Ghost Data Still Exists**

This guide breaks down every technical decision, architecture component, and forensic mechanism in **simple, clear language** so you can speak with authority, clarity, and deep understanding during your live AI Judge interview.

---

## 1. 30-Second Elevator Pitch

> *"GhostTrace is an evidence-first deletion forensic engine designed to verify whether customer personal data was truly deleted across distributed enterprise systems. In distributed architectures, deletion workflows often report 'Success' even when ghost data lingers in database replicas, analytics streams, or support tickets, or can be resurrected by active synchronization connectors. GhostTrace links current and historical identities (including SHA-256 email hashes), audits 94 multi-modal evidence files with strict point-in-time isolation, and generates deterministically ordered, evidence-backed findings, remediations, and verification steps."*

---

## 2. Core Architecture: How It Works

GhostTrace consists of four key components working together:

```
[ Deletion Request ]
         │
         ▼
[ 1. Authorization & Multilingual Classifier ] ──► If not deletion ──► NOT_APPLICABLE
         │
         ▼ (Authorized Deletion)
[ 2. Historical Identity Resolver ]
   - Tracks current & historical emails, phones, names
   - Ingests SHA-256 email hashes from audit logs
         │
         ▼
[ 3. Multi-Modal Evidence Ingestion & Cache ]
   - 24 SQL database dumps (in-memory SQLite)
   - 28 JSON snapshots & service resource exports
   - 26 Log files (two-pass trace correlation)
   - 4 PDF attachments (pypdf)
   - 11 PNG screenshots (Windows Native WinRT OCR)
         │
         ▼
[ 4. Temporal Policy & Forensic Engine ]
   - Time-travel isolation: strictly captured_at <= audit_at
   - Applies 15 rules from deletion_rules.csv
   - Discovers ghost records, active data flows, and restore risks
         │
         ▼
[ 5. Strict Step Serializer ]
   - Phase ordering: FINDING (1) ──► REMEDIATION (2) ──► VERIFICATION (3)
   - Canonical operation hierarchy & tie-breaker sorting
   - Exact 7-key JSON schema & valid evidence citations
```

---

## 3. Top Interview Questions & Model Answers

### Q1: "Why can't you just rely on `reported_status = COMPLETE` from the deletion worker?"
**Answer:**
> *"Because reported statuses are merely claims, not proof. In distributed systems, a deletion worker might successfully delete a record from the primary account database, but replication drift can leave records in read replicas. Furthermore, background sync connectors (such as `customer_events_connector`) or backup restore procedures can repopulate downstream systems after the deletion worker finished. GhostTrace treats reported statuses with zero trust and reconstructs the ground truth from physical evidence snapshots captured at or before `audit_at`."*

### Q2: "How did you handle historical identities and email changes?"
**Answer:**
> *"When users change their email address or phone number over time, `user_audit_log.csv` records the transition along with the SHA-256 hash of the email. In many downstream logs and analytics systems (like `analytics_platform`), records are keyed by this 64-character hash rather than plain text. GhostTrace's `IdentityResolver` builds a reverse lookup map from historical hashes to user IDs. When log events or JSON exports present an email hash, GhostTrace automatically links it back to the customer's identity graph, catching lingering ghost profiles that standard email matching completely misses."*

### Q3: "How does GhostTrace prevent future-data leakage during time-travel audits?"
**Answer:**
> *"Each deletion request specifies an `audit_at` timestamp. GhostTrace enforces strict temporal isolation:
> 1. In `system_activity.csv`, any event occurring after `audit_at` is discarded (`event_time <= audit_at`).
> 2. In `evidence_files.csv`, any evidence file captured after `audit_at` is quarantined (`captured_at <= audit_at`).
> This ensures that our forensic findings reflect the exact state of the system at the audit instant, without being tainted by subsequent operations or future snapshots."*

### Q4: "How do you parse and link multi-modal evidence across SQL, JSON, logs, PDFs, and PNGs?"
**Answer:**
> *"We implemented a modular multi-modal ingestion engine:
> - **SQL Snapshots:** Executed inside an in-memory SQLite database to inspect replicas and schemas directly.
> - **JSON Snapshots & Exports:** Parsed hierarchically, handling nested `service_exports` and direct collection records.
> - **Observability Logs:** Parsed using a two-pass algorithm. The first pass correlates trace IDs with lookup keys from dispatch events; the second pass extracts terminal observations from completion events.
> - **PDFs & Images:** PDF text is extracted via `pypdf`, and admin console screenshots are read using Windows Native WinRT OCR (`winocr`), which runs offline with zero external binary overhead."*

### Q5: "What is the difference between `COMPLETE` and `INCOMPLETE` in the output schema?"
**Answer:**
> *"Under the official challenge contract:
> - **`COMPLETE`**: Personal data is verified absent or properly treated across all systems. Only `VERIFICATION` steps are emitted, and every step **must** cite a valid `evidence_id` from the evidence manifest that proves absence or redaction.
> - **`INCOMPLETE`**: Lingering records, unredacted PII, active data flows, or restore risks were detected. GhostTrace emits `FINDING` steps (citing the evidence file where the risk was observed), followed by proposed `REMEDIATION` steps (with empty string `""` as evidence ID), and post-remediation `VERIFICATION` steps (also with empty string `""`).
> - **`NOT_APPLICABLE`**: The user request was not an authorized deletion (e.g. data export or request to keep the account active). It returns an empty array `[]`."*

### Q6: "Why did you build GhostTrace as a deterministic engine rather than calling LLMs for every row?"
**Answer:**
> *"Forensic deletion compliance requires 100% reproducibility, zero hallucinations, millisecond latency, and total data privacy. By implementing the forensic rules, identity resolution, and time-travel logic in deterministic Python:
> 1. GhostTrace audits all 518 cases in just **1.2 seconds** (~2.3 ms per request).
> 2. Zero PII ever leaves the local machine.
> 3. Zero API token costs (\$0.00 runtime inference cost).
> 4. Deterministic schema compliance: exactly 0 schema errors across all 518 cases."*

---

## 4. Key Failure Modes Solved

1. **Recreation Risk via Active Sync Connectors (Rule 14):**
   - The primary account was deleted, but `integration_service` had `customer_events_connector` enabled. GhostTrace flagged `REPORT_ACTIVE_DATA_FLOW` (state: `ACTIVE`) and planned `DISABLE_DATA_FLOW`.

2. **Attachment Deletion vs. Message Redaction (Rules 05 & 06):**
   - In `support_platform`, shared conversation messages must be redacted (`REDACT_RECORD`), but customer-specific attachments (like `delivery_correction_attachment.pdf`) must be permanently deleted (`DELETE_RECORD`). GhostTrace distinguishes between messages and attachments based on evidence category and deletion marker checks.

3. **Tombstone Referential Redaction (Rule 15):**
   - When an account is deleted, an internal tombstone is retained in `identity_service` so historical security audit logs don't break foreign key constraints. GhostTrace verifies that direct identifiers (email, phone, name) are stripped (`REDACTED`) while internal IDs persist.

---

## 5. Summary of Benchmark Results

- **Sample Ground Truth Accuracy:** **100.00% Status Accuracy** (32/32 sample cases).
- **Field Accuracies:** 100% Phase, 100% System ID, 100% Resource ID, 100% Operation, 100% State, 100% Evidence ID.
- **Production Output:** Exactly 518 rows, 100% valid schema, 0 errors.
