# GhostTrace — Submission Verification Checklist
**HackerRank Orchestrate October 2026 | Ghost Data Still Exists**

Use this checklist to verify all deliverables before uploading to HackerRank.

---

## 1. File Deliverables Verification

- [x] **`output.csv` (Repository Root)**
  - Path: `ghost-trace/output.csv`
  - Total Lines: Exactly 519 lines (1 header + 518 data rows).
  - Header: `case_id,deletion_status,steps_json`
  - Valid Statuses: Only `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`.
  - Sorted Order: Sorted alphabetically/numerically by `case_id`.
  - JSON Schema: 100% valid JSON array; each step has 7 keys (`step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
  - Evidence Citations: Non-empty valid manifest `file_id` for all `FINDING` steps and `COMPLETE` verification steps; empty string `""` for all proposed `REMEDIATION` actions.

- [x] **`code.zip` (Submission Archive)**
  - Path: `ghost-trace/code.zip`
  - Includes: `README.md`, `code/`, `code/evaluation/evaluation_report.md`, `code/evaluation/usage_report.md`, `code/evaluation/main.py`, `code/evaluation/test_synthetic_fixtures.py`.
  - Excludes: `dataset/`, `.venv/`, `venv/`, `__pycache__/`, `.git/`, and any nested archives (`.zip`, `.tar.gz`).
  - Size: Under 2 MB.

- [x] **`log.txt` / `chat_transcript` (Agent Conversation Trace)**
  - Path: `ghost-trace/log.txt`
  - Format: Strictly adheres to `AGENTS.md` §5.1 Session Start & §5.2 Turn Format.
  - Required Fields: `User Prompt`, `Agent Response Summary`, `Actions`, `Context`.
  - Tool and Model: `tool=Antigravity`, `model=Gemini 3.8 Flash (High)`.
  - Secrets Audit: No API keys, passwords, or personal credentials present.

---

## 2. Command-Line Reproduction Verification (Windows PowerShell)

Run these commands in PowerShell to verify clean local execution:

```powershell
# 1. Verify schema and 518 row count on output.csv
python code/evaluation/main.py --pred output.csv --expected-count 518

# 2. Run unit tests on synthetic failure modes
python code/evaluation/test_synthetic_fixtures.py

# 3. Evaluate 32 sample cases against ground truth
python code/main.py --input dataset/sample_deletion_requests.csv --output code/sample_cli_output.csv
python code/evaluation/main.py --pred code/sample_cli_output.csv --truth dataset/sample_output.csv

# 4. Re-generate full predictions
python code/main.py --input dataset/deletion_requests.csv --output output.csv
```

---

## 3. HackerRank Portal Upload Guide

1. Navigate to: [HackerRank Ghost Data Still Exists Challenge](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
2. **Upload `output.csv`**: In the file upload field for Predictions / Output.
3. **Upload `code.zip`**: In the Code Submission field.
4. **Upload `log.txt`**: In the Chat Transcript field.
5. Click **Submit** and prepare for the AI Judge interview using `code/AI_JUDGE_PREP.md`.
