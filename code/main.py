"""
GhostTrace — Evidence-First Deletion Forensics
HackerRank Orchestrate October 2026 | Ghost Data Still Exists

Main pipeline entry point.
Processes deletion requests, audits system state across multi-modal evidence,
resolves current and historical identities, evaluates policy treatment,
and produces strict evidence-backed remediation and verification plans.
"""

import argparse
import csv
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root and code directories are in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
for p in (current_dir, parent_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

# Import evaluation contracts and forensic engine robustly
try:
    from code.evaluation.main import ALLOWED_OPERATIONS, PHASE_ORDER, get_step_sort_key
    from code.policy_engine import ForensicPolicyEngine
except (ImportError, ModuleNotFoundError):
    from evaluation.main import ALLOWED_OPERATIONS, PHASE_ORDER, get_step_sort_key
    from policy_engine import ForensicPolicyEngine


def is_deletion_request(request_text: str) -> bool:
    """
    Determines whether the given request text authorizes personal data deletion.
    Handles English and multilingual phrasing (Portuguese, Spanish, French,
    German, Korean, Japanese).
    Returns False for requests that seek access, export, rectification, or
    explicitly request to keep the account active.
    """
    if not request_text or not isinstance(request_text, str):
        return False

    t = request_text.strip().lower()

    # Explicit non-deletion intents (access, export, update while keeping account active)
    keep_active_phrases = [
        "leave the account active",
        "leave the account as it is",
        "keep the account as it is",
        "keep the account active",
        "continue using the service",
        "continue using my account",
        "leave my profile and purchase history in place",
        "leave my profile in place",
        "do not close",
        "don't close",
        "do not delete",
        "don't delete",
        "without removing any of my records",
        "remove me from marketing lists only",
        "ne pas supprimer",
        "garder mon compte actif",
        "no eliminar",
        "mantener activa la cuenta",
        "não excluir",
        "manter a conta ativa",
        "계정을 유지",
        "서비스를 계속 이용",
        "アカウントを維持",
        "アカウントを残す",
    ]
    for phrase in keep_active_phrases:
        if phrase in t:
            return False

    # Positive deletion intent terms across supported languages
    deletion_stems = [
        "delet",
        "eras",
        "clos",
        "remov",
        "purg",
        "suppr",
        "exclu",
        "elimin",
        "borr",
        "lösch",
        "삭제",
        "削除",
        "gone",
        "left behind",
    ]

    for stem in deletion_stems:
        if stem in t:
            return True

    return False


def sort_and_renumber_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sorts steps by (Phase Order, Operation Canonical Order, system_id, resource_id)
    and renumbers consecutively starting at 1.
    """
    sorted_steps = sorted(steps, key=get_step_sort_key)
    renumbered = []
    for idx, s in enumerate(sorted_steps, start=1):
        step_copy = dict(s)
        step_copy["step_no"] = idx
        renumbered.append(step_copy)
    return renumbered


def process_baseline_request(
    row: Dict[str, str], default_evidence_id: str = "evidence_54"
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Phase 1 Baseline Request Processor:
    - Verifies deletion authorization
    - Emits compliant steps for sample validation
    """
    case_id = row["case_id"]
    request_text = row.get("request_text", "")
    reported_status = row.get("reported_status", "COMPLETE")

    if not is_deletion_request(request_text):
        return "NOT_APPLICABLE", []

    # Baseline heuristic: relies on reported status
    if reported_status == "COMPLETE":
        # Baseline complete case: emit verification steps with evidence proof
        steps = [
            {
                "step_no": 1,
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": f"account_{case_id.split('_')[-1]}",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": default_evidence_id,
            }
        ]
        return "COMPLETE", sort_and_renumber_steps(steps)
    else:
        # Baseline incomplete case: emit finding, remediation, and verification steps
        resource_id = f"account_{case_id.split('_')[-1]}"
        steps = [
            {
                "step_no": 1,
                "phase": "FINDING",
                "system_id": "account_service",
                "resource_id": resource_id,
                "operation": "REPORT_REMAINING_RECORD",
                "state": "PRESENT",
                "evidence_id": default_evidence_id,
            },
            {
                "step_no": 2,
                "phase": "REMEDIATION",
                "system_id": "account_service",
                "resource_id": resource_id,
                "operation": "DELETE_RECORD",
                "state": "ABSENT",
                "evidence_id": "",
            },
            {
                "step_no": 3,
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": resource_id,
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "",
            },
        ]
        return "INCOMPLETE", sort_and_renumber_steps(steps)


def run_pipeline(
    requests_path: str,
    output_path: str,
    dataset_dir: str = "dataset",
) -> None:
    """
    Executes the GhostTrace auditing pipeline.
    """
    if not os.path.isfile(requests_path):
        raise FileNotFoundError(f"Input file not found: {requests_path}")

    # Load requests
    requests = []
    with open(requests_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            requests.append(row)

    # Sort requests by case_id
    requests = sorted(requests, key=lambda r: r["case_id"])

    cache_file = os.path.join(os.path.dirname(__file__), "evidence_cache.json")
    if not os.path.isfile(cache_file):
        cache_file = "code/evidence_cache.json"

    engine = ForensicPolicyEngine(dataset_dir=dataset_dir, cache_file=cache_file)

    results = []
    for req in requests:
        status, steps = engine.audit_case(req)
        steps_json = json.dumps(steps, separators=(",", ":"))
        results.append(
            {
                "case_id": req["case_id"],
                "deletion_status": status,
                "steps_json": steps_json,
            }
        )

    # Write output CSV strictly adhering to format
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for res in results:
            writer.writerow([res["case_id"], res["deletion_status"], res["steps_json"]])

    print(
        f"[GhostTrace] Processed {len(results)} requests -> Generated '{output_path}'"
    )


def main():
    parser = argparse.ArgumentParser(
        description="GhostTrace Deletion Audit Pipeline"
    )
    parser.add_argument(
        "--input",
        default="dataset/deletion_requests.csv",
        help="Path to input requests CSV (default: dataset/deletion_requests.csv)",
    )
    parser.add_argument(
        "--output",
        default="output.csv",
        help="Path to target output CSV (default: output.csv)",
    )
    parser.add_argument(
        "--dataset-dir",
        default="dataset",
        help="Root path of dataset files (default: dataset)",
    )
    args = parser.parse_args()

    run_pipeline(
        requests_path=args.input,
        output_path=args.output,
        dataset_dir=args.dataset_dir,
    )


if __name__ == "__main__":
    main()
