"""
GhostTrace Evaluation Suite & Test Harness
HackerRank Orchestrate October 2026 | Ghost Data Still Exists

Validates submission output format, verifies structural schema contracts,
and calculates case-level, step-level, field-level, and sequence-level metrics.
"""

import argparse
import csv
import json
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Allowed operations and their required resulting states, mapped to their canonical sort order
ALLOWED_OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": ("PRESENT", 1),
        "REPORT_EXPOSED_PII": ("PRESENT", 2),
        "REPORT_ACTIVE_DATA_FLOW": ("ACTIVE", 3),
        "REPORT_RESTORE_RISK": ("ACTIVE", 4),
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": ("DISABLED", 1),
        "BLOCK_RESTORE": ("BLOCKED", 2),
        "DELETE_RECORD": ("ABSENT", 3),
        "REDACT_RECORD": ("REDACTED", 4),
        "ANONYMIZE_RECORD": ("ANONYMIZED", 5),
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": ("ABSENT", 1),
        "VERIFY_RECORD_PRESENT": ("PRESENT", 2),
        "VERIFY_RECORD_REDACTED": ("REDACTED", 3),
        "VERIFY_RECORD_ANONYMIZED": ("ANONYMIZED", 4),
        "VERIFY_DATA_FLOW_DISABLED": ("DISABLED", 5),
        "VERIFY_RESTORE_BLOCKED": ("BLOCKED", 6),
    },
}

PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

REQUIRED_STEP_KEYS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


def get_step_sort_key(step: Dict[str, Any]) -> Tuple[int, int, str, str]:
    phase = step.get("phase", "")
    op = step.get("operation", "")
    system_id = step.get("system_id", "")
    resource_id = step.get("resource_id", "")
    phase_rank = PHASE_ORDER.get(phase, 99)
    op_rank = ALLOWED_OPERATIONS.get(phase, {}).get(op, ("", 99))[1]
    return (phase_rank, op_rank, system_id, resource_id)


def validate_step_structure(
    step: Dict[str, Any],
    expected_step_no: int,
    case_id: str,
    case_status: str,
    valid_evidence_ids: Optional[Set[str]] = None,
) -> List[str]:
    errors = []
    # Key check
    step_keys = set(step.keys())
    if step_keys != REQUIRED_STEP_KEYS:
        missing = REQUIRED_STEP_KEYS - step_keys
        extra = step_keys - REQUIRED_STEP_KEYS
        if missing:
            errors.append(f"{case_id} step {expected_step_no}: missing keys {missing}")
        if extra:
            errors.append(f"{case_id} step {expected_step_no}: unexpected keys {extra}")

    # step_no check
    step_no = step.get("step_no")
    if step_no != expected_step_no:
        errors.append(
            f"{case_id}: step_no is {step_no}, expected consecutive {expected_step_no}"
        )

    # Phase check
    phase = step.get("phase")
    if phase not in PHASE_ORDER:
        errors.append(f"{case_id} step {expected_step_no}: invalid phase '{phase}'")
        return errors

    # Operation and state check
    op = step.get("operation")
    state = step.get("state")
    allowed_for_phase = ALLOWED_OPERATIONS.get(phase, {})
    if op not in allowed_for_phase:
        errors.append(
            f"{case_id} step {expected_step_no}: operation '{op}' not allowed for phase '{phase}'"
        )
    else:
        expected_state, _ = allowed_for_phase[op]
        if state != expected_state:
            errors.append(
                f"{case_id} step {expected_step_no}: operation '{op}' must have state '{expected_state}', got '{state}'"
            )

    # Evidence ID check
    evidence_id = step.get("evidence_id", "")
    if case_status == "COMPLETE":
        if phase != "VERIFICATION":
            errors.append(
                f"{case_id} COMPLETE: step phase must be VERIFICATION, got '{phase}'"
            )
        if not evidence_id or not str(evidence_id).strip():
            errors.append(
                f"{case_id} COMPLETE: step {expected_step_no} must cite valid evidence_id, got empty"
            )
        elif valid_evidence_ids and evidence_id not in valid_evidence_ids:
            errors.append(
                f"{case_id} COMPLETE: step {expected_step_no} evidence_id '{evidence_id}' not found in manifest"
            )
    elif case_status == "INCOMPLETE":
        if phase == "FINDING":
            if not evidence_id or not str(evidence_id).strip():
                errors.append(
                    f"{case_id} INCOMPLETE: FINDING step {expected_step_no} must cite evidence_id, got empty"
                )
            elif valid_evidence_ids and evidence_id not in valid_evidence_ids:
                errors.append(
                    f"{case_id} INCOMPLETE: FINDING step {expected_step_no} evidence_id '{evidence_id}' not in manifest"
                )
        elif phase in ("REMEDIATION", "VERIFICATION"):
            if evidence_id != "":
                errors.append(
                    f"{case_id} INCOMPLETE: {phase} step {expected_step_no} must have empty evidence_id, got '{evidence_id}'"
                )

    return errors


def validate_steps_ordering(steps: List[Dict[str, Any]], case_id: str) -> List[str]:
    errors = []
    keys = [get_step_sort_key(s) for s in steps]
    sorted_keys = sorted(keys)
    if keys != sorted_keys:
        errors.append(
            f"{case_id}: steps not strictly ordered by (phase, operation, system_id, resource_id)"
        )
    return errors


def validate_output_file(
    filepath: str,
    expected_count: Optional[int] = None,
    evidence_manifest_path: Optional[str] = None,
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validates the structure, headers, row count, sorting, JSON formatting,
    and step-level contracts of an output CSV file.
    """
    errors = []
    stats = {
        "total_rows": 0,
        "complete_count": 0,
        "incomplete_count": 0,
        "not_applicable_count": 0,
        "total_steps": 0,
    }

    if not os.path.isfile(filepath):
        return False, [f"File not found: {filepath}"], stats

    valid_evidence_ids: Optional[Set[str]] = None
    if evidence_manifest_path and os.path.isfile(evidence_manifest_path):
        try:
            with open(evidence_manifest_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                valid_evidence_ids = {
                    row["file_id"] for row in reader if "file_id" in row
                }
        except Exception as e:
            errors.append(f"Could not load evidence manifest: {e}")

    rows = []
    with open(filepath, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            return False, ["CSV file is completely empty"], stats
        expected_header = ["case_id", "deletion_status", "steps_json"]
        if header != expected_header:
            errors.append(f"Invalid header: got {header}, expected {expected_header}")

        for line_idx, row in enumerate(reader, start=2):
            if len(row) != 3:
                errors.append(
                    f"Line {line_idx}: expected 3 columns, got {len(row)}: {row}"
                )
                continue
            rows.append(row)

    stats["total_rows"] = len(rows)

    if expected_count is not None and len(rows) != expected_count:
        errors.append(f"Expected {expected_count} data rows, found {len(rows)}")

    case_ids = [r[0] for r in rows]
    # Check duplicate case_ids
    if len(case_ids) != len(set(case_ids)):
        duplicates = [cid for cid in case_ids if case_ids.count(cid) > 1]
        errors.append(f"Duplicate case_ids found: {set(duplicates)}")

    # Check natural / string sorting
    # Case IDs like case_01, case_02, or case_1, case_2...
    # Challenge requires: "sorted by case_id"
    if case_ids != sorted(case_ids):
        errors.append("Rows are not sorted by case_id in ascending order")

    for case_id, status, steps_raw in rows:
        if status not in VALID_STATUSES:
            errors.append(
                f"{case_id}: invalid status '{status}', must be one of {VALID_STATUSES}"
            )

        if status == "COMPLETE":
            stats["complete_count"] += 1
        elif status == "INCOMPLETE":
            stats["incomplete_count"] += 1
        elif status == "NOT_APPLICABLE":
            stats["not_applicable_count"] += 1

        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            errors.append(f"{case_id}: invalid JSON in steps_json: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json must be a JSON array")
            continue

        if status == "NOT_APPLICABLE":
            if len(steps) != 0:
                errors.append(
                    f"{case_id} NOT_APPLICABLE must have empty steps array [], got {len(steps)} steps"
                )
            continue

        stats["total_steps"] += len(steps)

        # Validate step-level contracts
        for idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"{case_id} step {idx}: step is not a JSON object")
                continue
            step_errs = validate_step_structure(
                step, idx, case_id, status, valid_evidence_ids
            )
            errors.extend(step_errs)

        # Validate ordering
        ordering_errs = validate_steps_ordering(steps, case_id)
        errors.extend(ordering_errs)

    is_valid = len(errors) == 0
    return is_valid, errors, stats


def evaluate_predictions(
    pred_path: str,
    truth_path: str,
    evidence_manifest_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates prediction CSV against reference truth CSV.
    Computes case-level, step-level, field-level, and sequence-level metrics.
    """
    valid_pred, pred_errors, pred_stats = validate_output_file(
        pred_path, evidence_manifest_path=evidence_manifest_path
    )
    valid_truth, truth_errors, truth_stats = validate_output_file(
        truth_path, evidence_manifest_path=evidence_manifest_path
    )

    pred_data = {}
    with open(pred_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            pred_data[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"]))

    truth_data = {}
    with open(truth_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            truth_data[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"]))

    common_cases = sorted(set(pred_data.keys()) & set(truth_data.keys()))
    total_truth_cases = len(truth_data)
    total_eval_cases = len(common_cases)

    status_matches = 0
    sequence_matches = 0

    total_truth_steps = 0
    total_pred_steps = 0
    matched_steps = 0

    field_matches = {
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    }
    field_totals = {k: 0 for k in field_matches}

    case_results = []

    for cid in common_cases:
        p_status, p_steps = pred_data[cid]
        t_status, t_steps = truth_data[cid]

        st_match = p_status == t_status
        if st_match:
            status_matches += 1

        seq_match = False
        if st_match and len(p_steps) == len(t_steps):
            # check exact step match including order
            all_equal = True
            for ps, ts in zip(p_steps, t_steps):
                for k in REQUIRED_STEP_KEYS:
                    if ps.get(k) != ts.get(k):
                        all_equal = False
                        break
                if not all_equal:
                    break
            if all_equal:
                seq_match = True
                sequence_matches += 1

        # Step matching (set of canonical tuple (phase, system_id, resource_id, operation, state))
        t_tuples = [
            (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])
            for s in t_steps
        ]
        p_tuples = [
            (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])
            for s in p_steps
        ]

        total_truth_steps += len(t_tuples)
        total_pred_steps += len(p_tuples)

        # Greedily match steps to evaluate field-level metrics
        t_matched = [False] * len(t_steps)
        for p_idx, ps in enumerate(p_steps):
            p_tup = p_tuples[p_idx]
            best_t_idx = None
            for t_idx, ts in enumerate(t_steps):
                if not t_matched[t_idx] and t_tuples[t_idx] == p_tup:
                    best_t_idx = t_idx
                    break
            if best_t_idx is not None:
                t_matched[best_t_idx] = True
                matched_steps += 1
                ts = t_steps[best_t_idx]
                for f_name in field_matches:
                    field_totals[f_name] += 1
                    if ps.get(f_name) == ts.get(f_name):
                        field_matches[f_name] += 1
            else:
                # partial match fallback for field comparison
                pass

        case_results.append(
            {
                "case_id": cid,
                "status_match": st_match,
                "sequence_match": seq_match,
                "pred_status": p_status,
                "truth_status": t_status,
                "pred_step_count": len(p_steps),
                "truth_step_count": len(t_steps),
            }
        )

    precision = matched_steps / total_pred_steps if total_pred_steps > 0 else 0.0
    recall = matched_steps / total_truth_steps if total_truth_steps > 0 else 0.0
    f1 = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    field_accuracies = {}
    for k in field_matches:
        tot = field_totals[k]
        field_accuracies[k] = (field_matches[k] / tot) if tot > 0 else 0.0

    report = {
        "pred_valid": valid_pred,
        "pred_errors_count": len(pred_errors),
        "pred_errors": pred_errors[:20],
        "pred_stats": pred_stats,
        "truth_stats": truth_stats,
        "total_eval_cases": total_eval_cases,
        "status_accuracy": status_matches / total_eval_cases if total_eval_cases > 0 else 0.0,
        "sequence_accuracy": sequence_matches / total_eval_cases if total_eval_cases > 0 else 0.0,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "field_accuracies": field_accuracies,
        "case_results": case_results,
    }
    return report


def main():
    parser = argparse.ArgumentParser(
        description="GhostTrace Evaluator & Harness"
    )
    parser.add_argument(
        "--pred",
        default="output.csv",
        help="Path to prediction CSV file (default: output.csv)",
    )
    parser.add_argument(
        "--truth",
        default=None,
        help="Path to reference ground-truth CSV (e.g. dataset/sample_output.csv)",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Expected number of data rows (e.g. 518 or 32)",
    )
    parser.add_argument(
        "--manifest",
        default="dataset/evidence_files.csv",
        help="Path to evidence_files.csv manifest",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )

    args = parser.parse_args()

    if args.truth:
        report = evaluate_predictions(
            args.pred, args.truth, evidence_manifest_path=args.manifest
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        elif args.format == "markdown":
            print(f"## GhostTrace Evaluation Report\n")
            print(f"- **Evaluated Cases**: {report['total_eval_cases']}")
            print(f"- **Status Accuracy**: {report['status_accuracy'] * 100:.2f}%")
            print(f"- **Sequence Exact Match Accuracy**: {report['sequence_accuracy'] * 100:.2f}%")
            print(f"- **Step F1**: {report['step_f1'] * 100:.2f}% (P={report['step_precision']*100:.1f}%, R={report['step_recall']*100:.1f}%)")
            print("\n### Field-level Accuracies")
            for f_name, acc in report["field_accuracies"].items():
                print(f"- `{f_name}`: {acc * 100:.2f}%")
        else:
            print("=" * 60)
            print("GHOSTTRACE EVALUATION SUMMARY")
            print("=" * 60)
            print(f"Prediction file : {args.pred}")
            print(f"Truth file      : {args.truth}")
            print(f"Valid schema    : {report['pred_valid']}")
            print(f"Cases evaluated : {report['total_eval_cases']}")
            print(f"Status accuracy : {report['status_accuracy'] * 100:.2f}%")
            print(f"Sequence acc    : {report['sequence_accuracy'] * 100:.2f}%")
            print(f"Step Precision  : {report['step_precision'] * 100:.2f}%")
            print(f"Step Recall     : {report['step_recall'] * 100:.2f}%")
            print(f"Step F1 Score   : {report['step_f1'] * 100:.2f}%")
            print("-" * 60)
            print("Field-level Accuracy:")
            for f_name, acc in report["field_accuracies"].items():
                print(f"  {f_name:14} : {acc * 100:.2f}%")
            if report["pred_errors"]:
                print("-" * 60)
                print(f"Schema Errors ({report['pred_errors_count']}):")
                for err in report["pred_errors"]:
                    print(f"  [!] {err}")
            print("=" * 60)
        sys.exit(0 if report["pred_valid"] else 1)
    else:
        is_valid, errors, stats = validate_output_file(
            args.pred,
            expected_count=args.expected_count,
            evidence_manifest_path=args.manifest,
        )
        if args.format == "json":
            print(
                json.dumps(
                    {"valid": is_valid, "stats": stats, "errors": errors}, indent=2
                )
            )
        else:
            print("=" * 60)
            print("GHOSTTRACE SCHEMA VALIDATION")
            print("=" * 60)
            print(f"File evaluated: {args.pred}")
            print(f"Valid: {is_valid}")
            print(f"Total rows: {stats['total_rows']}")
            print(f"  COMPLETE: {stats['complete_count']}")
            print(f"  INCOMPLETE: {stats['incomplete_count']}")
            print(f"  NOT_APPLICABLE: {stats['not_applicable_count']}")
            print(f"Total steps: {stats['total_steps']}")
            if errors:
                print(f"\nErrors found ({len(errors)}):")
                for err in errors[:25]:
                    print(f"  [X] {err}")
                if len(errors) > 25:
                    print(f"  ... and {len(errors) - 25} more errors")
            else:
                print("All schema contracts passed successfully.")
            print("=" * 60)
        sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
