import sys; sys.path.insert(0, '.')
import csv
import json
import pandas as pd
from code.policy_engine import ForensicPolicyEngine
from code.evaluation.main import evaluate_predictions

print("Initializing ForensicPolicyEngine...")
engine = ForensicPolicyEngine('dataset', 'code/evidence_cache.json')

reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
predictions = []

for idx, r in reqs.iterrows():
    status, steps = engine.audit_case(r.to_dict())
    predictions.append({
        'case_id': r['case_id'],
        'deletion_status': status,
        'steps_json': json.dumps(steps, separators=(',', ':'))
    })

pred_path = 'code/sample_predictions.csv'
with open(pred_path, 'w', encoding='utf-8', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
    writer.writeheader()
    writer.writerows(predictions)

print(f"Generated {len(predictions)} sample predictions.")

report = evaluate_predictions(pred_path, 'dataset/sample_output.csv')
print("\n" + "="*50)
print("SAMPLE EVALUATION RESULTS:")
print("="*50)
print(f"Status Accuracy : {report['status_accuracy']*100:.2f}%")
print(f"Sequence Match  : {report['sequence_accuracy']*100:.2f}%")
print(f"Step Precision  : {report['step_precision']*100:.2f}%")
print(f"Step Recall     : {report['step_recall']*100:.2f}%")
print(f"Step F1 Score   : {report['step_f1']*100:.2f}%")
print("-"*50)
for f_name, acc in report['field_accuracies'].items():
    print(f"  {f_name:14} : {acc*100:.2f}%")
print("="*50)
