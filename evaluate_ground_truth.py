"""
Evaluation script comparing heuristic model predictions against ground truth labels.

Loads predictions from IDS_heuristic_model_eval and ground truth from IDS_tables,
then analyzes:
- How many true attacks were detected
- How many false alarms (statistical anomalies) were detected
- How many benign events were incorrectly flagged
"""

import pandas as pd
import os
from collections import defaultdict

# Columns that were removed during cleaning (ground truth labels)
GROUND_TRUTH_COLUMNS = ["label", "scenario_name", "_malicious_count_param", 
                        "_benign_count_param", "_false_alarm_count_param"]

def load_and_merge_data(folder_name):
    """
    Load predictions from IDS_heuristic_model_eval and ground truth from IDS_tables.
    Merge them to compare.
    """
    results = []
    
    # Get all CSV files for this folder
    pred_dir = f"./IDS_heuristic_model_eval/{folder_name}"
    truth_dir = f"./IDS_tables/{folder_name}"
    
    if not os.path.exists(pred_dir):
        return None
    
    csv_files = sorted([f for f in os.listdir(pred_dir) if f.endswith('_predicted.csv')])
    
    for pred_file in csv_files:
        # Load predictions
        pred_path = os.path.join(pred_dir, pred_file)
        pred_df = pd.read_csv(pred_path)
        
        # Find corresponding ground truth file
        # Remove "_cleaned_predicted" suffix to find ground truth filename
        # e.g., "Data_Theft_18events_cleaned_predicted.csv" -> "Data_Theft_18events.csv"
        base_name = pred_file.replace('_cleaned_predicted.csv', '.csv')
        truth_path = os.path.join(truth_dir, base_name)
        
        if not os.path.exists(truth_path):
            print(f"  WARNING: Ground truth file not found: {base_name}")
            continue
        
        # Load ground truth
        truth_df = pd.read_csv(truth_path)
        
        # Merge on row index (assuming same order)
        if len(pred_df) != len(truth_df):
            print(f"  WARNING: Row count mismatch for {pred_file}: pred={len(pred_df)}, truth={len(truth_df)}")
            continue
        
        # Add ground truth columns to predictions
        for col in GROUND_TRUTH_COLUMNS:
            if col in truth_df.columns:
                pred_df[col] = truth_df[col]
        
        results.append(pred_df)
    
    if results:
        return pd.concat(results, ignore_index=True)
    return None

def evaluate_folder(folder_name):
    """
    Evaluate a single folder's predictions against ground truth.
    """
    print(f"\n{'='*70}")
    print(f"Folder: {folder_name}")
    print('='*70)
    
    # Load merged data
    df = load_and_merge_data(folder_name)
    if df is None:
        print(f"Could not load data for {folder_name}")
        return
    
    # Analyze by ground truth label
    stats = {
        'malicious': {'predicted_malicious': 0, 'predicted_benign': 0, 'total': 0},
        'benign': {'predicted_malicious': 0, 'predicted_benign': 0, 'total': 0},
        'false_alarm': {'predicted_malicious': 0, 'predicted_benign': 0, 'total': 0}
    }
    
    reason_breakdown = defaultdict(lambda: defaultdict(int))
    
    for idx, row in df.iterrows():
        if 'label' not in row or pd.isna(row['label']):
            continue
        
        # Normalize label: "False Alarm" -> "false_alarm", etc.
        truth = row['label'].lower().strip().replace(' ', '_')
        prediction = row['prediction'].lower().strip()
        reason = row['reason'] if 'reason' in row else ''
        
        if truth not in stats:
            continue  # Skip unknown labels
        
        category = 'predicted_malicious' if prediction == 'malicious' else 'predicted_benign'
        
        stats[truth]['total'] += 1
        stats[truth][category] += 1
        
        if prediction == 'malicious':
            reason_breakdown[truth][reason] += 1
    
    # Print summary
    for truth_label in ['malicious', 'benign', 'false_alarm']:
        s = stats[truth_label]
        total = s['total']
        if total == 0:
            continue
        
        mal_count = s['predicted_malicious']
        ben_count = s['predicted_benign']
        mal_pct = (mal_count / total * 100) if total > 0 else 0
        
        print(f"\n{truth_label.upper()} events (n={total}):")
        print(f"  Flagged as malicious:     {mal_count:3d} ({mal_pct:5.1f}%)")
        print(f"  Flagged as benign:        {ben_count:3d} ({100-mal_pct:5.1f}%)")
        
        # Show top reasons for detected events
        if truth_label in reason_breakdown and mal_count > 0:
            print(f"  Reasons (top 3):")
            top_reasons = sorted(reason_breakdown[truth_label].items(), 
                               key=lambda x: x[1], reverse=True)[:3]
            for reason, count in top_reasons:
                reason_short = reason[:60] + "..." if len(reason) > 60 else reason
                print(f"    - {reason_short} ({count})")
    
    # Print interpretation
    print(f"\n{'-'*70}")
    print("INTERPRETATION:")
    mal_detected = stats['malicious']['predicted_malicious'] / max(1, stats['malicious']['total'])
    fa_detected = stats['false_alarm']['predicted_malicious'] / max(1, stats['false_alarm']['total'])
    benign_flagged = stats['benign']['predicted_malicious'] / max(1, stats['benign']['total'])
    
    print(f"  Attack detection rate:      {mal_detected*100:5.1f}%")
    print(f"  False alarm detection rate: {fa_detected*100:5.1f}%  (statistical anomalies caught)")
    print(f"  Benign false positive rate: {benign_flagged*100:5.1f}%  (legitimate traffic flagged)")
    
    return {
        'folder': folder_name,
        'attack_rate': mal_detected,
        'false_alarm_rate': fa_detected,
        'benign_fp_rate': benign_flagged
    }

def main():
    """Evaluate all folders with ground truth comparisons."""
    print("\n" + "="*70)
    print("HEURISTIC MODEL EVALUATION AGAINST GROUND TRUTH")
    print("="*70)
    
    folders = sorted([d for d in os.listdir('./IDS_heuristic_model_eval') 
                     if os.path.isdir(f'./IDS_heuristic_model_eval/{d}')])
    
    results = []
    for folder in folders:
        result = evaluate_folder(folder)
        if result:
            results.append(result)
    
    # Summary across all folders
    if results:
        print(f"\n{'='*70}")
        print("SUMMARY ACROSS ALL FOLDERS")
        print('='*70)
        
        avg_attack_rate = sum(r['attack_rate'] for r in results) / len(results)
        avg_fa_rate = sum(r['false_alarm_rate'] for r in results) / len(results)
        avg_benign_fp = sum(r['benign_fp_rate'] for r in results) / len(results)
        
        print(f"\nAverage attack detection rate:      {avg_attack_rate*100:5.1f}%")
        print(f"Average false alarm detection rate: {avg_fa_rate*100:5.1f}%")
        print(f"Average benign false positive rate: {avg_benign_fp*100:5.1f}%")
        
        print("\n" + "-"*70)
        print("KEY INSIGHTS:")
        print(f"  * Model detects {avg_attack_rate*100:.1f}% of true attacks")
        print(f"  * Model detects {avg_fa_rate*100:.1f}% of false alarms (statistical anomalies)")
        print(f"  * Model miscategorizes {avg_benign_fp*100:.1f}% of benign traffic")
        
        if avg_fa_rate > 0.8:
            print(f"  GOOD: Model effectively catching statistically abnormal behavior")
        else:
            print(f"  NOTE: Model may not be sensitive enough to statistical anomalies")

if __name__ == '__main__':
    main()
