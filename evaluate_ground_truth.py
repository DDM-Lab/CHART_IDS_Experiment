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
    Optionally load human feedback from IDS_with_feedback if available.
    Merge them to compare.
    """
    results = []
    
    # Get all CSV files for this folder
    pred_dir = f"./IDS_heuristic_model_eval/{folder_name}"
    truth_dir = f"./IDS_tables/{folder_name}"
    feedback_dir = f"./IDS_with_feedback/{folder_name}"
    
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
        
        # Try to load human feedback if available
        if os.path.exists(feedback_dir):
            feedback_file = base_name.replace('.csv', '_with_feedback.csv')
            feedback_path = os.path.join(feedback_dir, feedback_file)
            
            if os.path.exists(feedback_path):
                try:
                    feedback_df = pd.read_csv(feedback_path)
                    # Merge feedback columns (model_final_pred, decision_flipped, etc.)
                    feedback_cols = ['human_feedback', 'human_confidence', 'human_explanation',
                                   'model_final_pred', 'model_final_conf', 'decision_flipped', 
                                   'flip_reason', 'rule_override_count', 'confidence_gap']
                    
                    for col in feedback_cols:
                        if col in feedback_df.columns:
                            pred_df[col] = feedback_df[col]
                except Exception as e:
                    pass  # Silently skip if feedback merge fails
        
        results.append(pred_df)
    
    if results:
        return pd.concat(results, ignore_index=True)
    return None

def calculate_accuracy(df, use_original_pred=True):
    """
    Calculate accuracy metrics relative to ground truth.
    
    treated_as_correct:
    - "malicious" ground truth should be predicted "malicious"
    - "benign" or "false_alarm" (both non-malicious) treated same for accuracy
    
    Returns dict with accuracies by category
    """
    accuracy = {
        'overall': {'correct': 0, 'total': 0},
        'malicious': {'correct': 0, 'total': 0},
        'not_malicious': {'correct': 0, 'total': 0}
    }
    
    pred_col = 'prediction' if use_original_pred else 'model_final_pred'
    
    for idx, row in df.iterrows():
        if 'label' not in row or pd.isna(row['label']) or pred_col not in row:
            continue
        
        truth = row['label'].lower().strip().replace(' ', '_')
        prediction = str(row[pred_col]).lower().strip()
        
        # Normalize truth: "false_alarm" and "benign" both treated as not malicious
        if truth == 'malicious':
            truth_category = 'malicious'
        elif truth in ['benign', 'false_alarm']:
            truth_category = 'not_malicious'
        else:
            continue
        
        # Check if prediction matches ground truth
        # Correct if: (truth is malicious AND pred is malicious) OR (truth is not_malicious AND pred is not_malicious)
        is_correct = False
        if truth_category == 'malicious':
            is_correct = (prediction == 'malicious')
        else:  # not_malicious
            is_correct = (prediction == 'not malicious')
        
        accuracy['overall']['total'] += 1
        accuracy[truth_category]['total'] += 1
        
        if is_correct:
            accuracy['overall']['correct'] += 1
            accuracy[truth_category]['correct'] += 1
    
    return accuracy

def format_accuracy_table(accuracy_pre, accuracy_post, label=""):
    """Format accuracy comparison as a readable table."""
    print(f"\n{label}")
    print(f"{'-'*70}")
    print(f"{'Category':<20} {'Pre-Feedback':<18} {'Post-Feedback':<18} {'Improvement':<12}")
    print(f"{'-'*70}")
    
    for category in ['overall', 'malicious', 'not_malicious']:
        cat_pre = accuracy_pre[category]
        cat_post = accuracy_post[category]
        
        if cat_pre['total'] == 0:
            continue
        
        pre_acc = (cat_pre['correct'] / cat_pre['total'] * 100) if cat_pre['total'] > 0 else 0
        post_acc = (cat_post['correct'] / cat_post['total'] * 100) if cat_post['total'] > 0 else 0
        improvement = post_acc - pre_acc
        
        cat_display = category.replace('_', ' ').title()
        print(f"{cat_display:<20} {pre_acc:>6.1f}% ({cat_pre['correct']}/{cat_pre['total']:<3}) "
              f"{post_acc:>6.1f}% ({cat_post['correct']}/{cat_post['total']:<3}) "
              f"{improvement:>+6.1f}%")
    
    print(f"{'-'*70}")

def evaluate_folder(folder_name):
    """
    Evaluate a single folder's predictions against ground truth.
    Optionally evaluates human feedback impact if available.
    """
    print(f"\n{'='*70}")
    print(f"Folder: {folder_name}")
    print('='*70)
    
    # Load merged data
    df = load_and_merge_data(folder_name)
    if df is None:
        print(f"Could not load data for {folder_name}")
        return
    
    # Check if feedback data is available
    has_feedback = 'human_feedback' in df.columns and df['human_feedback'].notna().sum() > 0
    
    # Calculate accuracy (pre-feedback)
    accuracy_all_pre = calculate_accuracy(df, use_original_pred=True)
    # Calculate accuracy (pre-feedback)
    accuracy_all_pre = calculate_accuracy(df, use_original_pred=True)
    
    # If feedback available, calculate post-feedback accuracy and feedback-only accuracy
    if has_feedback:
        accuracy_all_post = calculate_accuracy(df, use_original_pred=False)
        
        # Get rows with feedback
        df_feedback = df[df['human_feedback'].notna()]
        accuracy_feedback_pre = calculate_accuracy(df_feedback, use_original_pred=True)
        accuracy_feedback_post = calculate_accuracy(df_feedback, use_original_pred=False)
    else:
        accuracy_all_post = None
        accuracy_feedback_pre = None
        accuracy_feedback_post = None
    
    # Display predictions summary
    print(f"\nPREDICTION SUMMARY:")
    print(f"{'-'*70}")
    
    # Analyze by ground truth label
    stats = {
        'malicious': {'predicted_malicious': 0, 'predicted_benign': 0, 'total': 0},
        'benign': {'predicted_malicious': 0, 'predicted_benign': 0, 'total': 0},
        'false_alarm': {'predicted_malicious': 0, 'predicted_benign': 0, 'total': 0}
    }
    
    feedback_stats = {
        'total_with_feedback': 0,
        'human_agrees': 0,
        'human_disagrees': 0,
        'decisions_flipped': 0,
        'flip_correct': 0,  # Flip matched ground truth
        'flip_incorrect': 0  # Flip worsened accuracy
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
        
        # Analyze human feedback if available
        if has_feedback and pd.notna(row.get('human_feedback')):
            feedback_stats['total_with_feedback'] += 1
            
            human_pred = row['human_feedback'].lower().strip()
            
            # Check if human agrees with model
            if human_pred == prediction:
                feedback_stats['human_agrees'] += 1
            else:
                feedback_stats['human_disagrees'] += 1
            
            # Check if decision was flipped
            if row.get('decision_flipped', False) == True or row.get('decision_flipped', '') == 'True':
                feedback_stats['decisions_flipped'] += 1
                
                # Check if flip was correct (matches ground truth)
                final_pred = row['model_final_pred'].lower().strip()
                truth_normalized = 'malicious' if truth == 'malicious' else 'not malicious'
                
                if final_pred == truth_normalized:
                    feedback_stats['flip_correct'] += 1
                else:
                    feedback_stats['flip_incorrect'] += 1
    
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
    
    # Display accuracy comparison
    print(f"\n{'='*70}")
    print("ACCURACY ANALYSIS:")
    print('='*70)
    
    # Overall accuracy
    format_accuracy_table(accuracy_all_pre, accuracy_all_post if accuracy_all_post else accuracy_all_pre,
                         "OVERALL ACCURACY (All Rows):")
    
    # Feedback-specific accuracy (if available)
    if has_feedback and accuracy_feedback_pre:
        format_accuracy_table(accuracy_feedback_pre, accuracy_feedback_post,
                             "ACCURACY ON ROWS WITH HUMAN FEEDBACK:")
    
    # Print human feedback analysis if available
    if has_feedback and feedback_stats['total_with_feedback'] > 0:
        print(f"\nHUMAN FEEDBACK ANALYSIS:")
        print(f"{'-'*70}")
        total_fb = feedback_stats['total_with_feedback']
        agrees = feedback_stats['human_agrees']
        disagrees = feedback_stats['human_disagrees']
        flipped = feedback_stats['decisions_flipped']
        
        print(f"  Rows with human feedback:    {total_fb}")
        print(f"  Human-model agreement:       {agrees:3d} ({agrees/total_fb*100:5.1f}%)")
        print(f"  Human-model disagreement:    {disagrees:3d} ({disagrees/total_fb*100:5.1f}%)")
        print(f"  Decisions flipped:           {flipped:3d} ({flipped/total_fb*100:5.1f}%)")
        
        if flipped > 0:
            flip_correct = feedback_stats['flip_correct']
            flip_incorrect = feedback_stats['flip_incorrect']
            correct_pct = (flip_correct / flipped * 100) if flipped > 0 else 0
            print(f"  Flip accuracy (vs truth):    {flip_correct:3d}/{flipped} ({correct_pct:5.1f}%) improved")
            if flip_incorrect > 0:
                print(f"                               {flip_incorrect:3d}/{flipped} ({100-correct_pct:5.1f}%) worsened")
    
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
        'benign_fp_rate': benign_flagged,
        'has_feedback': has_feedback,
        'feedback_stats': feedback_stats if has_feedback else None,
        'accuracy_all_pre': accuracy_all_pre,
        'accuracy_all_post': accuracy_all_post,
        'accuracy_feedback_pre': accuracy_feedback_pre,
        'accuracy_feedback_post': accuracy_feedback_post
    }

def main():
    """Evaluate all folders with ground truth comparisons."""
    print("\n" + "="*70)
    print("HEURISTIC MODEL EVALUATION AGAINST GROUND TRUTH")
    print("="*70)
    
    folders = sorted([d for d in os.listdir('./IDS_heuristic_model_eval') 
                     if os.path.isdir(f'./IDS_heuristic_model_eval/{d}')])
    
    results = []
    feedback_summary = {
        'total_with_feedback': 0,
        'human_agrees': 0,
        'human_disagrees': 0,
        'decisions_flipped': 0,
        'flip_correct': 0,
        'flip_incorrect': 0
    }
    
    accuracy_agg_all_pre = {'overall': {'correct': 0, 'total': 0}, 'malicious': {'correct': 0, 'total': 0}, 'not_malicious': {'correct': 0, 'total': 0}}
    accuracy_agg_all_post = {'overall': {'correct': 0, 'total': 0}, 'malicious': {'correct': 0, 'total': 0}, 'not_malicious': {'correct': 0, 'total': 0}}
    accuracy_agg_fb_pre = {'overall': {'correct': 0, 'total': 0}, 'malicious': {'correct': 0, 'total': 0}, 'not_malicious': {'correct': 0, 'total': 0}}
    accuracy_agg_fb_post = {'overall': {'correct': 0, 'total': 0}, 'malicious': {'correct': 0, 'total': 0}, 'not_malicious': {'correct': 0, 'total': 0}}
    
    for folder in folders:
        result = evaluate_folder(folder)
        if result:
            results.append(result)
            # Aggregate feedback stats
            if result['has_feedback'] and result['feedback_stats']:
                for key in feedback_summary:
                    feedback_summary[key] += result['feedback_stats'].get(key, 0)
            
            # Aggregate accuracy stats
            for category in ['overall', 'malicious', 'not_malicious']:
                accuracy_agg_all_pre[category]['correct'] += result['accuracy_all_pre'][category]['correct']
                accuracy_agg_all_pre[category]['total'] += result['accuracy_all_pre'][category]['total']
                
                if result['accuracy_all_post']:
                    accuracy_agg_all_post[category]['correct'] += result['accuracy_all_post'][category]['correct']
                    accuracy_agg_all_post[category]['total'] += result['accuracy_all_post'][category]['total']
                
                if result['accuracy_feedback_pre']:
                    accuracy_agg_fb_pre[category]['correct'] += result['accuracy_feedback_pre'][category]['correct']
                    accuracy_agg_fb_pre[category]['total'] += result['accuracy_feedback_pre'][category]['total']
                
                if result['accuracy_feedback_post']:
                    accuracy_agg_fb_post[category]['correct'] += result['accuracy_feedback_post'][category]['correct']
                    accuracy_agg_fb_post[category]['total'] += result['accuracy_feedback_post'][category]['total']
    
    # Summary across all folders
    if results:
        print(f"\n{'='*70}")
        print("SUMMARY ACROSS ALL FOLDERS")
        print('='*70)
        
        avg_attack_rate = sum(r['attack_rate'] for r in results) / len(results)
        avg_fa_rate = sum(r['false_alarm_rate'] for r in results) / len(results)
        avg_benign_fp = sum(r['benign_fp_rate'] for r in results) / len(results)
        
        print(f"\nMODEL PREDICTIONS:")
        print(f"  Average attack detection rate:      {avg_attack_rate*100:5.1f}%")
        print(f"  Average false alarm detection rate: {avg_fa_rate*100:5.1f}%")
        print(f"  Average benign false positive rate: {avg_benign_fp*100:5.1f}%")
        
        # Accuracy summary
        print(f"\n{'='*70}")
        format_accuracy_table(accuracy_agg_all_pre, accuracy_agg_all_post,
                             "OVERALL ACCURACY IMPROVEMENT (All Rows):")
        
        if accuracy_agg_fb_pre['overall']['total'] > 0:
            format_accuracy_table(accuracy_agg_fb_pre, accuracy_agg_fb_post,
                                 "ACCURACY ON FEEDBACK ROWS:")
        
        # Feedback summary
        if feedback_summary['total_with_feedback'] > 0:
            print(f"\nHUMAN FEEDBACK IMPACT:")
            total_fb = feedback_summary['total_with_feedback']
            agrees = feedback_summary['human_agrees']
            disagrees = feedback_summary['human_disagrees']
            flipped = feedback_summary['decisions_flipped']
            
            print(f"  Total rows with human feedback:  {total_fb}")
            print(f"  Human-model agreement:           {agrees:3d} ({agrees/total_fb*100:5.1f}%)")
            print(f"  Human-model disagreement:        {disagrees:3d} ({disagrees/total_fb*100:5.1f}%)")
            print(f"  Total decisions flipped:         {flipped:3d} ({flipped/total_fb*100:5.1f}%)")
            
            if flipped > 0:
                flip_correct = feedback_summary['flip_correct']
                flip_incorrect = feedback_summary['flip_incorrect']
                correct_pct = (flip_correct / flipped * 100) if flipped > 0 else 0
                print(f"  Flip accuracy (vs ground truth): {flip_correct:3d}/{flipped} ({correct_pct:5.1f}%) improved")
                if flip_incorrect > 0:
                    print(f"                                  {flip_incorrect:3d}/{flipped} ({100-correct_pct:5.1f}%) worsened")
        
        print("\n" + "-"*70)
        print("KEY INSIGHTS:")
        print(f"  * Model detects {avg_attack_rate*100:.1f}% of true attacks")
        print(f"  * Model detects {avg_fa_rate*100:.1f}% of false alarms (statistical anomalies)")
        print(f"  * Model miscategorizes {avg_benign_fp*100:.1f}% of benign traffic")
        
        if avg_fa_rate > 0.8:
            print(f"  GOOD: Model effectively catching statistically abnormal behavior")
        else:
            print(f"  NOTE: Model may not be sensitive enough to statistical anomalies")
        
        if feedback_summary['total_with_feedback'] > 0:
            agree_pct = feedback_summary['human_agrees'] / feedback_summary['total_with_feedback'] * 100
            if agree_pct > 70:
                print(f"  GOOD: Human experts agree with model {agree_pct:.1f}% of the time")
            else:
                print(f"  NOTE: Human experts have significant disagreements ({100-agree_pct:.1f}%)")
            
            if feedback_summary['decisions_flipped'] > 0:
                flip_acc = feedback_summary['flip_correct'] / feedback_summary['decisions_flipped'] * 100
                print(f"  Human feedback improved accuracy: {flip_acc:.1f}% of flipped decisions correct")

if __name__ == '__main__':
    main()
