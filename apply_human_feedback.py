"""
Human Feedback Integration Script

Merges human expert feedback with heuristic model predictions.
Applies decision flip logic based on confidence levels.
Tracks rule overrides for analysis.

Usage:
    python apply_human_feedback.py <predictions_dir> <feedback_dir> --output-dir <output_dir>

Example:
    python apply_human_feedback.py ./IDS_heuristic_model_eval ./human_feedback --output-dir ./IDS_with_feedback
"""

import pandas as pd
import os
import sys
import argparse
import logging
from pathlib import Path
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HumanFeedbackIntegrator:
    """Integrates human expert feedback with model predictions."""
    
    def __init__(self):
        self.rule_override_counts = defaultdict(int)
        self.feedback_stats = {
            'total_rows': 0,
            'with_feedback': 0,
            'agreements': 0,
            'disagreements': 0
        }
    
    def compute_confidence_adjustment(self, model_pred, model_conf, human_feedback, human_conf):
        """
        Compute adjusted confidence based on human feedback.
        Model prediction NEVER flips; confidence adjusts to reflect agreement/disagreement.
        
        Gap-scaled penalty approach:
        - Agreement: Boost confidence based on human's agreement strength
        - Disagreement: Reduce confidence based on human's confidence level and gap magnitude
        - Gap = abs(model_conf - human_conf); larger gaps = stronger penalty signal
        
        Args:
            model_pred: "malicious" or "not malicious"
            model_conf: float [0.0-1.0]
            human_feedback: "malicious" or "not malicious" (or NaN if no feedback)
            human_conf: float [0.0-1.0] (or NaN if no feedback)
        
        Returns:
            tuple: (adjusted_confidence, adjustment_reason)
        """
        # No human feedback provided
        if pd.isna(human_feedback) or pd.isna(human_conf):
            return model_conf, "No human feedback provided"
        
        confidence_gap = abs(model_conf - human_conf)
        
        # Human agrees with model
        if human_feedback == model_pred:
            self.feedback_stats['agreements'] += 1
            
            # Boost confidence based on agreement strength
            if human_conf >= 0.85:
                adjusted = min(model_conf + 0.10, 0.95)
                return adjusted, f"Agreement: Human very confident (conf={human_conf:.2f}) → Boosted to {adjusted:.2f}"
            elif human_conf >= 0.70:
                # Keep unchanged
                return model_conf, f"Agreement: Human moderately confident (conf={human_conf:.2f}) → Unchanged"
            else:
                # Slight boost for weak agreement
                adjusted = model_conf + 0.05
                return adjusted, f"Agreement: Human weakly confident (conf={human_conf:.2f}) → Slight boost to {adjusted:.2f}"
        
        # Human disagrees - apply gap-scaled penalty
        self.feedback_stats['disagreements'] += 1
        
        # Confidence floor to prevent over-penalizing
        confidence_floor = 0.30
        
        if human_conf >= 0.80:
            # Strong disagreement: Base penalty inverted + gap scaling
            base_penalty = (1.0 - model_conf) * 0.50
            gap_penalty = confidence_gap * 0.20
            adjusted = max(base_penalty + gap_penalty, confidence_floor)
            return adjusted, f"Strong disagreement (human_conf={human_conf:.2f}): Gap={confidence_gap:.2f}, penalty applied → {adjusted:.2f}"
        
        elif human_conf >= 0.70:
            # Moderate disagreement
            base_penalty = (1.0 - model_conf) * 0.35
            gap_penalty = confidence_gap * 0.15
            adjusted = max(base_penalty + gap_penalty, confidence_floor)
            return adjusted, f"Moderate disagreement (human_conf={human_conf:.2f}): Gap={confidence_gap:.2f}, penalty applied → {adjusted:.2f}"
        
        elif human_conf >= 0.55:
            # Weak disagreement
            base_penalty = (1.0 - model_conf) * 0.25
            gap_penalty = confidence_gap * 0.10
            adjusted = max(base_penalty + gap_penalty, confidence_floor)
            return adjusted, f"Weak disagreement (human_conf={human_conf:.2f}): Gap={confidence_gap:.2f}, penalty applied → {adjusted:.2f}"
        
        else:  # human_conf < 0.55
            # Very weak disagreement: Minimal penalty, mostly trust model
            adjusted = max(model_conf - 0.05, confidence_floor)
            return adjusted, f"Very weak disagreement (human_conf={human_conf:.2f}): Minimal adjustment → {adjusted:.2f}"

    
    def integrate_feedback(self, pred_df, feedback_df):
        """
        Merge model predictions with human feedback and adjust confidence.
        
        Model prediction NEVER flips. Confidence adjusts based on agreement/disagreement
        to reflect human feedback strength without losing the model's original perspective.
        
        Args:
            pred_df: DataFrame with model predictions
            feedback_df: DataFrame with human feedback (id, human_feedback, human_confidence, human_explanation)
        
        Returns:
            DataFrame: Merged with confidence_adjusted and adjustment_reason columns
        """
        # Merge on id
        result_df = pred_df.copy()
        
        # If feedback_df is empty, just add empty columns
        if feedback_df is None or len(feedback_df) == 0:
            result_df['human_feedback'] = None
            result_df['human_confidence'] = None
            result_df['human_explanation'] = None
            result_df['confidence_adjusted'] = result_df['confidence']
            result_df['confidence_gap'] = 0.0
            result_df['adjustment_reason'] = "No human feedback provided"
            result_df['rule_override_count'] = 0
            return result_df
        
        # Clean feedback: convert empty strings to NaN
        feedback_df = feedback_df.copy()
        feedback_df['human_feedback'] = feedback_df['human_feedback'].replace('', None)
        feedback_df['human_confidence'] = pd.to_numeric(feedback_df['human_confidence'], errors='coerce')
        feedback_df['human_explanation'] = feedback_df['human_explanation'].replace('', None)
        
        # Merge feedback
        result_df = result_df.merge(
            feedback_df[['id', 'human_feedback', 'human_confidence', 'human_explanation']],
            on='id',
            how='left'
        )
        
        # Compute confidence adjustments
        confidence_adjusted = []
        confidence_gaps = []
        adjustment_reasons = []
        rule_counts = []
        
        for _, row in result_df.iterrows():
            self.feedback_stats['total_rows'] += 1
            
            model_pred = row['prediction']
            model_conf = row['confidence']
            human_feedback = row.get('human_feedback', None)
            human_conf = row.get('human_confidence', None)
            anomaly_type = row.get('reason', 'unknown')
            
            # Compute confidence adjustment
            adjusted_conf, adjustment_reason = self.compute_confidence_adjustment(
                model_pred, model_conf, human_feedback, human_conf
            )
            
            # Calculate confidence gap (only if feedback provided)
            if pd.notna(human_feedback) and pd.notna(human_conf):
                gap = abs(model_conf - human_conf)
                self.feedback_stats['with_feedback'] += 1
                
                # Track rule override (when confidence is significantly reduced)
                if pd.notna(human_feedback) and human_feedback != model_pred:
                    if adjusted_conf < (model_conf - 0.15):  # Significant reduction
                        self.rule_override_counts[anomaly_type] += 1
            else:
                gap = 0.0
            
            confidence_adjusted.append(adjusted_conf)
            confidence_gaps.append(gap)
            adjustment_reasons.append(adjustment_reason)
            rule_counts.append(self.rule_override_counts.get(anomaly_type, 0))
        
        # Add new columns
        result_df['confidence_adjusted'] = confidence_adjusted
        result_df['confidence_gap'] = confidence_gaps
        result_df['adjustment_reason'] = adjustment_reasons
        result_df['rule_override_count'] = rule_counts
        
        return result_df
    
    def process_folder(self, pred_dir, feedback_dir, output_dir):
        """
        Process all CSV files in a folder with feedback.
        
        Args:
            pred_dir: Input predictions directory
            feedback_dir: Input feedback directory (same structure)
            output_dir: Output directory for integrated results
        """
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Get all prediction files
        pred_files = sorted([f for f in os.listdir(pred_dir) if f.endswith('.csv')])
        
        for pred_file in pred_files:
            # Load predictions
            pred_path = os.path.join(pred_dir, pred_file)
            pred_df = pd.read_csv(pred_path)
            
            # Load feedback if exists (same filename pattern)
            feedback_path = os.path.join(feedback_dir, pred_file.replace('_predicted.csv', '_feedback.csv'))
            feedback_df = None
            if os.path.exists(feedback_path):
                feedback_df = pd.read_csv(feedback_path)
                logger.info(f"  Found feedback for {pred_file}: {len(feedback_df)} rows")
            else:
                logger.info(f"  No feedback file for {pred_file}")
            
            # Integrate
            integrated_df = self.integrate_feedback(pred_df, feedback_df)
            
            # Save output
            output_path = os.path.join(output_dir, pred_file.replace('_predicted.csv', '_with_feedback.csv'))
            integrated_df.to_csv(output_path, index=False)
            logger.info(f"✓ {pred_file}: Integrated feedback, output to {os.path.basename(output_path)}")
    
    def process_directory_structure(self, pred_base_dir, feedback_base_dir, output_base_dir):
        """
        Process nested directory structure (dataset types).
        
        Args:
            pred_base_dir: Base predictions directory (e.g., ./IDS_heuristic_model_eval)
            feedback_base_dir: Base feedback directory (e.g., ./human_feedback)
            output_base_dir: Base output directory (e.g., ./IDS_with_feedback)
        """
        # Get all subdirectories (dataset types like 18events_30pct_fa_bal)
        dataset_dirs = sorted([d for d in os.listdir(pred_base_dir) 
                               if os.path.isdir(os.path.join(pred_base_dir, d))])
        
        logger.info(f"Processing {len(dataset_dirs)} dataset folders...\n")
        
        for dataset_dir in dataset_dirs:
            pred_dir = os.path.join(pred_base_dir, dataset_dir)
            feedback_dir = os.path.join(feedback_base_dir, dataset_dir)
            output_dir = os.path.join(output_base_dir, dataset_dir)
            
            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Dataset: {dataset_dir}")
            self.process_folder(pred_dir, feedback_dir, output_dir)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print feedback integration summary."""
        logger.info("\n" + "="*70)
        logger.info("FEEDBACK INTEGRATION SUMMARY")
        logger.info("="*70)
        logger.info(f"Total rows processed:        {self.feedback_stats['total_rows']}")
        logger.info(f"Rows with human feedback:    {self.feedback_stats['with_feedback']}")
        logger.info(f"  - Agreements:              {self.feedback_stats['agreements']}")
        logger.info(f"  - Disagreements:           {self.feedback_stats['disagreements']}")
        logger.info("")
        logger.info("NOTE: Model predictions NEVER flip. Confidence adjusts based on feedback.")
        logger.info("")
        
        if self.feedback_stats['with_feedback'] > 0:
            disagreement_rate = self.feedback_stats['disagreements'] / self.feedback_stats['with_feedback'] * 100
            logger.info(f"Disagreement rate: {disagreement_rate:.1f}%")
        
        logger.info("\nRules with significant confidence reductions:")
        if self.rule_override_counts:
            for rule, count in sorted(self.rule_override_counts.items(), key=lambda x: x[1], reverse=True):
                logger.info(f"  - {rule}: {count} instances")
        else:
            logger.info("  (none)")
        logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Integrate human expert feedback with model predictions'
    )
    parser.add_argument(
        'predictions_dir',
        help='Input directory with model predictions (e.g., ./IDS_heuristic_model_eval)'
    )
    parser.add_argument(
        'feedback_dir',
        help='Input directory with human feedback CSVs (e.g., ./human_feedback)'
    )
    parser.add_argument(
        '--output-dir',
        default='./IDS_with_feedback',
        help='Output directory for integrated results (default: ./IDS_with_feedback)'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.predictions_dir):
        logger.error(f"Predictions directory not found: {args.predictions_dir}")
        sys.exit(1)
    
    if not os.path.exists(args.feedback_dir):
        logger.warning(f"Feedback directory not found: {args.feedback_dir} (will create)")
        os.makedirs(args.feedback_dir, exist_ok=True)
    
    # Process
    integrator = HumanFeedbackIntegrator()
    integrator.process_directory_structure(
        args.predictions_dir,
        args.feedback_dir,
        args.output_dir
    )
    
    logger.info(f"\nOutput saved to: {args.output_dir}")


if __name__ == '__main__':
    main()
