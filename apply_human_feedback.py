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
            'decisions_flipped': 0,
            'agreements': 0,
            'disagreements': 0
        }
    
    def compute_model_final_pred(self, model_pred, model_conf, human_feedback, human_conf):
        """
        Decide if model should flip its prediction based on human feedback.
        
        Decision flip logic:
        - If human agrees: no flip
        - If human disagrees: flip depends on human_conf vs model_conf
        
        Args:
            model_pred: "malicious" or "not malicious"
            model_conf: float [0.0-1.0]
            human_feedback: "malicious" or "not malicious" (or NaN if no feedback)
            human_conf: float [0.0-1.0] (or NaN if no feedback)
        
        Returns:
            tuple: (final_pred, flipped, flip_reason)
        """
        # No human feedback provided
        if pd.isna(human_feedback) or pd.isna(human_conf):
            return model_pred, False, "No human feedback provided"
        
        # Human agrees with model
        if human_feedback == model_pred:
            self.feedback_stats['agreements'] += 1
            return model_pred, False, f"Human agrees (conf={human_conf:.2f})"
        
        # Human disagrees - apply flip logic
        self.feedback_stats['disagreements'] += 1
        
        if human_conf >= 0.80:
            # Human very confident → FLIP to human's feedback
            self.feedback_stats['decisions_flipped'] += 1
            return human_feedback, True, f"Human very confident (conf={human_conf:.2f}) → FLIP"
        
        elif human_conf >= 0.70:
            # Human moderately confident
            if model_conf < 0.75:
                # Model was also uncertain → FLIP
                self.feedback_stats['decisions_flipped'] += 1
                return human_feedback, True, f"Both uncertain (model_conf={model_conf:.2f}, human_conf={human_conf:.2f}) → FLIP"
            else:
                # Model was confident → Keep original
                return model_pred, False, f"Model confident (conf={model_conf:.2f}), human moderate → KEEP model"
        
        elif human_conf >= 0.55:
            # Human weakly confident
            if model_conf < 0.65:
                # Model very uncertain → FLIP
                self.feedback_stats['decisions_flipped'] += 1
                return human_feedback, True, f"Model very weak (conf={model_conf:.2f}), human weak → FLIP"
            else:
                # Model reasonably confident → Keep original
                return model_pred, False, f"Model moderate (conf={model_conf:.2f}), human weak → KEEP model"
        
        else:  # human_conf < 0.55
            # Human very uncertain → NEVER flip, trust model
            return model_pred, False, f"Human very uncertain (conf={human_conf:.2f}) → TRUST model"
    
    def compute_final_confidence(self, model_conf, model_pred, human_conf, human_feedback, decision_flipped):
        """
        Compute final confidence after human feedback.
        
        Args:
            model_conf: Original model confidence
            model_pred: Original model prediction
            human_conf: Human's confidence
            human_feedback: Human's feedback
            decision_flipped: Whether decision was flipped
        
        Returns:
            float: Final model confidence
        """
        # Agreement cases
        if human_feedback == model_pred:
            if human_conf >= 0.85:
                # Human strongly validates - boost slightly
                return min(model_conf + 0.10, 0.95)
            elif human_conf >= 0.70:
                # Human agrees moderately - keep
                return model_conf
            else:
                # Human agrees weakly - slight boost
                return model_conf + 0.05
        
        # Disagreement cases
        if human_conf >= 0.85:
            # Human strong override - heavy penalty to model
            if model_conf < 0.70:
                return 0.40
            elif model_conf < 0.80:
                return (1.0 - model_conf) + 0.30
            else:
                return (1.0 - model_conf) + 0.15
        
        elif human_conf >= 0.70:
            # Human moderate override
            if model_conf < 0.70:
                return 0.50
            else:
                return (1.0 - model_conf) + 0.40
        
        elif human_conf >= 0.55:
            # Human weak override
            return (1.0 - model_conf) + 0.45
        
        else:
            # Human very uncertain - boost model
            return min(model_conf + 0.05, 0.80)
    
    def integrate_feedback(self, pred_df, feedback_df):
        """
        Merge model predictions with human feedback and compute adaptations.
        
        Args:
            pred_df: DataFrame with model predictions
            feedback_df: DataFrame with human feedback (id, human_feedback, human_confidence, human_explanation)
        
        Returns:
            DataFrame: Merged with new columns
        """
        # Merge on id
        result_df = pred_df.copy()
        
        # If feedback_df is empty, just add empty columns
        if feedback_df is None or len(feedback_df) == 0:
            result_df['human_feedback'] = None
            result_df['human_confidence'] = None
            result_df['human_explanation'] = None
            result_df['model_final_pred'] = result_df['prediction']
            result_df['model_final_conf'] = result_df['confidence']
            result_df['decision_flipped'] = False
            result_df['flip_reason'] = "No human feedback"
            result_df['rule_override_count'] = 0
            result_df['confidence_gap'] = 0.0
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
        
        # Compute model adaptations
        model_final_preds = []
        model_final_confs = []
        decision_flipped = []
        flip_reasons = []
        rule_counts = []
        confidence_gaps = []
        
        for _, row in result_df.iterrows():
            self.feedback_stats['total_rows'] += 1
            
            model_pred = row['prediction']
            model_conf = row['confidence']
            human_feedback = row.get('human_feedback', None)
            human_conf = row.get('human_confidence', None)
            anomaly_type = row.get('reason', 'unknown')
            
            # Compute decision flip
            final_pred, flipped, reason = self.compute_model_final_pred(
                model_pred, model_conf, human_feedback, human_conf
            )
            
            # Compute final confidence
            if pd.notna(human_feedback) and pd.notna(human_conf):
                final_conf = self.compute_final_confidence(
                    model_conf, model_pred, human_conf, human_feedback, flipped
                )
                self.feedback_stats['with_feedback'] += 1
                
                # Track rule override
                if flipped and anomaly_type not in ['No anomalies detected', 'unknown']:
                    self.rule_override_counts[anomaly_type] += 1
                
                # Confidence gap
                gap = abs(model_conf - human_conf)
            else:
                final_conf = model_conf
                gap = 0.0
            
            model_final_preds.append(final_pred)
            model_final_confs.append(final_conf)
            decision_flipped.append(flipped)
            flip_reasons.append(reason)
            rule_counts.append(self.rule_override_counts.get(anomaly_type, 0))
            confidence_gaps.append(gap)
        
        # Add new columns
        result_df['model_final_pred'] = model_final_preds
        result_df['model_final_conf'] = model_final_confs
        result_df['decision_flipped'] = decision_flipped
        result_df['flip_reason'] = flip_reasons
        result_df['rule_override_count'] = rule_counts
        result_df['confidence_gap'] = confidence_gaps
        
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
        logger.info(f"  - Decisions flipped:       {self.feedback_stats['decisions_flipped']}")
        
        if self.feedback_stats['with_feedback'] > 0:
            flip_rate = self.feedback_stats['decisions_flipped'] / self.feedback_stats['disagreements'] * 100
            logger.info(f"  - Flip rate on disagreement: {flip_rate:.1f}%")
        
        logger.info("\nRule Override Counts:")
        for rule, count in sorted(self.rule_override_counts.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  - {rule}: {count} overrides")
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
