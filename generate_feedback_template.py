"""
Human Feedback Template Generator

Creates empty feedback CSVs for each model output, ready for human review.
Shows format: id, human_feedback, human_confidence, human_explanation

Usage:
    python generate_feedback_template.py <predictions_dir> --output-dir <feedback_dir>
"""

import pandas as pd
import os
import sys
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def generate_templates(pred_base_dir, feedback_base_dir):
    """
    Generate empty feedback CSV templates for all prediction files.
    
    Args:
        pred_base_dir: Base predictions directory
        feedback_base_dir: Base feedback directory to create
    """
    dataset_dirs = sorted([d for d in os.listdir(pred_base_dir) 
                           if os.path.isdir(os.path.join(pred_base_dir, d))])
    
    logger.info(f"Generating feedback templates for {len(dataset_dirs)} datasets...\n")
    
    for dataset_dir in dataset_dirs:
        pred_dir = os.path.join(pred_base_dir, dataset_dir)
        feedback_dir = os.path.join(feedback_base_dir, dataset_dir)
        Path(feedback_dir).mkdir(parents=True, exist_ok=True)
        
        pred_files = sorted([f for f in os.listdir(pred_dir) if f.endswith('_predicted.csv')])
        
        logger.info(f"Dataset: {dataset_dir} ({len(pred_files)} files)")
        
        for pred_file in pred_files:
            # Load prediction file to get IDs
            pred_path = os.path.join(pred_dir, pred_file)
            pred_df = pd.read_csv(pred_path)
            
            # Create feedback template
            feedback_df = pd.DataFrame({
                'id': pred_df['id'],
                'human_feedback': [None] * len(pred_df),  # Empty for human to fill
                'human_confidence': [None] * len(pred_df),  # Empty (0.0-1.0)
                'human_explanation': [None] * len(pred_df)  # Optional notes
            })
            
            # Save template
            template_file = pred_file.replace('_predicted.csv', '_feedback.csv')
            template_path = os.path.join(feedback_dir, template_file)
            feedback_df.to_csv(template_path, index=False)
            
            logger.info(f"  ✓ {template_file}")
    
    logger.info(f"\nFeedback templates created in: {feedback_base_dir}")
    logger.info("\nInstructions:")
    logger.info("  1. Open the feedback CSV files in Excel or text editor")
    logger.info("  2. For each row you review:")
    logger.info("     - human_feedback: enter 'malicious' or 'not malicious'")
    logger.info("     - human_confidence: enter 0.0-1.0 (0.5=uncertain, 0.9=very confident)")
    logger.info("     - human_explanation: optional - explain your decision")
    logger.info("  3. Leave rows blank if you don't review them")
    logger.info("  4. Run: python apply_human_feedback.py ./IDS_heuristic_model_eval ./human_feedback --output-dir ./IDS_with_feedback")


def main():
    parser = argparse.ArgumentParser(description='Generate feedback templates for model predictions')
    parser.add_argument(
        'predictions_dir',
        help='Input predictions directory (e.g., ./IDS_heuristic_model_eval)'
    )
    parser.add_argument(
        '--output-dir',
        default='./human_feedback',
        help='Output directory for feedback templates (default: ./human_feedback)'
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.predictions_dir):
        logger.error(f"Predictions directory not found: {args.predictions_dir}")
        sys.exit(1)
    
    generate_templates(args.predictions_dir, args.output_dir)


if __name__ == '__main__':
    main()
