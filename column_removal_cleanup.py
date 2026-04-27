"""
IDS Table Column Removal Utility

This script removes ground-truth columns from IDS tables for heuristic model development.
The rule-based model should not have access to these columns during development/testing.

Usage:
    python column_removal_cleanup.py <input_directory> [--output-dir <output_directory>]

Example:
    python column_removal_cleanup.py ./IDS_tables --output-dir ./IDS_cleaned_tables
"""

import os
import sys
import argparse
import logging
from pathlib import Path
import pandas as pd

cols_to_remove = ["_false_alarm_pct_param", "_malicious_count_param", "_benign_count_param", "_false_alarm_count_param", "attack_cat", "label", "_unsw_row_id","scenario_name", "_source", "phase" ]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_output_directory(output_dir: str) -> Path:
    """Create output directory if it doesn't exist."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {output_path.absolute()}")
    return output_path


def process_csv_file(input_file: Path, output_file: Path) -> bool:
    """
    Process a single CSV file: remove specified columns and save.
    
    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Read the CSV
        df = pd.read_csv(input_file)
        original_shape = df.shape
        
        # Find columns to remove that actually exist in this file
        columns_to_remove = [col for col in cols_to_remove if col in df.columns]
        
        # Remove the columns
        df_cleaned = df.drop(columns=columns_to_remove)
        final_shape = df_cleaned.shape
        
        # Save to output file
        df_cleaned.to_csv(output_file, index=False)
        
        # Log result
        logger.info(
            f"✓ {input_file.name}: "
            f"Shape {original_shape} → {final_shape} | "
            f"Removed {len(columns_to_remove)} columns"
        )
        
        if columns_to_remove:
            logger.debug(f"  Removed columns: {columns_to_remove}")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Failed to process {input_file.name}: {str(e)}")
        return False


def process_directory(input_dir: str, output_dir: str) -> tuple:
    """
    Recursively process all CSV files in the input directory.
    
    Args:
        input_dir: Input directory path
        output_dir: Output directory path
        
    Returns:
        Tuple of (successful_count, failed_count)
    """
    input_path = Path(input_dir)
    output_path = setup_output_directory(output_dir)
    
    # Validate input directory
    if not input_path.is_dir():
        logger.error(f"Input directory does not exist: {input_path}")
        return 0, 1
    
    # Find all CSV files recursively
    csv_files = list(input_path.rglob("*.csv"))
    
    if not csv_files:
        logger.warning(f"No CSV files found in {input_path}")
        return 0, 0
    
    logger.info(f"Found {len(csv_files)} CSV files to process")
    
    successful = 0
    failed = 0
    
    # Process each CSV file
    for csv_file in sorted(csv_files):
        # Preserve relative directory structure in output
        relative_path = csv_file.relative_to(input_path)
        relative_output_dir = output_path / relative_path.parent
        relative_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create output filename with _cleaned suffix
        stem = csv_file.stem
        output_filename = f"{stem}_cleaned.csv"
        output_file = relative_output_dir / output_filename
        
        if process_csv_file(csv_file, output_file):
            successful += 1
        else:
            failed += 1
    
    return successful, failed


def main():
    parser = argparse.ArgumentParser(
        description="Remove ground-truth columns from IDS tables for heuristic model development"
    )
    parser.add_argument(
        "input_directory",
        help="Input directory containing CSV files"
    )
    parser.add_argument(
        "--output-dir",
        default="./IDS_cleaned_tables",
        help="Output directory for cleaned CSV files (default: ./IDS_cleaned_tables)"
    )
    
    args = parser.parse_args()
    
    logger.info("=" * 70)
    logger.info("IDS Table Column Removal Utility")
    logger.info("=" * 70)
    logger.info(f"Columns to remove: {cols_to_remove}")
    logger.info("")
    
    # Process directory
    successful, failed = process_directory(
        args.input_directory,
        args.output_dir
    )
    
    # Summary
    logger.info("")
    logger.info("=" * 70)
    logger.info(f"Processing complete: {successful} successful, {failed} failed")
    logger.info("=" * 70)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
