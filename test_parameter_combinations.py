"""
IDS Pipeline Parameter Testing Suite

Systematically tests 20 parameter combinations to validate pipeline robustness.
Executes test matrix, validates output, and generates summary report.
"""

import subprocess
import json
import csv
from pathlib import Path
from datetime import datetime
import sys
import pandas as pd

# ============================================================
# TEST MATRIX: 20 Strategic Parameter Combinations
# ============================================================

TEST_MATRIX = [
    # Phase 1: Edge Cases (Event Count)
    {"run": 1, "events": 18, "fa_bin": "standard", "ratio_mode": "balanced", "phase": "Edge Cases (Min)"},
    {"run": 2, "events": 45, "fa_bin": "standard", "ratio_mode": "balanced", "phase": "Edge Cases (Max)"},
    {"run": 3, "events": 30, "fa_bin": "standard", "ratio_mode": "balanced", "phase": "Baseline"},
    
    # Phase 2: False Alarm Bins (All Options)
    {"run": 4, "events": 30, "fa_bin": "zero", "ratio_mode": "balanced", "phase": "FA Bins"},
    {"run": 5, "events": 30, "fa_bin": "very_conservative", "ratio_mode": "balanced", "phase": "FA Bins"},
    {"run": 6, "events": 30, "fa_bin": "conservative", "ratio_mode": "balanced", "phase": "FA Bins"},
    {"run": 7, "events": 30, "fa_bin": "elevated", "ratio_mode": "balanced", "phase": "FA Bins"},
    {"run": 8, "events": 30, "fa_bin": "high", "ratio_mode": "balanced", "phase": "FA Bins"},
    
    # Phase 3: Ratio Modes (All Options)
    {"run": 9, "events": 30, "fa_bin": "standard", "ratio_mode": "port_heavy", "phase": "Ratio Modes"},
    {"run": 10, "events": 30, "fa_bin": "standard", "ratio_mode": "volume_heavy", "phase": "Ratio Modes"},
    {"run": 11, "events": 30, "fa_bin": "standard", "ratio_mode": "duration_heavy", "phase": "Ratio Modes"},
    
    # Phase 4: Interaction Tests
    {"run": 12, "events": 18, "fa_bin": "zero", "ratio_mode": "balanced", "phase": "Interactions"},
    {"run": 13, "events": 45, "fa_bin": "high", "ratio_mode": "port_heavy", "phase": "Interactions"},
    {"run": 14, "events": 25, "fa_bin": "elevated", "ratio_mode": "volume_heavy", "phase": "Interactions"},
    {"run": 15, "events": 35, "fa_bin": "very_conservative", "ratio_mode": "duration_heavy", "phase": "Interactions"},
    
    # Phase 5: Reproducibility (Repeat Critical Runs)
    {"run": 16, "events": 30, "fa_bin": "standard", "ratio_mode": "balanced", "phase": "Reproducibility", "is_repeat": True, "repeat_of": 3},
    {"run": 17, "events": 18, "fa_bin": "zero", "ratio_mode": "balanced", "phase": "Reproducibility", "is_repeat": True, "repeat_of": 12},
    {"run": 18, "events": 45, "fa_bin": "high", "ratio_mode": "port_heavy", "phase": "Reproducibility", "is_repeat": True, "repeat_of": 13},
    
    # Phase 6: Final Validation
    {"run": 19, "events": 33, "fa_bin": "conservative", "ratio_mode": "balanced", "phase": "Final Validation"},
]

SCENARIOS = [
    "WannaCry",
    "Data_Theft",
    "ShellShock",
    "Netcat_Backdoor",
    "passwd_gzip_scp",
]

# ============================================================
# TEST EXECUTION FUNCTIONS
# ============================================================

def modify_main_py(events: int, fa_bin: str, ratio_mode: str):
    """
    Temporarily modify main.py with test parameters.
    
    Args:
        events: TOTAL_EVENTS_PER_TABLE value
        fa_bin: FALSE_ALARM_BIN value
        ratio_mode: FA_TYPE_RATIO_MODE value
    """
    main_py_path = Path("main.py")
    
    # Read original file
    content = main_py_path.read_text()
    
    # Replace parameter values
    content = content.replace(
        'TOTAL_EVENTS_PER_TABLE = 30',
        f'TOTAL_EVENTS_PER_TABLE = {events}'
    )
    content = content.replace(
        'FALSE_ALARM_BIN = "standard"',
        f'FALSE_ALARM_BIN = "{fa_bin}"'
    )
    content = content.replace(
        'FA_TYPE_RATIO_MODE = "balanced"',
        f'FA_TYPE_RATIO_MODE = "{ratio_mode}"'
    )
    
    # Write modified file
    main_py_path.write_text(content)
    
    print(f"  Modified main.py: events={events}, fa_bin={fa_bin}, ratio_mode={ratio_mode}")


def reset_main_py():
    """Reset main.py to baseline defaults."""
    main_py_path = Path("main.py")
    content = main_py_path.read_text()
    
    # Reset to defaults
    content = content.replace(
        'TOTAL_EVENTS_PER_TABLE = ' + str.split(content, 'TOTAL_EVENTS_PER_TABLE = ')[1].split('\n')[0],
        'TOTAL_EVENTS_PER_TABLE = 30'
    )
    
    # Easier approach: just restore from template
    main_py_path.write_text('''"""
IDS Pipeline - Main Entry Point

Simple, parameterized pipeline orchestrator.
Set your configuration parameters below, then run.
"""

from helper_functions import PipelineConfig, run_pipeline


# ============================================================
# USER CONFIGURATION
# ============================================================
# Modify these three lines to customize the pipeline run:

TOTAL_EVENTS_PER_TABLE = 30           # Range: 18-45 events per table
FALSE_ALARM_BIN = "standard"         # Options: zero | very_conservative | conservative | standard | elevated | high
FA_TYPE_RATIO_MODE = "balanced"      # Options: balanced | port_heavy | volume_heavy | duration_heavy

# ============================================================
# END OF USER CONFIGURATION
# ============================================================


if __name__ == "__main__":
    # Create configuration object with validation
    config = PipelineConfig(
        total_events_per_table=TOTAL_EVENTS_PER_TABLE,
        false_alarm_bin=FALSE_ALARM_BIN,
        fa_type_ratio_mode=FA_TYPE_RATIO_MODE
    )
    
    # Run the pipeline
    run_pipeline(config)
''')
    print("  Reset main.py to defaults")


def run_pipeline():
    """Execute main.py and capture output."""
    try:
        result = subprocess.run(
            [sys.executable, "main.py"],
            capture_output=True,
            text=True,
            timeout=120  # 2-minute timeout per run
        )
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout[-500:] if result.stdout else "",  # Last 500 chars
            "stderr": result.stderr[-500:] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "TIMEOUT: Pipeline took >2 minutes",
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"ERROR: {str(e)}",
        }


def validate_output(expected_events: int) -> dict:
    """
    Validate pipeline output CSVs.
    
    Args:
        expected_events: Expected row count per scenario
        
    Returns:
        dict: Validation results
    """
    ids_tables_path = Path("IDS_tables")
    results = {
        "files_found": 0,
        "csv_count": 0,
        "structure_valid": True,
        "row_counts": {},
        "label_distribution": {},
        "errors": []
    }
    
    # Check if IDS_tables exists
    if not ids_tables_path.exists():
        results["errors"].append("IDS_tables folder not found")
        return results
    
    # The pipeline creates CSVs in subdirectories, find them recursively
    csv_files = list(ids_tables_path.glob("*/*.csv"))
    results["files_found"] = len(csv_files)
    results["csv_count"] = len(csv_files)
    
    # Validate each CSV
    for scenario in SCENARIOS:
        # Look recursively in subdirectories
        matching_files = list(ids_tables_path.glob(f"*/{scenario}_*_events.csv"))
        
        if not matching_files:
            results["errors"].append(f"Missing CSV for {scenario}")
            results["structure_valid"] = False
            continue
        
        csv_file = matching_files[0]
        
        try:
            df = pd.read_csv(csv_file)
            
            # Check row count (allow ±1 due to TIER 1 variability)
            row_count = len(df)
            results["row_counts"][scenario] = row_count
            
            if not (expected_events - 1 <= row_count <= expected_events + 1):
                results["errors"].append(
                    f"{scenario}: Expected {expected_events}±1 rows, got {row_count}"
                )
                results["structure_valid"] = False
            
            # Check columns (should have 21 columns post-assembly)
            expected_cols = 21
            if len(df.columns) != expected_cols:
                results["errors"].append(
                    f"{scenario}: Expected {expected_cols} columns, got {len(df.columns)}"
                )
                results["structure_valid"] = False
            
            # Check label distribution
            label_counts = df["label"].value_counts().to_dict()
            results["label_distribution"][scenario] = label_counts
            
            # Spot-check: should have some malicious, benign, false alarm
            if "Malicious" not in label_counts or label_counts["Malicious"] < 10:
                results["errors"].append(f"{scenario}: Malicious count looks low ({label_counts.get('Malicious', 0)})")
            
        except Exception as e:
            results["errors"].append(f"{scenario}: {str(e)}")
            results["structure_valid"] = False
    
    return results


# ============================================================
# MAIN TEST EXECUTION
# ============================================================

def main():
    """Execute full test suite."""
    print("\n" + "="*70)
    print("IDS PIPELINE PARAMETER TESTING SUITE")
    print("="*70)
    print(f"Start time: {datetime.now().isoformat()}")
    print(f"Total runs: {len(TEST_MATRIX)}")
    print("="*70 + "\n")
    
    # Results tracking
    results = []
    
    # Execute each test
    for test in TEST_MATRIX:
        run_num = test["run"]
        is_repeat = test.get("is_repeat", False)
        repeat_label = f" (repeat of run {test.get('repeat_of', '')})" if is_repeat else ""
        
        print(f"\n[RUN {run_num:2d}/{len(TEST_MATRIX)}]{repeat_label}")
        print(f"  Phase: {test['phase']}")
        print(f"  Parameters: events={test['events']}, fa_bin={test['fa_bin']}, ratio_mode={test['ratio_mode']}")
        
        try:
            # Modify main.py
            modify_main_py(test['events'], test['fa_bin'], test['ratio_mode'])
            
            # Run pipeline
            print("  Executing pipeline...")
            exec_result = run_pipeline()
            
            # Validate output
            validation_result = validate_output(test['events'])
            
            # Compile results
            test_result = {
                "run": run_num,
                "phase": test['phase'],
                "events": test['events'],
                "fa_bin": test['fa_bin'],
                "ratio_mode": test['ratio_mode'],
                "exec_success": exec_result["success"],
                "exec_returncode": exec_result["returncode"],
                "csv_count": validation_result["csv_count"],
                "structure_valid": validation_result["structure_valid"],
                "errors": "; ".join(validation_result["errors"][:3]) if validation_result["errors"] else "None",
            }
            
            # Print result
            status = "✅ PASS" if (exec_result["success"] and validation_result["structure_valid"]) else "❌ FAIL"
            exec_status = "Success" if exec_result["success"] else f"Failed (code {exec_result['returncode']})"
            print(f"  Result: {status}")
            print(f"    • Execution: {exec_status}")
            print(f"    • CSV files: {validation_result['csv_count']}/5")
            print(f"    • Structure valid: {validation_result['structure_valid']}")
            if validation_result['errors']:
                for err in validation_result['errors'][:2]:  # Show first 2 errors
                    print(f"    • Error: {err}")
            
            results.append(test_result)
            
        except Exception as e:
            print(f"  Result: ❌ FAIL (Exception)")
            print(f"    • Error: {str(e)}")
            results.append({
                "run": run_num,
                "phase": test['phase'],
                "events": test['events'],
                "fa_bin": test['fa_bin'],
                "ratio_mode": test['ratio_mode'],
                "exec_success": False,
                "exec_returncode": -1,
                "csv_count": 0,
                "structure_valid": False,
                "errors": str(e)[:100],
            })
    
    # Reset main.py to defaults
    print("\n" + "="*70)
    print("Resetting main.py to defaults...")
    reset_main_py()
    
    # Generate summary report
    print("="*70)
    print("SUMMARY REPORT")
    print("="*70 + "\n")
    
    # Calculate statistics
    total_runs = len(results)
    passed_runs = sum(1 for r in results if r["exec_success"] and r["structure_valid"])
    failed_runs = total_runs - passed_runs
    pass_rate = (passed_runs / total_runs) * 100 if total_runs > 0 else 0
    
    print(f"Total runs: {total_runs}")
    print(f"Passed: {passed_runs} ✅")
    print(f"Failed: {failed_runs} ❌")
    print(f"Pass rate: {pass_rate:.1f}%")
    print()
    
    # Summary by phase
    print("Results by phase:")
    for phase in ["Edge Cases (Min)", "Edge Cases (Max)", "Baseline", "FA Bins", "Ratio Modes", "Interactions", "Reproducibility", "Final Validation"]:
        phase_results = [r for r in results if r["phase"] == phase]
        if phase_results:
            phase_passed = sum(1 for r in phase_results if r["exec_success"] and r["structure_valid"])
            phase_total = len(phase_results)
            status = "✅" if phase_passed == phase_total else "❌" if phase_passed == 0 else "⚠️"
            print(f"  {status} {phase}: {phase_passed}/{phase_total} passed")
    
    print()
    print("Failures (if any):")
    failures = [r for r in results if not (r["exec_success"] and r["structure_valid"])]
    if failures:
        for f in failures:
            print(f"  Run {f['run']:2d}: {f['errors']}")
    else:
        print("  None - all tests passed! 🎉")
    
    # Save results to CSV
    results_csv = Path("test_results_summary.csv")
    with open(results_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\nDetailed results saved to: {results_csv}")
    
    print(f"\nEnd time: {datetime.now().isoformat()}")
    print("="*70 + "\n")
    
    return passed_runs == total_runs  # Return True if all passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
