"""
IDS Pipeline: Fast Parameter Testing Suite (Streamlined)

Tests 8 critical parameter combinations to validate pipeline robustness.
Focus on edge cases and key interactions, not full combinatorial coverage.
"""

import subprocess
import json
import csv
from pathlib import Path
from datetime import datetime
import sys
import pandas as pd
import shutil

# ============================================================
# CRITICAL TEST MATRIX: 8 Strategic Combinations
# ============================================================
# Focuses on edge cases + key interactions, not all combos
# Expected runtime: ~25-30 minutes (8 runs × 3-4 min each)

TEST_MATRIX = [
    # Edge cases: Event count extremes
    {"run": 1, "events": 18, "fa_bin": "standard", "ratio_mode": "balanced", "label": "MIN events (18)"},
    {"run": 2, "events": 45, "fa_bin": "standard", "ratio_mode": "balanced", "label": "MAX events (45)"},
    
    # FA bin extremes (at mid events)
    {"run": 3, "events": 30, "fa_bin": "zero", "ratio_mode": "balanced", "label": "FA = 0% (zero)"},
    {"run": 4, "events": 30, "fa_bin": "high", "ratio_mode": "balanced", "label": "FA = 40% (high)"},
    
    # Ratio mode variations
    {"run": 5, "events": 30, "fa_bin": "standard", "ratio_mode": "port_heavy", "label": "Ratio = port_heavy"},
    {"run": 6, "events": 30, "fa_bin": "standard", "ratio_mode": "volume_heavy", "label": "Ratio = volume_heavy"},
    
    # Interaction: max events + high FA
    {"run": 7, "events": 45, "fa_bin": "high", "ratio_mode": "port_heavy", "label": "Combined: MAX + HIGH FA"},
    
    # Baseline (current default)
    {"run": 8, "events": 30, "fa_bin": "standard", "ratio_mode": "balanced", "label": "BASELINE (current)"},
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
    """Temporarily modify main.py with test parameters."""
    main_py_path = Path("main.py")
    content = main_py_path.read_text()
    
    # Replace parameter values
    import re
    content = re.sub(
        r'TOTAL_EVENTS_PER_TABLE = \d+',
        f'TOTAL_EVENTS_PER_TABLE = {events}',
        content
    )
    content = re.sub(
        r'FALSE_ALARM_BIN = "[^"]*"',
        f'FALSE_ALARM_BIN = "{fa_bin}"',
        content
    )
    content = re.sub(
        r'FA_TYPE_RATIO_MODE = "[^"]*"',
        f'FA_TYPE_RATIO_MODE = "{ratio_mode}"',
        content
    )
    
    main_py_path.write_text(content)


def reset_main_py():
    """Reset main.py to baseline defaults."""
    main_py_path = Path("main.py")
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


def run_pipeline():
    """Execute main.py and capture output."""
    try:
        result = subprocess.run(
            [sys.executable, "main.py"],
            capture_output=True,
            text=True,
            timeout=300,  # 5-minute timeout per run
            stdin=subprocess.DEVNULL  # Don't inherit stdin from parent
        )
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "returncode": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
        }


def validate_output(expected_events: int) -> dict:
    """Validate pipeline output CSVs."""
    ids_tables_path = Path("IDS_tables")
    results = {
        "files_found": 0,
        "csv_count": 0,
        "structure_valid": True,
        "row_counts": {},
        "errors": []
    }
    
    if not ids_tables_path.exists():
        results["errors"].append("IDS_tables not found")
        return results
    
    # Find CSVs recursively (they're in subdirectories)
    all_csvs = list(ids_tables_path.rglob("*.csv"))
    results["csv_count"] = len(all_csvs)
    
    # DEBUG: Print what we found
    #print(f"\n    DEBUG: Found {len(all_csvs)} total CSVs")
    #for csv_file in all_csvs:
    #    print(f"      - {csv_file.name}")
    
    if len(all_csvs) == 0:
        results["errors"].append(f"No CSVs found in IDS_tables/")
        results["structure_valid"] = False
        return results
    
    if len(all_csvs) < 5:
        results["errors"].append(f"Only {len(all_csvs)}/5 CSVs found")
        results["structure_valid"] = False
        return results
    
    # Validate each scenario CSV
    for scenario in SCENARIOS:
        matching_files = list(ids_tables_path.rglob(f"{scenario}_*events.csv"))
        
        if not matching_files:
            results["errors"].append(f"Missing {scenario}")
            results["structure_valid"] = False
            continue
        
        csv_file = matching_files[0]  # Use first match if multiple
        
        try:
            df = pd.read_csv(csv_file)
            row_count = len(df)
            results["row_counts"][scenario] = row_count
            
            # Check row count tolerance (allow ±1 for TIER 1 variability)
            if not (expected_events - 1 <= row_count <= expected_events + 1):
                results["errors"].append(
                    f"{scenario}: got {row_count} rows, expected {expected_events}±1"
                )
                results["structure_valid"] = False
            
            # Check for critical columns (not exact count, as internal columns vary)
            critical_cols = ['timestamp', 'src_host', 'dst_host', 'src_ip', 'dst_ip', 
                           'dport', 'service', 'label', 'attack_cat', 'bytes', 'packets']
            missing_cols = [c for c in critical_cols if c not in df.columns]
            if missing_cols:
                results["errors"].append(f"{scenario}: missing columns {missing_cols}")
                results["structure_valid"] = False
            
        except Exception as e:
            results["errors"].append(f"{scenario}: {str(e)[:50]}")
            results["structure_valid"] = False
    
    return results


# ============================================================
# MAIN TEST EXECUTION
# ============================================================

def main():
    """Execute streamlined test suite."""
    print("\n" + "="*70)
    print("IDS PIPELINE: PARAMETER TESTING (STREAMLINED)")
    print("="*70)
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Runs: {len(TEST_MATRIX)}")
    print("Est. time: 25-30 minutes")
    print("="*70 + "\n")
    
    results = []
    passed = 0
    failed = 0
    
    for test in TEST_MATRIX:
        run_num = test["run"]
        label = test["label"]
        
        print(f"[RUN {run_num}/{len(TEST_MATRIX)}] {label}")
        print(f"  Params: {test['events']} events | {test['fa_bin']} FA | {test['ratio_mode']}")
        
        try:
            # Clean IDS_tables before run to isolate results
            ids_tables_path = Path("IDS_tables")
            if ids_tables_path.exists():
                shutil.rmtree(ids_tables_path)
            
            # Modify main.py
            modify_main_py(test['events'], test['fa_bin'], test['ratio_mode'])
            
            # Run pipeline
            print("  Executing...", end=" ", flush=True)
            exec_result = run_pipeline()
            
            if not exec_result["success"]:
                print(f"EXEC FAILED")
                results.append({"run": run_num, "label": label, "status": "FAIL", "reason": "Execution error"})
                failed += 1
                continue
            
            print("OK")
            
            # Validate output (IDS_tables still exists with fresh results)
            print("  Validating...", end=" ", flush=True)
            validation_result = validate_output(test['events'])
            
            if validation_result["structure_valid"]:
                print("✅ PASS")
                results.append({"run": run_num, "label": label, "status": "PASS", "reason": ""})
                passed += 1
            else:
                print("❌ FAIL")
                error_msg = "; ".join(validation_result["errors"][:2]) if validation_result["errors"] else "Unknown"
                results.append({"run": run_num, "label": label, "status": "FAIL", "reason": error_msg})
                failed += 1
            
        except Exception as e:
            print(f"❌ FAIL (Exception)")
            results.append({"run": run_num, "label": label, "status": "FAIL", "reason": str(e)[:50]})
            failed += 1
    
    # Reset main.py
    print("\n" + "="*70)
    reset_main_py()
    
    # Summary report
    print("SUMMARY REPORT")
    print("="*70)
    print(f"Total runs: {len(TEST_MATRIX)}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {failed} ❌")
    print(f"Pass rate: {(passed/len(TEST_MATRIX)*100):.0f}%")
    print()
    
    if failed > 0:
        print("❌ FAILURES:")
        for r in results:
            if r["status"] == "FAIL":
                print(f"  Run {r['run']:2d}: {r['label']:30s} - {r['reason']}")
    else:
        print("✅ ALL TESTS PASSED!")
    
    print()
    print(f"End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")
    
    # Save results
    with open("test_results_summary.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["run", "label", "status", "reason"])
        writer.writeheader()
        writer.writerows(results)
    print(f"Results saved to: test_results_summary.csv")
    
    return passed == len(TEST_MATRIX)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
