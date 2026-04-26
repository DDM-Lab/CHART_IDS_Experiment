"""
IDS Pipeline: Parameter Testing (Simplified)

Tests parameter combinations by running the pipeline with different configs
and checking if valid CSVs are generated.
"""

import subprocess
import sys
from pathlib import Path
from datetime import datetime
import pandas as pd

TEST_CASES = [
    {"run": 1, "events": 18, "fa_bin": "standard", "ratio_mode": "balanced", "label": "MIN events (18)"},
    {"run": 2, "events": 30, "fa_bin": "zero", "ratio_mode": "balanced", "label": "FA = 0% (zero)"},
    {"run": 3, "events": 30, "fa_bin": "standard", "ratio_mode": "balanced", "label": "BASELINE (standard)"},
    {"run": 4, "events": 30, "fa_bin": "high", "ratio_mode": "balanced", "label": "FA = 40% (high)"},
    {"run": 5, "events": 30, "fa_bin": "standard", "ratio_mode": "port_heavy", "label": "Ratio = port_heavy"},
    {"run": 6, "events": 45, "fa_bin": "standard", "ratio_mode": "balanced", "label": "MAX events (45)"},
]

SCENARIOS = ["WannaCry", "Data_Theft", "ShellShock", "Netcat_Backdoor", "passwd_gzip_scp"]


def update_main_py(events, fa_bin, ratio_mode):
    """Update main.py parameters."""
    main_py = Path("main.py")
    content = main_py.read_text()
    
    # Simple string replacements
    content = content.replace(
        "TOTAL_EVENTS_PER_TABLE = 30",
        f"TOTAL_EVENTS_PER_TABLE = {events}"
    )
    content = content.replace(
        'FALSE_ALARM_BIN = "standard"',
        f'FALSE_ALARM_BIN = "{fa_bin}"'
    )
    content = content.replace(
        'FA_TYPE_RATIO_MODE = "balanced"',
        f'FA_TYPE_RATIO_MODE = "{ratio_mode}"'
    )
    
    main_py.write_text(content)


def run_pipeline():
    """Run the pipeline and return True if successful."""
    try:
        result = subprocess.run(
            [sys.executable, "main.py"],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except:
        return False


def validate_csvsexist():
    """Check if valid CSVs exist in IDS_tables."""
    ids_tables = Path("IDS_tables")
    
    if not ids_tables.exists():
        return False, "IDS_tables not found"
    
    # Look for CSVs recursively
    csv_files = list(ids_tables.rglob("*.csv"))
    
    if len(csv_files) < 5:
        return False, f"Only {len(csv_files)}/5 CSVs found"
    
    # Check each scenario
    for scenario in SCENARIOS:
        matching = list(ids_tables.rglob(f"{scenario}_*_events.csv"))
        
        if not matching:
            return False, f"Missing {scenario}"
        
        try:
            df = pd.read_csv(matching[0])
            if len(df) < 15 or len(df) > 50:  # Reasonable event count
                return False, f"{scenario}: suspicious row count {len(df)}"
            if len(df.columns) != 21:
                return False, f"{scenario}: wrong column count {len(df.columns)}"
        except:
            return False, f"{scenario}: can't read CSV"
    
    return True, "OK"


def main():
    print("\n" + "="*70)
    print("IDS PIPELINE PARAMETER TESTING (SIMPLIFIED)")
    print("="*70)
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Testing {len(TEST_CASES)} parameter combinations")
    print("="*70 + "\n")
    
    passed = 0
    failed = 0
    failures = []
    
    for test in TEST_CASES:
        run = test["run"]
        label = test["label"]
        
        print(f"[RUN {run}/{len(TEST_CASES)}] {label:40s}", end=" ")
        print(f"({test['events']}e | {test['fa_bin']:5s} FA | {test['ratio_mode']})", end=" ")
        sys.stdout.flush()
        
        try:
            # Update config
            update_main_py(test['events'], test['fa_bin'], test['ratio_mode'])
            
            # Run pipeline
            if not run_pipeline():
                print("❌ EXEC FAILED")
                failed += 1
                failures.append((run, label, "Pipeline execution failed"))
                continue
            
            # Validate output
            valid, msg = validate_csvsexist()
            
            if valid:
                print("✅ PASS")
                passed += 1
            else:
                print(f"❌ FAIL ({msg})")
                failed += 1
                failures.append((run, label, msg))
        
        except Exception as e:
            print(f"❌ ERROR: {str(e)[:30]}")
            failed += 1
            failures.append((run, label, str(e)[:50]))
    
    # Reset main.py
    print("\nResetting main.py to defaults...", end=" ")
    update_main_py(30, "standard", "balanced")
    print("Done")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Passed: {passed}/{len(TEST_CASES)} ✅")
    print(f"Failed: {failed}/{len(TEST_CASES)} ❌")
    print(f"Pass rate: {(passed/len(TEST_CASES)*100):.0f}%")
    
    if failures:
        print("\n❌ FAILURES:")
        for run, label, msg in failures:
            print(f"  Run {run}: {label:40s} - {msg}")
    else:
        print("\n✅ ALL TESTS PASSED!")
    
    print(f"\nEnd: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
