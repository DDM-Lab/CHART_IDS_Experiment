"""Debug why certain parameter combinations fail"""
import re
from pathlib import Path
import subprocess
import sys
import shutil

def modify_main(events, fa_bin, ratio_mode):
    main_py = Path('main.py').read_text()
    main_py = re.sub(r'TOTAL_EVENTS_PER_TABLE = \d+', f'TOTAL_EVENTS_PER_TABLE = {events}', main_py)
    main_py = re.sub(r'FALSE_ALARM_BIN = "[^"]*"', f'FALSE_ALARM_BIN = "{fa_bin}"', main_py)
    main_py = re.sub(r'FA_TYPE_RATIO_MODE = "[^"]*"', f'FA_TYPE_RATIO_MODE = "{ratio_mode}"', main_py)
    Path('main.py').write_text(main_py)

# Test the failing combinations
failures = [
    {"name": "45 events", "events": 45, "fa_bin": "standard", "ratio_mode": "balanced"},
    {"name": "30 events + high FA", "events": 30, "fa_bin": "high", "ratio_mode": "balanced"},
    {"name": "45 events + high FA", "events": 45, "fa_bin": "high", "ratio_mode": "port_heavy"},
]

for test in failures:
    print(f"\n{'='*70}")
    print(f"Testing: {test['name']}")
    print(f"Params: {test['events']} events | {test['fa_bin']} FA | {test['ratio_mode']}")
    print('='*70)
    
    # Clean and modify
    if Path('IDS_tables').exists():
        shutil.rmtree('IDS_tables')
    modify_main(test['events'], test['fa_bin'], test['ratio_mode'])
    
    # Run pipeline and capture last 50 lines
    result = subprocess.run(
        [sys.executable, 'main.py'],
        capture_output=True,
        text=True,
        timeout=300,
        stdin=subprocess.DEVNULL
    )
    
    if result.returncode == 0:
        print("✅ SUCCESS")
    else:
        print(f"❌ FAILED (exit code {result.returncode})")
        print("\nLast 50 lines of output:")
        lines = (result.stdout + result.stderr).split('\n')
        for line in lines[-50:]:
            if line.strip():
                print(line)
