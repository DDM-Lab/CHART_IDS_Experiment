from pathlib import Path

ids_tables = Path('IDS_tables')

# Try different search patterns
patterns = [
    'WannaCry_*_events.csv',
    'WannaCry_*',
    '*.csv',
]

print("Testing glob patterns:")
for pattern in patterns:
    matches = list(ids_tables.rglob(pattern))
    print(f'Pattern "{pattern}": {len(matches)} matches')
    if matches:
        for match in matches[:3]:
            print(f'  → {match.name}')

print("\nSearching for WannaCry with various methods:")
# Method 1: rglob
print(f"rglob('*WannaCry*'): {len(list(ids_tables.rglob('*WannaCry*')))}")

# Method 2: Direct check
wannacry_files = [f for f in ids_tables.rglob('*.csv') if 'WannaCry' in f.name]
print(f"Filter with 'WannaCry' in name: {len(wannacry_files)}")
if wannacry_files:
    print(f"  → {wannacry_files[0].name}")

# Method 3: Check glob with underscore
print(f"rglob('WannaCry_*_events.csv'): {len(list(ids_tables.rglob('WannaCry_*_events.csv')))}")

# List all files
print("\nAll CSV files found:")
for csv in sorted(ids_tables.rglob('*.csv')):
    print(f"  {csv.relative_to(ids_tables)}")
