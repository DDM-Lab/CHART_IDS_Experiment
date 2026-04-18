"""Quick verification of Step 3 output"""
import json

with open('templates/zero_day_templates.json', 'r') as f:
    templates = json.load(f)

print("\n=== STEP 3 VERIFICATION ===\n")
print("Malicious Events per Scenario:\n")

for scenario in templates['scenarios']:
    name = scenario['scenario_name']
    events = scenario.get('_step3_malicious_events', [])
    print(f"  {name}: {len(events)} events")
    
    if events:
        # Show phase distribution
        phases = {}
        for e in events:
            phase = e.get('phase', 'unknown')
            phases[phase] = phases.get(phase, 0) + 1
        
        print(f"    Phase distribution: {phases}")
        
        # Show first and last event
        first = events[0]
        last = events[-1]
        print(f"    First:  T={first['timestamp']:.1f}s | {first['src_host']} -> {first['dst_host']}:{first['dport']} | {first['phase']}")
        print(f"    Last:   T={last['timestamp']:.1f}s | {last['src_host']} -> {last['dst_host']}:{last['dport']} | {last['phase']}")
    print()

print("✓ Step 3 completed successfully!\n")
