# IDS Pipeline Parameterization Plan

**Date**: April 18, 2026  
**Purpose**: Design a flexible parameterization system to make IDS table size and event distribution configurable

---

## EXECUTIVE SUMMARY

### Current State
The IDS pipeline generates fixed-size tables:
- **Total events per scenario**: 30 (hard-coded)
- **Malicious events**: 10-11 (hard-coded, same for all scenarios)
- **Benign events**: 15 (hard-coded)
- **False alarm events**: 4-5 (hard-coded)

### Proposed Solution
**Three-tier parameterization strategy:**

1. **User-facing parameters** in `main.py` (2 inputs):
   - `total_events_per_table`: Configurable between 18-45 (default: 30)
   - `false_alarm_pct`: Configurable proportion (default: 0.15 = 15%)

2. **Scenario-specific fixed values** in `global_constraints.json`:
   - `malicious_count`: NOT parameterized; set in stone per scenario based on attack complexity
     - Simple attacks (passwd_gzip_scp, Netcat Backdoor): 7 events
     - Medium attacks (Data_Theft, ShellShock): 9 events
     - Complex attacks (WannaCry): 11 events

3. **Computed intermediate values** (derived from user inputs + scenario data):
   - `malicious_count`: Lookup from scenario in global_constraints
   - `false_alarm_count`: Calculated = round(total_events_per_table × false_alarm_pct)
   - `benign_count`: Calculated = total_events_per_table - malicious_count - false_alarm_count

4. **Step-level implementations**:
   - Step 3: Use scenario's fixed `malicious_count` (no selection logic needed)
   - Step 4: Generate `benign_count` events (calculated remainder)
   - Step 5: Generate `false_alarm_count` events (distributed across 3 types)
   - Step 6: Use all counts to validate and assemble final table

---

## CURRENT HARD-CODED VALUES

### Step 3: Malicious Events (step_3.py)
**Current Implementation**:
```python
# Hard-coded in global_constraints.json as "10-11 events"
# Implemented in step_3.py via _generate_tier1_events()
# TIER 1 sampling: randomly sample 10-11 UNSW rows
```

**Location**: 
- [global_constraints.json](../templates/global_constraints.json) - line ~9: `"count": "10-11 events"`
- [step_3.py](../step_3.py) - TIER 1 strategy for sampling

---

### Step 4: Benign Events (step_4.py)
**Current Implementation**:
```python
def _generate_benign_events_for_scenario(scenario_name, pooled_benign_df, template, constraints):
    num_events = 15  # ← Hard-coded
    if len(pooled_benign_df) < num_events:
        sampled_df = pooled_benign_df.copy()
    else:
        sampled_df = pooled_benign_df.sample(n=num_events, random_state=None)
```

**Location**: [step_4.py](../step_4.py) - line ~165: `num_events = 15`

---

### Step 5: False Alarm Events (step_5.py)
**Current Implementation**:
```python
FALSE_ALARM_TYPES = {
    'type_1_unusual_port_benign_service': {
        'count': 2,  # ← Hard-coded
        'description': '...',
        'anomaly': 'port',
    },
    'type_2_high_volume_benign_service': {
        'count': 2,  # ← Hard-coded
        'description': '...',
        'anomaly': 'bytes',
    },
    'type_3_rare_duration_benign_service': {
        'count': 1,  # ← Hard-coded
        'description': '...',
        'anomaly': 'duration',
    },
}
```

**Location**: [step_5.py](../step_5.py) - lines ~31-48: `'count': 2`, `'count': 2`, `'count': 1`

---

### Step 6: Final Assembly (step_6.py)
**Current Implementation**:
```python
TEMPORAL_ARCHITECTURE = {
    'WannaCry': {
        'total_duration': 1800,
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 6},
            {'name': 'attack_phase_1', 'start': 300, 'end': 600, 'type': 'attack', 'event_count': 4},
            {'name': 'attack_phase_2', 'start': 600, 'end': 900, 'type': 'attack', 'event_count': 4},
            {'name': 'attack_phase_3', 'start': 900, 'end': 1200, 'type': 'attack', 'event_count': 2},
            {'name': 'benign_recovery', 'start': 1200, 'end': 1800, 'type': 'benign', 'event_count': 9},
        ],
        ...
    },
    ...
}
```

**Key Note**: Phase `event_count` values sum to 30:
- Benign baseline: 6
- Attack phases (1+2+3): 4+4+2 = 10
- Benign recovery: 9
- Total: 6+10+9 = 25 benign/malicious
- Plus false alarms: 5
- **Grand total: 30**

**Location**: [step_6.py](../step_6.py) - lines ~30-85: Phase definitions

**Validation**: [step_6.py](../step_6.py) - lines ~220-230: Hardcoded range checks
```python
if not (10 <= malicious_count <= 11):
    errors.append(f"Malicious count {malicious_count} not in range [10-11]")
```

---

## PROPOSED PARAMETERIZATION ARCHITECTURE

### 1. User-Facing Parameters (main.py)

**New code in main()** before pipeline execution:

```python
# ============================================================
# USER-CONFIGURABLE PIPELINE PARAMETERS
# ============================================================

# Table size configuration
total_events_per_table = 30  # Range: 18-45 (default: 30)
if not (18 <= total_events_per_table <= 45):
    raise ValueError(
        f"total_events_per_table must be between 18 and 45, got {total_events_per_table}"
    )

# False alarm proportion (benign events automatically computed as remainder)
false_alarm_pct = 0.15  # Range: 0.05-0.30 (default: 0.15 = 15%)
if not (0.05 <= false_alarm_pct <= 0.30):
    raise ValueError(
        f"false_alarm_pct must be between 0.05 and 0.30, got {false_alarm_pct}"
    )

print(f"Pipeline Configuration:")
print(f"  Total events per table: {total_events_per_table}")
print(f"  False alarm proportion: {100*false_alarm_pct:.1f}%")
print(f"  (Malicious and Benign counts are scenario-specific and calculated by composition)")
```

**Validation Rules:**
- `total_events_per_table`: 18 ≤ N ≤ 45
- `false_alarm_pct`: 0.05 ≤ P ≤ 0.30 (ensures benign events get a reasonable share)
- Composition ensures: malicious + benign + false_alarm = total_events

### 2. Global Constraints Update (global_constraints.json)

**Add scenario-specific malicious event counts** (based on attack complexity analysis):

```json
{
  ...
  "label_distribution": {
    "total_events_per_table": 30,
    "total_events_min": 18,
    "total_events_max": 45,
    "false_alarm_pct_default": 0.15,
    "false_alarm_pct_min": 0.05,
    "false_alarm_pct_max": 0.30,
    "benign": {
      "count": "calculated",
      "percentage": "calculated",
      "definition": "Routine enterprise traffic unrelated to attack progression; fills remainder of table"
    },
    "false_alarm": {
      "count": "calculated",
      "percentage": "user_configurable",
      "definition": "Locally anomalous but globally benign events"
    }
  },
  
  "scenario_malicious_events": {
    "attack_complexity_levels": {
      "simple": {
        "description": "Direct linear attacks with minimal network movement",
        "scenarios": ["passwd_gzip_scp", "Netcat_Backdoor"],
        "malicious_count": 7,
        "rationale": "Credential theft or backdoor creation typically 6-8 network events total"
      },
      "medium": {
        "description": "Multi-phase attacks with discovery and exfiltration",
        "scenarios": ["Data_Theft", "ShellShock"],
        "malicious_count": 9,
        "rationale": "Requires discovery phase + staging phase + exfiltration phase"
      },
      "complex": {
        "description": "Worms or multi-system attacks with reconnaissance and lateral movement",
        "scenarios": ["WannaCry"],
        "malicious_count": 11,
        "rationale": "Must show scanning, exploitation, and spreading across multiple hosts"
      }
    },
    "WannaCry": {
      "malicious_count": 11,
      "complexity": "complex",
      "justification": "Ransomware worm with lateral movement (scanning + exploit + encryption on multiple systems)"
    },
    "Data_Theft": {
      "malicious_count": 9,
      "complexity": "medium",
      "justification": "Insider threat with discovery + staging + exfiltration via FTP/SSH"
    },
    "ShellShock": {
      "malicious_count": 9,
      "complexity": "medium",
      "justification": "Web exploitation with bash execution + data access + exfiltration"
    },
    "Netcat_Backdoor": {
      "malicious_count": 7,
      "complexity": "simple",
      "justification": "Backdoor installation and testing, minimal network movement"
    },
    "passwd_gzip_scp": {
      "malicious_count": 7,
      "complexity": "simple",
      "justification": "Direct credential theft: access + compress + transfer (linear sequence)"
    }
  },
  
  ...
}
```

**Changes from previous design:**
- ✅ Removed `distribution_malicious_pct`, `distribution_benign_pct` (no longer parameterized)
- ✅ Added `total_events_min`, `total_events_max` (enforce 18-45 range)
- ✅ Changed `false_alarm` from fixed count to parameterizable percentage
- ✅ Added new section `scenario_malicious_events` with per-scenario fixed values
- ✅ Marked `benign` and `false_alarm` counts as "calculated" (computed at runtime)
- ✅ Benign is always a remainder: `benign_count = total - malicious - false_alarm`

### 3. Step 3: Malicious Event Generation (step_3.py)

**Current function signature** (unchanged):
```python
def generate_malicious_events_step_3(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    random_seed=42
):
```

**Modification**: Read `malicious_count` from scenario data via global_constraints (no parameterization)

```python
def generate_malicious_events_step_3(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    random_seed=42,
    scenario_name=None  # Add parameter to identify scenario
):
    """
    Generate malicious events per scenario.
    
    Changes:
    - Read scenario-specific malicious_count from global_constraints
    - Count is FIXED per scenario (not parameterizable)
    """
    
    with open(global_constraints_path, 'r') as f:
        global_constraints = json.load(f)
    
    # Lookup scenario's fixed malicious count (no user selection)
    if scenario_name not in global_constraints['scenario_malicious_events']:
        raise ValueError(f"Scenario {scenario_name} not found in global_constraints")
    
    malicious_count = global_constraints['scenario_malicious_events'][scenario_name]['malicious_count']
    
    # In _generate_tier1_events():
    # Replace: num_sampled = min(10 + random.randint(0, 1), len(filtered_df))
    # With: num_sampled = min(malicious_count, len(filtered_df))
    
    # Similar change for _generate_tier2_events()
```

**Key difference from previous design:**
- ❌ NO percentage-based calculation
- ✅ Direct lookup from `scenario_malicious_events[scenario_name]['malicious_count']`
- ✅ If data insufficient, TIER 2/3 fallback still applies (maintains synthesis framework)
- ✅ Simplifies Step 3 logic (no parameterization needed)

---

### 4. Step 4: Benign Event Generation (step_4.py)

**Modification**: Read `benign_count` from computed value (calculated as remainder)

```python
def generate_benign_events_step_4(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    total_events_per_table,
    false_alarm_count,
    scenario_name,
    random_seed=42
):
    """Generate benign events with computed count (remainder of table)"""
    
    with open(global_constraints_path, 'r') as f:
        global_constraints = json.load(f)
    
    # Get malicious count for this scenario
    malicious_count = global_constraints['scenario_malicious_events'][scenario_name]['malicious_count']
    
    # Calculate benign as remainder
    benign_count = total_events_per_table - malicious_count - false_alarm_count
    
    if benign_count < 5:
        raise ValueError(
            f"Insufficient benign slots: total={total_events_per_table}, "
            f"malicious={malicious_count}, false_alarm={false_alarm_count}. "
            f"Benign would be {benign_count} (minimum 5 required)"
        )
    
    # Pass benign_count to _generate_benign_events_for_scenario()
```

**In `_generate_benign_events_for_scenario()`**:
```python
def _generate_benign_events_for_scenario(scenario_name, pooled_benign_df, template, constraints, benign_count):
    """Generate benign_count events for scenario (calculated as remainder)"""
    
    num_events = benign_count  # Use parameter (not hard-coded 15)
    if len(pooled_benign_df) < num_events:
        # Log warning if insufficient real data
        print(f"  [WARN] Only {len(pooled_benign_df)} benign rows available, generating {num_events} events...")
        sampled_df = pooled_benign_df.copy()
    else:
        sampled_df = pooled_benign_df.sample(n=num_events, random_state=None)
    
    # Rest of generation logic unchanged
```

**Key insight:**
- Benign count is always a **dynamic remainder**: `benign = total - malicious - false_alarm`
- This ensures the table always sums to the target total
- Minimum constraint: benign ≥ 5 (must have meaningful baseline traffic)

---

### 5. Step 5: False Alarm Event Generation (step_5.py)

**Modification**: Use computed `false_alarm_count` (from user's false_alarm_pct parameter)

```python
def generate_false_alarms_step_5(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    total_events_per_table,
    false_alarm_pct,
    random_seed=42
):
    """Generate false alarm events with user-configured proportion"""
    
    with open(global_constraints_path, 'r') as f:
        global_constraints = json.load(f)
    
    # Compute false_alarm_count from user percentage
    false_alarm_count = round(total_events_per_table * false_alarm_pct)
    
    # Validate reasonable bounds
    if false_alarm_count < 3:
        raise ValueError(f"false_alarm_count must be ≥3 for meaningful triage, got {false_alarm_count}")
    if false_alarm_count > 10:
        print(f"  [WARN] false_alarm_count={false_alarm_count} is high; consider reducing false_alarm_pct")
    
    # Calculate type-specific counts (maintain 2:2:1 ratio if possible)
    # Rule: Keep Type 3 as 1 event (represents "rare duration" - singleton)
    # Distribute remaining between Type 1 and Type 2 (50/50)
    
    if false_alarm_count < 3:
        # Edge case: fewer than 3 events
        type_1_count = max(1, false_alarm_count // 3)
        type_2_count = max(1, false_alarm_count // 3)
        type_3_count = false_alarm_count - type_1_count - type_2_count
    else:
        # Standard distribution (aim for 2:2:1)
        type_3_count = 1  # Reserved for "rare duration" singleton
        remaining = false_alarm_count - type_3_count
        type_1_count = remaining // 2
        type_2_count = remaining - type_1_count
    
    # Update FALSE_ALARM_TYPES dynamically
    FALSE_ALARM_TYPES['type_1_unusual_port_benign_service']['count'] = type_1_count
    FALSE_ALARM_TYPES['type_2_high_volume_benign_service']['count'] = type_2_count
    FALSE_ALARM_TYPES['type_3_rare_duration_benign_service']['count'] = type_3_count
    
    # Rest of generation logic unchanged
    # (loops already use FALSE_ALARM_TYPES['count'] dynamically)
```

**Distribution examples:**
| User false_alarm_pct | Total events | false_alarm_count | Type 1 | Type 2 | Type 3 |
|----------------------|--------------|-------------------|--------|--------|--------|
| 0.10 (10%) | 30 | 3 | 1 | 1 | 1 |
| 0.15 (15%) | 30 | 5 | 2 | 2 | 1 |
| 0.20 (20%) | 30 | 6 | 2 | 3 | 1 |
| 0.15 (15%) | 36 | 5 | 2 | 2 | 1 |
| 0.15 (15%) | 45 | 7 | 3 | 3 | 1 |

---

### 6. Step 6: Final Assembly & Temporal Ordering (step_6.py)

**Simplification**: All event counts are already computed; Step 6 just allocates them to phases

```python
def assemble_30_events_step_6(
    templates_path,
    global_constraints_path,
    output_dir="IDS_tables",
    output_report_path="step_6_summary.txt",
    total_events_per_table,
    malicious_count_per_scenario,  # dict: {scenario_name: count}
    benign_count_per_scenario,      # dict: {scenario_name: count}
    false_alarm_count,               # scalar (same for all scenarios)
    random_seed=42
):
    """Assemble final events with pre-computed counts"""
    
    # For each scenario, the counts are already determined:
    # - malicious_count = scenario-specific (from global_constraints)
    # - benign_count = calculated remainder
    # - false_alarm_count = round(total * user_false_alarm_pct)
    # - total = user_total_events_per_table
    
    for scenario_name in SCENARIOS:
        mal_count = malicious_count_per_scenario[scenario_name]
        ben_count = benign_count_per_scenario[scenario_name]
        fa_count = false_alarm_count
        
        # Build temporal architecture with known event counts
        TEMPORAL_ARCHITECTURE = _build_temporal_architecture(
            scenario_name,
            mal_count,
            ben_count,
            fa_count,
            total_duration=1800
        )
```

**Key insight**: All counts are pre-computed before Step 6, so no dynamic calculation needed in this step.
```
Phase 0 (benign_baseline):  6 benign events      (0-300s)
Phase 1 (attack):          4 malicious events    (300-600s)
Phase 2 (attack):          4 malicious events    (600-900s)
Phase 3 (attack):          2 malicious events    (900-1200s)
Phase 4 (benign_recovery):  9 benign + 5 FA      (1200-1800s)
Total: 30 events (10 mal + 15 ben + 5 FA)
```

**Proposed Approach**: Dynamically construct phase architecture

```python
def assemble_30_events_step_6(
    templates_path,
    global_constraints_path,
    output_dir="IDS_tables",
    output_report_path="step_6_summary.txt",
    random_seed=42
):
    """Assemble final events with configurable counts and temporal allocation"""
    
    with open(global_constraints_path, 'r') as f:
        global_constraints = json.load(f)
    
    malicious_count = global_constraints['label_distribution']['malicious']['count']
    benign_count = global_constraints['label_distribution']['benign']['count']
    false_alarm_count = global_constraints['label_distribution']['false_alarm']['count']
    total_events = global_constraints['label_distribution']['total_events_per_table']
    
    # Dynamically build TEMPORAL_ARCHITECTURE for each scenario
    
    TEMPORAL_ARCHITECTURE = _build_temporal_architecture(
        scenario_name,
        malicious_count,
        benign_count,
        false_alarm_count,
        total_duration=1800  # Keep observation window fixed
    )
```

**Helper Function**:
```python
def _build_temporal_architecture(scenario_name, mal_count, ben_count, fa_count, total_duration=1800):
    """
    Construct phase-based temporal architecture dynamically.
    
    Strategy:
    1. Reserve benign_baseline phase (0-300s): 20% of benign events
    2. Allocate malicious events across attack phases (300-1200s)
    3. Reserve benign_recovery phase (1200-1800): 80% of benign + all false alarms
    
    Args:
        scenario_name: Scenario identifier
        mal_count: Number of malicious events
        ben_count: Number of benign events
        fa_count: Number of false alarm events
        total_duration: Observation window in seconds (default 1800)
    
    Returns:
        dict: TEMPORAL_ARCHITECTURE configuration for scenario
    """
    
    # Phase time allocation (based on typical SOC attack progression)
    baseline_duration = 300
    attack_duration = 900  # 300-1200s
    recovery_duration = 600  # 1200-1800s
    
    # Event allocation logic
    benign_baseline_count = max(1, ben_count // 5)  # ~20% in baseline
    benign_recovery_count = ben_count - benign_baseline_count
    
    # Allocate malicious events across 3 attack phases
    # Rule: Try to distribute evenly, but allow flexibility
    mal_per_phase = mal_count // 3
    mal_remainder = mal_count % 3
    mal_phase_counts = [
        mal_per_phase + (1 if i < mal_remainder else 0)
        for i in range(3)
    ]  # e.g., [4, 4, 3] or [3, 3, 4]
    
    # Build phase configuration
    phases = [
        {
            'name': 'benign_baseline',
            'start': 0,
            'end': baseline_duration,
            'type': 'benign',
            'event_count': benign_baseline_count,
        },
        {
            'name': 'attack_phase_1',
            'start': baseline_duration,
            'end': baseline_duration + attack_duration // 3,
            'type': 'attack',
            'event_count': mal_phase_counts[0],
        },
        {
            'name': 'attack_phase_2',
            'start': baseline_duration + attack_duration // 3,
            'end': baseline_duration + 2 * attack_duration // 3,
            'type': 'attack',
            'event_count': mal_phase_counts[1],
        },
        {
            'name': 'attack_phase_3',
            'start': baseline_duration + 2 * attack_duration // 3,
            'end': baseline_duration + attack_duration,
            'type': 'attack',
            'event_count': mal_phase_counts[2],
        },
        {
            'name': 'benign_recovery',
            'start': baseline_duration + attack_duration,
            'end': total_duration,
            'type': 'benign',
            'event_count': benign_recovery_count + fa_count,  # Both benign and FA mix in recovery
        },
    ]
    
    return {
        scenario_name: {
            'total_duration': total_duration,
            'phases': phases,
            'false_alarm_zones': _calculate_false_alarm_zones(phases, fa_count),
        }
    }

def _calculate_false_alarm_zones(phases, fa_count):
    """
    Calculate distributed zones for false alarms within recovery phase.
    
    Spreads false alarms across the benign_recovery phase to avoid
    clustering them all at the end.
    """
    recovery_phase = phases[-1]
    start = recovery_phase['start']
    end = recovery_phase['end']
    duration = end - start
    
    # Spread FA across multiple zones
    zone_width = duration / max(fa_count, 1)
    zones = [
        (start + i * zone_width, start + (i+1) * zone_width)
        for i in range(fa_count)
    ]
    
    return zones
```

**Validation Updates**:
```python
def validate_30_event_table(df, global_constraints):
    """
    Validate final table against computed event counts.
    
    Changes:
    - Read expected counts from global_constraints
    - Validate counts match (potentially with small tolerance)
    """
    
    expected_total = global_constraints['label_distribution']['total_events_per_table']
    expected_malicious = global_constraints['label_distribution']['malicious']['count']
    expected_benign = global_constraints['label_distribution']['benign']['count']
    expected_false_alarm = global_constraints['label_distribution']['false_alarm']['count']
    
    actual_total = len(df)
    actual_malicious = len(df[df['label'] == 'Malicious'])
    actual_benign = len(df[df['label'] == 'Benign'])
    actual_false_alarm = len(df[df['label'] == 'False Alarm'])
    
    errors = []
    
    # Allow ±1 tolerance for rounding effects
    TOLERANCE = 1
    
    if actual_total != expected_total:
        errors.append(
            f"Total event count mismatch: expected {expected_total}, got {actual_total}"
        )
    
    if abs(actual_malicious - expected_malicious) > TOLERANCE:
        errors.append(
            f"Malicious count mismatch: expected {expected_malicious}, got {actual_malicious}"
        )
    
    if abs(actual_benign - expected_benign) > TOLERANCE:
        errors.append(
            f"Benign count mismatch: expected {expected_benign}, got {actual_benign}"
        )
    
    if abs(actual_false_alarm - expected_false_alarm) > TOLERANCE:
        errors.append(
            f"False alarm count mismatch: expected {expected_false_alarm}, got {actual_false_alarm}"
        )
    
    return errors
```

---

## IMPLEMENTATION SEQUENCE

### Phase 1: Configuration Infrastructure (Low Risk) - 1 day
1. Add 2 parameters to `main.py` (total_events_per_table, false_alarm_pct)
2. Add validation for parameter ranges
3. Compute false_alarm_count in main.py
4. **Do NOT modify Steps 3-6 yet** - keeps existing functionality intact

### Phase 2: Global Constraints Update (Low Risk) - 2 hours
1. Add `scenario_malicious_events` section to `global_constraints.json`
2. Populate with scenario-specific counts (7, 9, 11)
3. Add rationale for each attack complexity level
4. Test JSON parsing

### Phase 3: Step 3 Implementation (Low Risk) - 4 hours
1. Modify `step_3.py` to lookup `malicious_count` from `scenario_malicious_events[scenario_name]`
2. Remove any percentage-based calculation
3. Test with existing scenarios (direct lookup should be simpler than before)

### Phase 4: Step 4 Implementation (Low Risk) - 1 day
1. Modify `step_4.py` to receive `benign_count` parameter (calculated in main.py)
2. Pass parameter to `_generate_benign_events_for_scenario()`
3. Test with various benign_count values

### Phase 5: Step 5 Implementation (Low Risk) - 4 hours
1. Modify `step_5.py` to receive `false_alarm_count` parameter (pre-calculated in main.py)
2. Distribute across 3 types using fixed ratio formula
3. Test distribution logic with various false_alarm_count values

### Phase 6: Step 6 Implementation (Low Risk) - 1 day
1. Simplify `step_6.py` (no dynamic architecture builder needed)
2. Update validation logic to use pre-computed counts
3. Test temporal architecture with various configurations

### Phase 7: Integration & Testing - 1-2 days
1. Update `main.py` to pass all computed counts to Steps 3-6
2. End-to-end testing with 3+ configurations:
   - Config 1: total=30, false_alarm_pct=0.15 (default)
   - Config 2: total=20, false_alarm_pct=0.10 (small)
   - Config 3: total=45, false_alarm_pct=0.20 (large)
3. Verify CSVs have correct event counts per scenario
4. Update documentation

---

## BACKWARD COMPATIBILITY

**Migration Path**:
- Current defaults remain unchanged (total=30, malicious 35%, benign 50%, false alarm 15%)
- Existing `global_constraints.json` works with updated code if percentages are converted to counts
- Step files maintain ability to run with old-style string-based configs (with deprecation warning)

---

## CONFIGURATION EXAMPLES

### Example 1: Current Configuration (Default)
```python
# main.py
total_events_per_table = 30
false_alarm_pct = 0.15
```

**Result for each scenario**:
```
WannaCry:
  - malicious_count = 11 (fixed, from global_constraints)
  - false_alarm_count = round(30 * 0.15) = 5
  - benign_count = 30 - 11 - 5 = 14
  - Total: 30 ✓

Data_Theft:
  - malicious_count = 9 (fixed, from global_constraints)
  - false_alarm_count = 5
  - benign_count = 30 - 9 - 5 = 16
  - Total: 30 ✓

Netcat_Backdoor:
  - malicious_count = 7 (fixed, from global_constraints)
  - false_alarm_count = 5
  - benign_count = 30 - 7 - 5 = 18
  - Total: 30 ✓
```

### Example 2: Smaller Dataset (20 events, conservative false alarms)
```python
# main.py
total_events_per_table = 20
false_alarm_pct = 0.10
```

**Result for each scenario**:
```
WannaCry:
  - malicious_count = 11 (fixed)
  - false_alarm_count = round(20 * 0.10) = 2
  - benign_count = 20 - 11 - 2 = 7
  - Total: 20 ✓

Netcat_Backdoor:
  - malicious_count = 7 (fixed)
  - false_alarm_count = 2
  - benign_count = 20 - 7 - 2 = 11
  - Total: 20 ✓
```

### Example 3: Large Dataset (45 events, high false alarm rate for triage training)
```python
# main.py
total_events_per_table = 45
false_alarm_pct = 0.20
```

**Result for each scenario**:
```
WannaCry:
  - malicious_count = 11 (fixed)
  - false_alarm_count = round(45 * 0.20) = 9
  - benign_count = 45 - 11 - 9 = 25
  - Total: 45 ✓

Data_Theft:
  - malicious_count = 9 (fixed)
  - false_alarm_count = 9
  - benign_count = 45 - 9 - 9 = 27
  - Total: 45 ✓
```

### Example 4: Testing Low False Alarm (Focus on attack detection)
```python
# main.py
total_events_per_table = 30
false_alarm_pct = 0.05
```

**Result for each scenario**:
```
WannaCry:
  - malicious_count = 11 (fixed)
  - false_alarm_count = round(30 * 0.05) = 2
  - benign_count = 30 - 11 - 2 = 17
  - Total: 30 ✓

Netcat_Backdoor:
  - malicious_count = 7 (fixed)
  - false_alarm_count = 2
  - benign_count = 30 - 7 - 2 = 21
  - Total: 30 ✓
```

---

## DATA FLOW DIAGRAM

```
main.py (User Input)
├── total_events_per_table = 30 (range: 18-45)
└── false_alarm_pct = 0.15 (range: 0.05-0.30)
    
Compute (in main.py)
├── false_alarm_count = round(30 * 0.15) = 5
└── (benign_count computed later per scenario)

global_constraints.json (Pre-populated)
└── scenario_malicious_events:
    ├── WannaCry.malicious_count = 11 (fixed, scenario-specific)
    ├── Data_Theft.malicious_count = 9
    ├── ShellShock.malicious_count = 9
    ├── Netcat_Backdoor.malicious_count = 7
    └── passwd_gzip_scp.malicious_count = 7

Step 3 (step_3.py)
├── Read: scenario-specific malicious_count (fixed lookup)
└── Generate: 11 malicious events for WannaCry, 9 for Data_Theft, etc.

Step 4 (step_4.py)
├── Lookup: malicious_count for this scenario
├── Calculate: benign_count = total - malicious - false_alarm
│            = 30 - 11 - 5 = 14 (for WannaCry)
└── Generate: 14 benign events for WannaCry

Step 5 (step_5.py)
├── Receive: false_alarm_count = 5 (user parameter)
├── Distribute: Type 1 (2) + Type 2 (2) + Type 3 (1)
└── Generate: 5 false alarm events

Step 6 (step_6.py)
├── Receive: all computed counts
├── Calculate: total = malicious + benign + false_alarm
│            = 11 + 14 + 5 = 30 ✓
├── Build: temporal architecture
└── Output: final CSV files (5 scenarios × N events each)
```

---

## VALIDATION CHECKLIST

- [ ] Parameter validation in `main.py` (percentages sum to 100%)
- [ ] Rounding compensation logic tested (handles various totals)
- [ ] `global_constraints.json` update examples created
- [ ] Step 3: Malicious count parameterization implemented and tested
- [ ] Step 4: Benign count parameterization implemented and tested
- [ ] Step 5: False alarm distribution logic implemented and tested
- [ ] Step 6: Dynamic temporal architecture builder implemented
- [ ] Step 6: Validation logic updated for dynamic counts
- [ ] End-to-end tests with 3+ different configurations
- [ ] CSVs generated correctly with new counts
- [ ] Event labels (Malicious, Benign, False Alarm) match expected distribution
- [ ] Timestamps still strictly increasing (temporal ordering)
- [ ] Documentation updated (README, inline comments)
- [ ] Backward compatibility verified (existing workflows still work)

---

## RISKS & MITIGATION

### Risk 1: Temporal Ordering Issues in Step 6
**Problem**: Phase allocation changes could break timestamp ordering  
**Mitigation**: Exhaustive testing with edge cases (very small/large counts)

### Risk 2: Insufficient Event Data
**Problem**: Requesting more events than UNSW data available  
**Mitigation**: Implement TIER 2/3 fallback with synthetic variations (already exists)

### Risk 3: Incorrect Event Count Distribution in Step 5
**Problem**: False alarm distribution doesn't perfectly match requested count  
**Mitigation**: Implement rounding compensation (largest type absorbs remainder)

### Risk 4: Schema Consistency
**Problem**: global_constraints.json format changed breaks backward compatibility  
**Mitigation**: Support both old (string) and new (numeric) formats in Step readers

---

## FILES TO MODIFY

| File | Component | Changes | Effort |
|------|-----------|---------|--------|
| `main.py` | User interface | Add 2 parameters + validation (total_events_per_table, false_alarm_pct) | 1 day |
| `global_constraints.json` | Config schema | Add scenario_malicious_events section (7, 9, 11 per scenario) | 2 hours |
| `step_3.py` | Malicious generation | Change lookup: read from scenario_malicious_events[scenario_name] | 4 hours |
| `step_4.py` | Benign generation | Add parameter for benign_count (calculate as remainder) | 1 day |
| `step_5.py` | False alarm generation | Add parameter for false_alarm_count (from user %) | 4 hours |
| `step_6.py` | Assembly & validation | Use pre-computed counts (no dynamic architecture builder needed) | 1 day |
| `helper_functions.py` | Utilities | Add validation function for parameter ranges | 2 hours |
| Documentation | Reference | Update README, comments, add examples | 1 day |

**Total Estimated Effort**: 5-7 days (significantly reduced from 9-13 days)

**Why simpler**: Malicious events are fixed per scenario (no parameterization), so no need for complex percentage calculations in Step 3. Benign events are always remainder (no percentage parametrization needed).

---

## QUESTIONS FOR STAKEHOLDERS

1. **Malicious Event Counts per Scenario**: Are the fixed counts (7, 9, 11) realistic based on your understanding of these attacks?
   - Simple attacks (7): passwd-gzip-scp, Netcat Backdoor
   - Medium attacks (9): Data_Theft, ShellShock
   - Complex attacks (11): WannaCry

2. **False Alarm Percentage Range**: Is 0.05-0.30 (5%-30%) a reasonable range for user input?
   - Conservative: 0.05-0.10  (few false alarms, focus on attack detection)
   - Standard: 0.10-0.20     (realistic SIEM baseline)
   - High: 0.20-0.30         (more triage training opportunities)

3. **Total Events Range**: Is 18-45 events a reasonable range?
   - Lower bound (18): Minimum for showing attack + baseline + FA
   - Upper bound (45): Maximum before losing investigability focus

4. **False Alarm Type Distribution**: Keep 2:2:1 ratio (Type 1:2:3) for all counts, or allow configurable per-scenario ratios?

5. **Configuration UI**: Should parameters be:
   - Hard-coded in main.py only?
   - Also support CLI arguments (--total-events, --false-alarm-pct)?
   - Also support separate config file (JSON/YAML)?

---

## SUCCESS CRITERIA

- ✅ Parameters configurable in `main.py` (total_events_per_table, false_alarm_pct)
- ✅ Scenario-specific malicious counts in `global_constraints.json` (7, 9, 11 per attack)
- ✅ Benign count calculated as remainder (total - malicious - false_alarm)
- ✅ All 5 steps use parameterized values
- ✅ End-to-end pipeline works with ≥3 different configurations
- ✅ Generated CSVs have correct event counts per scenario (verify all scenarios with different counts)
- ✅ Label counts match expected distribution (Malicious, Benign, False Alarm)
- ✅ Temporal ordering maintained (timestamps strictly increasing)
- ✅ Parameter validation prevents invalid configurations (e.g., false_alarm_pct > 0.30)
- ✅ Documentation updated with examples and constraints
- ✅ Backward compatibility maintained (if desired)

---

## APPENDIX: New Architecture Summary

### User Parameters (Input - 2 values)
| Parameter | Range | Default | Type |
|-----------|-------|---------|------|
| `total_events_per_table` | 18-45 | 30 | Integer |
| `false_alarm_pct` | 0.05-0.30 | 0.15 | Float (%) |

### Scenario-Specific Fixed Values (Lookup - from global_constraints.json)
| Scenario | Complexity | Malicious Count | Rationale |
|----------|-----------|-----------------|-----------|
| WannaCry | Complex | 11 | Worm with lateral movement + multi-system |
| Data_Theft | Medium | 9 | Discovery + staging + exfiltration |
| ShellShock | Medium | 9 | Web exploit + execution + data access |
| Netcat_Backdoor | Simple | 7 | Backdoor install + test |
| passwd_gzip_scp | Simple | 7 | Linear: access → compress → transfer |

### Computed Values (Derived - per scenario)
| Value | Computation | Example (WannaCry) |
|-------|-------------|-------------------|
| `malicious_count` | Lookup from global_constraints | 11 |
| `false_alarm_count` | round(total * false_alarm_pct) | round(30 × 0.15) = 5 |
| `benign_count` | total - malicious - false_alarm | 30 - 11 - 5 = 14 |
| **Total** | **malicious + benign + false_alarm** | **30** |

### Implementation Impact

**Simplified vs. Previous Design:**
- ❌ Removed: 3 user parameters (distribution_malicious_pct, distribution_benign_pct already embedded in scenario choice)
- ✅ Reduced to: 2 user parameters (simpler interface)
- ✅ Added: Scenario-specific malicious counts (realistic per attack)
- ✅ Gained: Automatic benign composition (fills remainder)

**Step-by-step changes:**
| Step | Before | After |
|------|--------|-------|
| **Step 3** | Read malicious_pct, compute malicious_count | Lookup malicious_count directly |
| **Step 4** | Read benign_pct, compute benign_count | Calculate benign_count as remainder |
| **Step 5** | Read false_alarm_pct, compute count | Use pre-computed false_alarm_count |
| **Step 6** | Build dynamic architecture from 3 counts | Use pre-computed counts directly |

