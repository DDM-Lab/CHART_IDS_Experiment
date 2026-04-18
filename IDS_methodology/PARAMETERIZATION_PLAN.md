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
   - `false_alarm_bin`: Predefined bin from {very_conservative, conservative, standard, elevated, high} (default: "standard")

2. **False Alarm Rate Binning** (Safety mechanism to prevent impossible configs):
   - **Why bins?** Each scenario has different max FA rate (WannaCry: 64%, passwd_gzip_scp: 77%)
   - **Solution**: Predefined bins use the GLOBAL minimum (64%) so all scenarios are safe
   - **Bins available**:
     - `very_conservative`: 0.05 (5%) - Minimal false alarms, focus on attack detection
     - `conservative`: 0.10 (10%) - Few false alarms, realistic baseline
     - `standard`: 0.15 (15%) - Typical enterprise SIE baseline (DEFAULT)
     - `elevated`: 0.20 (20%) - More noise, SOC analyst training
     - `high`: 0.30 (30%) - High noise, triage/filtering skill development

3. **Scenario-specific fixed values** in `zero_day_templates.json`:
   - `malicious_count`: NOT parameterized; set in stone per scenario based on attack complexity
   - `max_false_alarm_pct`: Per-scenario maximum false alarm rate (for reference, not enforcement due to binning)
     - Simple attacks (passwd_gzip_scp, Netcat Backdoor): 7 events, max 77%
     - Medium attacks (Data_Theft, ShellShock): 9 events, max 70%
     - Complex attacks (WannaCry): 11 events, max 64%

4. **Computed intermediate values** (derived from user inputs + scenario data):
   - `false_alarm_pct`: Lookup from chosen bin (converts "standard" → 0.15)
   - `false_alarm_count`: Calculated = round(total_events_per_table × false_alarm_pct)
   - **Per scenario:**
     - `malicious_count`: Lookup from scenario in zero_day_templates.json
     - `benign_count`: Calculated = total_events_per_table - malicious_count - false_alarm_count

5. **Validation & Safety**:
   - User can ONLY choose from predefined bins (no arbitrary percentages allowed)
   - All bins use global-safe rate (64%) so all scenarios work for any bin
   - Guard against impossible configs: `malicious_count + false_alarm_count > total_events_per_table` should never occur
   - Allow `benign_count` to reach zero (if FA rate hits max), but document this clearly

6. **Step-level implementations**:
   - Step 3: Use scenario's fixed `malicious_count` (no selection logic needed)
   - Step 4: Generate `benign_count` events (calculated remainder, per-scenario)
   - Step 5: Generate `false_alarm_count` events (same count for all scenarios, distributed across 3 types)
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

# ============================================================
# FALSE ALARM RATE BINS (safe for ALL scenarios)
# ============================================================
# Global constraint: use minimum of all scenario maxes (WannaCry max 64%)
FALSE_ALARM_BINS = {
    "zero": {
        "pct": 0.00,
        "description": "No false alarms - pure attack focus"
    },
    "very_conservative": {
        "pct": 0.05,
        "description": "Minimal false alarms, focus on attack detection"
    },
    "conservative": {
        "pct": 0.10,
        "description": "Few false alarms, realistic baseline"
    },
    "standard": {
        "pct": 0.15,
        "description": "Typical enterprise SIEM baseline (DEFAULT)"
    },
    "elevated": {
        "pct": 0.20,
        "description": "More noise, SOC analyst training"
    },
    "high": {
        "pct": 0.30,
        "description": "High noise, triage/filtering skill development"
    }
}

# ============================================================
# FALSE ALARM TYPE DISTRIBUTION RATIOS
# ============================================================
# Distribute false_alarm_count across 3 types:
#   Type 1: Unusual port + benign service (e.g., DNS on port 12345)
#   Type 2: High volume + benign service (e.g., massive DNS response)
#   Type 3: Rare duration + benign service (e.g., very long SSH session)
#
# Based on NoDOZE research, different distributions reflect attack patterns:
FA_TYPE_RATIO_MODES = {
    "balanced": {
        "type1": 0.40,  # 40% port anomalies
        "type2": 0.40,  # 40% volume anomalies
        "type3": 0.20,  # 20% duration anomalies
        "description": "Balanced: equal emphasis on port and volume anomalies (DEFAULT)"
    },
    "port_heavy": {
        "type1": 0.60,  # 60% port anomalies (highly visible to IDS)
        "type2": 0.20,  # 20% volume anomalies
        "type3": 0.20,  # 20% duration anomalies
        "description": "Port-heavy: more visible/obvious anomalies"
    },
    "volume_heavy": {
        "type1": 0.20,  # 20% port anomalies
        "type2": 0.60,  # 60% volume anomalies (requires baselines)
        "type3": 0.20,  # 20% duration anomalies
        "description": "Volume-heavy: requires statistical analysis to detect"
    },
    "duration_heavy": {
        "type1": 0.20,  # 20% port anomalies
        "type2": 0.20,  # 20% volume anomalies
        "type3": 0.60,  # 60% duration anomalies (subtle, hard to spot)
        "description": "Duration-heavy: subtle patterns, advanced detection needed"
    }
}

# Select desired FA type distribution
fa_type_ratio_mode = "balanced"  # Choose from: balanced | port_heavy | volume_heavy | duration_heavy
if fa_type_ratio_mode not in FA_TYPE_RATIO_MODES:
    raise ValueError(
        f"fa_type_ratio_mode must be one of {list(FA_TYPE_RATIO_MODES.keys())}, got '{fa_type_ratio_mode}'"
    )

# Table size configuration
total_events_per_table = 30  # Range: 18-45 (default: 30)
if not (18 <= total_events_per_table <= 45):
    raise ValueError(
        f"total_events_per_table must be between 18 and 45, got {total_events_per_table}"
    )

# False alarm bin selection (ONLY predefined bins allowed)
false_alarm_bin = "standard"  # Choose from: very_conservative | conservative | standard | elevated | high
if false_alarm_bin not in FALSE_ALARM_BINS:
    raise ValueError(
        f"false_alarm_bin must be one of {list(FALSE_ALARM_BINS.keys())}, got '{false_alarm_bin}'. "
        f"Arbitrary percentages not allowed for safety. Available options:\n"
        + "\n".join([
            f"  - {bin_name}: {bin_info['pct']*100:.0f}% ({bin_info['description']})"
            for bin_name, bin_info in FALSE_ALARM_BINS.items()
        ])
    )

# Convert bin to percentage
false_alarm_pct = FALSE_ALARM_BINS[false_alarm_bin]["pct"]

# ============================================================
# VALIDATION: Cannot have BOTH zero FA AND zero benign
# ============================================================
# This would result in tables with ONLY malicious events
if false_alarm_pct == 0.0:
    # Check if this config would create zero benign for any scenario
    with open("templates/zero_day_templates.json", "r") as f:
        templates_check = json.load(f)
    
    for scenario in templates_check["scenarios"]:
        mal_count = scenario["malicious_count"]
        ben_count = total_events_per_table - mal_count - 0  # 0 because FA = 0
        
        if ben_count <= 0:
            raise ValueError(
                f"INVALID CONFIGURATION: false_alarm_bin='zero' with total_events={total_events_per_table}\n"
                f"Would result in zero/negative benign for {scenario['name']} "
                f"(malicious={mal_count}, benign={ben_count})\n"
                f"This would create ONLY malicious events, violating minimum events constraint.\n\n"
                f"SOLUTIONS:\n"
                f"  1. Increase total_events_per_table to > {mal_count}\n"
                f"  2. Use non-zero false_alarm_bin (very_conservative, conservative, etc.)\n"
            )

print(f"\n{'='*60}")
print(f"Pipeline Configuration:")
print(f"{'='*60}")
print(f"  Total events per table: {total_events_per_table}")
print(f"  False alarm bin: {false_alarm_bin} ({false_alarm_pct*100:.0f}%)")
print(f"  FA type ratio mode: {fa_type_ratio_mode}")
print(f"  (Malicious counts fixed per scenario in templates)")
print(f"  (Benign counts calculated as: total - malicious - false_alarm)")
print(f"{'='*60}\n")
```

**Validation Rules:**
- `total_events_per_table`: 18 ≤ N ≤ 45
- `false_alarm_bin`: Must be one of {very_conservative, conservative, standard, elevated, high}
- Bins ensure safety: all values ≤ 0.30, which is safe for all scenarios
- Composition ensures: malicious + benign + false_alarm = total_events (per scenario)

### 2. Templates Update (zero_day_templates.json)

**Add scenario-specific malicious event counts and max false alarm rates** to each scenario in `zero_day_templates.json`:

Each scenario object MUST include:
```json
{
  "scenario_name": "WannaCry",
  "malicious_count": 11,
  "complexity": "complex",
  "justification": "Ransomware worm with lateral movement (scanning + exploit + encryption on multiple systems)",
  "max_false_alarm_pct": 0.65,
  "max_false_alarm_pct_rationale": "With 11 malicious events out of 30 total, max FA rate = (30-11)/30 = 63%. Set to 0.65 for safety margin.",
  ...rest of scenario fields...
}
```

**Scenario Configuration Table**:

| Scenario | Complexity | Malicious Events | Max FA % | Rationale |
|----------|-----------|-----------------|----------|-----------|
| WannaCry | Complex | 11 | 63% | Worm with lateral movement; needs sufficient malicious events |
| Data_Theft | Medium | 9 | 70% | Multi-phase exfiltration; needs attack chain visibility |
| ShellShock | Medium | 9 | 70% | Web exploitation; medium complexity chain |
| Netcat_Backdoor | Simple | 7 | 77% | Backdoor; simpler chain, more room for benign baseline |
| passwd_gzip_scp | Simple | 7 | 77% | Linear credential theft; minimal network movement |

**Why per-scenario max rates?**
- **WannaCry (11 malicious)**: Complex attack requires ~11 events to show worm propagation. With 30-event limit, max FA = (30-11)/30 = 63%
- **Data_Theft (9 malicious)**: Medium complexity requires discovery + staging + exfiltration. Max FA = (30-9)/30 = 70%
- **Netcat_Backdoor (7 malicious)**: Simple linear attack. Max FA = (30-7)/30 = 77%

If user requests higher FA rate than scenario allows, pipeline REJECTS and returns clear error.

**Changes from previous design:**
- ✅ Moved scenario_malicious_events from global_constraints.json to zero_day_templates.json
- ✅ Added max_false_alarm_pct per scenario (prevents impossible configurations)
- ✅ Removed generic `label_distribution` fallbacks; all counts now scenario-specific
- ✅ Benign count is always remainder: `benign_count = total - malicious - false_alarm`

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

**Modification**: Read `malicious_count` from scenario data via templates_path (no parameterization)

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
    - Read scenario-specific malicious_count from templates (zero_day_templates.json)
    - Count is FIXED per scenario (not parameterizable)
    """
    
    with open(templates_path, 'r') as f:
        templates_data = json.load(f)
    
    # Find this scenario in templates
    scenario_template = None
    for s in templates_data['scenarios']:
        if s['scenario_name'] == scenario_name:
            scenario_template = s
            break
    
    if not scenario_template:
        raise ValueError(f"Scenario {scenario_name} not found in templates")
    
    # Lookup scenario's fixed malicious count (no user selection)
    malicious_count = scenario_template['malicious_count']
    
    # In _generate_tier1_events():
    # Replace: num_sampled = min(10 + random.randint(0, 1), len(filtered_df))
    # With: num_sampled = min(malicious_count, len(filtered_df))
    
    # Similar change for _generate_tier2_events()
```

**Key difference from previous design:**
- ✅ Read from `templates_path` (zero_day_templates.json) not global_constraints_path
- ✅ Direct lookup of scenario-specific `malicious_count`
- ✅ If data insufficient, TIER 2/3 fallback still applies (maintains synthesis framework)
- ✅ Simplifies Step 3 logic (no parameterization needed)

---

### 4. Step 4: Benign Event Generation (step_4.py)

**CRITICAL CHANGES** - Must handle benign_count=0 edge case

**New function receives** `benign_count_per_scenario` dict (pre-computed in main.py):
```python
def generate_benign_events_step_4(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    benign_count_per_scenario,  # NEW: dict like {'WannaCry': 14, 'Data_Theft': 16, ...}
    random_seed=42
):
    """
    Generate benign events with parameterized counts per scenario.
    
    EDGE CASE HANDLING:
    - If benign_count_per_scenario[scenario] == 0:
      * Skip benign generation for that scenario
      * Log WARNING: "{scenario_name}: benign_count=0, generating 0 benign events"
      * Return [] for that scenario
    """
    for scenario_name in benign_count_per_scenario.keys():
        ben_count = benign_count_per_scenario[scenario_name]
        events = _generate_benign_events_for_scenario(
            scenario_name,
            pooled_benign_df,
            scenario_template,
            constraints,
            ben_count  # Pass the computed count
        )
```

**In `_generate_benign_events_for_scenario()`**:
```python
def _generate_benign_events_for_scenario(scenario_name, pooled_benign_df, template, 
                                          constraints, benign_count):
    """
    EDGE CASE: benign_count == 0
    - Return empty list []
    - Write WARNING to logger (included in step_6_summary.txt)
    - Temporal architecture builder MUST handle empty benign event list
    """
    
    if benign_count <= 0:
        logger.warning(f"{scenario_name}: benign_count={benign_count}, generating 0 benign events")
        return []
    
    # Normal logic for benign_count > 0
    num_events = benign_count  # Use parameter (not hard-coded 15)
    if len(pooled_benign_df) < num_events:
        logger.warning(f"Only {len(pooled_benign_df)} benign rows available, generating {num_events} events...")
        sampled_df = pooled_benign_df.copy()
    else:
        sampled_df = pooled_benign_df.sample(n=num_events, random_state=None)
    
    # Rest of generation logic unchanged
```

**Key insight:**
- Benign count is always a **dynamic remainder**: `benign = total - malicious - false_alarm`
- This ensures the table always sums to the target total
- **Benign can reach zero** if user sets false_alarm_pct at scenario's max (this is documented but allowed)

---

### 5. Step 5: False Alarm Event Generation (step_5.py)

**CRITICAL CHANGES** - Must apply FA type ratio distribution and handle false_alarm_count=0

**New function receives** `false_alarm_count` + `fa_type_ratio_mode` (pre-computed in main.py):
```python
def generate_false_alarms_step_5(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    false_alarm_count,  # NEW: pre-computed count (same for all scenarios)
    fa_type_ratio_mode,  # NEW: "balanced" | "port_heavy" | "volume_heavy" | "duration_heavy"
    random_seed=42
):
    """
    Generate false alarm events with user-configured type distribution.
    
    EDGE CASE HANDLING:
    - If false_alarm_count == 0:
      * Skip FA generation entirely
      * Log WARNING: "false_alarm_count=0, skipping FA generation"
      * Return {} (empty results for all scenarios)
    """
```

**Helper function - Type distribution logic**:
```python
def _distribute_false_alarms(false_alarm_count, fa_type_ratio_mode):
    """
    Distribute false_alarm_count across 3 types using selected ratio mode.
    
    Based on NoDOZE research and user selection:
    - balanced (default): 40% Type1 (port), 40% Type2 (volume), 20% Type3 (duration)
    - port_heavy: 60% Type1, 20% Type2, 20% Type3
    - volume_heavy: 20% Type1, 60% Type2, 20% Type3
    - duration_heavy: 20% Type1, 20% Type2, 60% Type3
    
    Returns: dict with {\"type_1\": count1, \"type_2\": count2, \"type_3\": count3}
    
    Example (balanced mode, 5 FA):
      type1 = round(5 * 0.40) = 2
      type2 = round(5 * 0.40) = 2
      type3 = 5 - 2 - 2 = 1
      Result: {\"type_1\": 2, \"type_2\": 2, \"type_3\": 1}
    """
    
    ratio = FA_TYPE_RATIO_MODES[fa_type_ratio_mode]
    
    type1_count = round(false_alarm_count * ratio[\"type1\"])
    type2_count = round(false_alarm_count * ratio[\"type2\"])
    type3_count = false_alarm_count - type1_count - type2_count  # Absorb remainder
    
    return {\"type_1\": type1_count, \"type_2\": type2_count, \"type_3\": type3_count}

def _generate_false_alarms_for_scenario(scenario_name, pooled_benign_df, benign_stats,
                                         scenario_template, constraints, 
                                         false_alarm_count, fa_type_ratio_mode):
    """
    EDGE CASE: false_alarm_count == 0
    - Return empty list []
    - Log WARNING: \"false_alarm_count=0, skipping FA generation for all scenarios\"
    - Step 6 will handle absence of FA events gracefully
    """
    
    if false_alarm_count <= 0:
        logger.warning(f\"false_alarm_count={false_alarm_count}, generating 0 false alarm events\")
        return []
    
    # Get type distribution for this configuration
    distribution = _distribute_false_alarms(false_alarm_count, fa_type_ratio_mode)
    
    # Generate Type 1, 2, 3 with distributed counts
    type1_events = _generate_type1_events(pooled_benign_df, benign_stats, distribution[\"type_1\"], ...)
    type2_events = _generate_type2_events(pooled_benign_df, benign_stats, distribution[\"type_2\"], ...)
    type3_events = _generate_type3_events(pooled_benign_df, benign_stats, distribution[\"type_3\"], ...)
    
    return type1_events + type2_events + type3_events
```

**Distribution examples** (balanced mode - 2:2:1):
| false_alarm_count | Type 1 | Type 2 | Type 3 | Mode |
|------------------|--------|--------|--------|------|
| 0 | - | - | - | (skipped) |
| 2 | 1 | 1 | 0 | balanced |
| 5 | 2 | 2 | 1 | balanced |
| 6 | 2 | 3 | 1 | balanced |
| 10 | 4 | 4 | 2 | balanced |

**Distribution examples** (all modes, 5 FA events):
| Mode | Type 1 | Type 2 | Type 3 | Ratios | Use Case |
|------|--------|--------|--------|--------|----------|
| balanced | 2 | 2 | 1 | 40:40:20 | Default - good mix of anomaly types |
| port_heavy | 3 | 1 | 1 | 60:20:20 | Easier to detect (visible port anomalies) |
| volume_heavy | 1 | 3 | 1 | 20:60:20 | Advanced analysis needed (baselines) |
| duration_heavy | 1 | 1 | 3 | 20:20:60 | Subtle patterns (hard to detect manually) |

---

### 6. Step 6: Final Assembly & Temporal Ordering (step_6.py)

**CRITICAL CHANGES** - Must handle zero benign and zero FA edge cases, add metadata columns

**New function signature**:
```python
def assemble_30_events_step_6(
    templates_path,
    global_constraints_path,
    output_dir,  # NEW: "IDS_tables/30events_15pct_fa"
    output_report_path,  # NEW: step_6_summary.txt (root workspace)
    total_events_per_table,  # NEW: 30
    false_alarm_count,  # NEW: 5
    malicious_count_per_scenario,  # NEW: dict {scenario: count}
    benign_count_per_scenario,  # NEW: dict {scenario: count}
    random_seed=42
):
    """
    Assemble final events with pre-computed counts and temporal ordering.
    
    EDGE CASES:
    - benign_count_per_scenario[scenario] == 0: Skip benign baseline phase
    - false_alarm_count == 0: Skip FA generation, benign recovery only
    - Both zero: Should be caught in main.py validation
    """
```

**Output directory creation** (main.py, before calling steps):
```python
# Create output directory structure
output_dir = f"IDS_tables/{total_events_per_table}events_{int(false_alarm_pct*100)}pct_fa"
os.makedirs(output_dir, exist_ok=True)  # Overwrite silently if exists
print(f"Output directory: {output_dir}")
```

**Metadata columns** (Step 6 adds when writing CSVs - FIRST 5 columns):
```python
# Example output row structure (5 metadata + existing columns):
# _total_events_param | _false_alarm_pct_param | _malicious_count_param | _benign_count_param | _false_alarm_count_param | ...existing columns...
# 30                  | 0.15                   | 11                     | 14                  | 5                       | [flow_id, duration, bytes, ...]

def _add_metadata_columns(df, total_events, fa_pct, mal_count, ben_count, fa_count):
    \"\"\"Insert 5 metadata columns at the beginning of dataframe\"\"\"
    metadata = pd.DataFrame({
        '_total_events_param': [total_events] * len(df),
        '_false_alarm_pct_param': [fa_pct] * len(df),
        '_malicious_count_param': [mal_count] * len(df),
        '_benign_count_param': [ben_count] * len(df),
        '_false_alarm_count_param': [fa_count] * len(df),
    })
    return pd.concat([metadata, df], axis=1)
```

**Temporal architecture modification** for zero benign case:
```python
def _build_temporal_architecture(scenario_name, mal_count, ben_count, fa_count, total_duration=1800):
    \"\"\"
    Build temporal phases accounting for zero benign/FA cases.
    
    STANDARD (ben > 0, fa > 0):
      Phase 0: benign_baseline (20% of ben events, 0-300s)
      Phase 1-3: attack_phases (mal events distributed per scenario, 300-1200s)
      Phase 4: benign_recovery (80% ben + all fa, 1200-1800s)
    
    CASE: ben == 0, fa > 0
      Phase 0: [SKIPPED]
      Phase 1-3: attack_phases (all mal events)
      Phase 4: false_alarm_recovery (only fa events, no benign)
      WARNING: No benign baseline/recovery phases
    
    CASE: ben > 0, fa == 0
      Phase 0: benign_baseline (20% of ben events)
      Phase 1-3: attack_phases (all mal events)
      Phase 4: benign_recovery (80% ben, no fa)
      WARNING: No false alarm events
    \"\"\"
    
    if ben_count <= 0 and fa_count <= 0:
        raise ValueError(
            f\"Invalid: both benign=0 and fa=0 for {scenario_name}. \"\n
            f\"Would only have {mal_count} malicious events.\"
        )
    
    baseline_duration = 300   # 0-300s
    attack_duration = 900     # 300-1200s
    recovery_duration = 600   # 1200-1800s
    
    phases = []
    
    # Phase 0: Benign baseline (SKIP if ben_count == 0)
    if ben_count > 0:
        benign_baseline_count = max(1, ben_count // 5)
        phases.append({
            'name': 'benign_baseline',
            'start': 0,
            'end': baseline_duration,
            'type': 'benign',
            'event_count': benign_baseline_count,
        })
    else:
        logger.warning(f\"{scenario_name}: benign_count=0, skipping benign baseline phase\")
    
    # Phases 1-3: Attack phases (distribute mal_count per scenario strategy)
    attack_phase_counts = _get_per_scenario_phase_allocation(scenario_name, mal_count)
    for i, phase_count in enumerate(attack_phase_counts):
        phases.append({
            'name': f'attack_phase_{i+1}',
            'start': 300 + (i * 300),
            'end': 300 + ((i+1) * 300),
            'type': 'attack',
            'event_count': phase_count,
        })
    
    # Phase 4: Recovery (benign + FA mix)
    recovery_benign = max(0, ben_count - (ben_count // 5)) if ben_count > 0 else 0
    phases.append({
        'name': 'benign_recovery',
        'start': 1200,
        'end': 1800,
        'type': 'benign',
        'event_count': recovery_benign + fa_count,
    })
    
    return {'phases': phases, ...}
```

**Simplification**: All event counts are already computed; Step 6 just allocates them to phases and handles edge cases

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

## 7. Main.py Integration & Control Flow (Step Orchestration)

**Problem This Solves**: Issues #3 & #4 - When/where benign_count is computed and how Steps are called

### Control Flow Pseudocode

```python
def main():
    # ========== SECTION A: Load config and user parameters ==========
    with open("templates/zero_day_templates.json") as f:
        templates_data = json.load(f)
    
    # User sets these two parameters
    total_events_per_table = 30  # (18-45)
    false_alarm_bin = "standard"  # (one of: very_conservative, conservative, standard, elevated, high)
    
    # Validate and convert bin to percentage
    if false_alarm_bin not in FALSE_ALARM_BINS:
        raise ValueError(f"Invalid bin: {false_alarm_bin}")
    false_alarm_pct = FALSE_ALARM_BINS[false_alarm_bin]["pct"]
    
    # Compute GLOBAL false_alarm_count (same for all 5 scenarios)
    false_alarm_count = round(total_events_per_table * false_alarm_pct)
    
    print(f"Configuration: total={total_events_per_table}, FA_bin={false_alarm_bin} ({false_alarm_pct*100:.0f}%)")
    print(f"  Computed FA_count: {false_alarm_count} (applied to all scenarios)")
    
    # ========== SECTION B: Per-scenario computation ==========
    # Build dicts to store per-scenario values
    malicious_count_per_scenario = {}
    benign_count_per_scenario = {}
    scenario_validation_errors = []
    
    for scenario in templates_data["scenarios"]:
        scenario_name = scenario["scenario_name"]
        mal_count = scenario["malicious_count"]
        max_fa_pct = scenario["max_false_alarm_pct"]
        
        # Compute per-scenario benign count (as remainder)
        ben_count = total_events_per_table - mal_count - false_alarm_count
        
        # Validate this scenario's configuration
        if ben_count < 0:
            scenario_validation_errors.append(
                f"{scenario_name}: benign would be negative ({ben_count}). "
                f"Cannot fit mal({mal_count}) + fa({false_alarm_count}) in total({total_events_per_table})"
            )
        
        if ben_count == 0:
            print(f"  [WARN] {scenario_name}: benign_count=0 (FA rate at maximum)")
        
        # Store for later use
        malicious_count_per_scenario[scenario_name] = mal_count
        benign_count_per_scenario[scenario_name] = max(0, ben_count)
    
    # Check for validation errors
    if scenario_validation_errors:
        print("ERROR: Configuration invalid for one or more scenarios:")
        for error in scenario_validation_errors:
            print(f"  - {error}")
        print("\nRecommendations:")
        print(f"  - Increase total_events_per_table (currently {total_events_per_table})")
        print(f"  - Decrease false_alarm_bin (currently {false_alarm_bin} = {false_alarm_pct*100:.0f}%)")
        raise ValueError("Configuration invalid")
    
    # ========== SECTION C: Call Steps with computed values ==========
    
    # Step 3: Generate malicious events
    # Called ONCE, processes all scenarios internally
    print(f"\nStep 3: Generating malicious events...")
    step_3_result = step_3.generate_malicious_events_step_3(
        transformed_csv_path="IDS_Datasets/UNSW_NB15_transformed.csv",
        templates_path="templates/zero_day_templates.json",
        global_constraints_path="templates/global_constraints.json",
        random_seed=42
    )
    
    # Step 4: Generate benign events
    # Called ONCE with per-scenario dict
    print(f"Step 4: Generating benign events...")
    step_4_result = step_4.generate_benign_events_step_4(
        transformed_csv_path="IDS_Datasets/UNSW_NB15_transformed.csv",
        templates_path="templates/zero_day_templates.json",
        benign_count_per_scenario=benign_count_per_scenario,
        random_seed=42
    )
    
    # Step 5: Generate false alarm events
    # Called ONCE with single false_alarm_count (same for all scenarios)
    print(f"Step 5: Generating false alarm events...")
    step_5_result = step_5.generate_false_alarms_step_5(
        transformed_csv_path="IDS_Datasets/UNSW_NB15_transformed.csv",
        templates_path="templates/zero_day_templates.json",
        false_alarm_count=false_alarm_count,
        random_seed=42
    )
    
    # Step 6: Final assembly and output
    # Called ONCE with all pre-computed counts
    print(f"Step 6: Assembling tables with temporal ordering...")
    
    # Create output directory based on parameters
    output_dir = f"IDS_tables/{total_events_per_table}events_{int(false_alarm_pct*100)}pct_fa"
    
    step_6_result = step_6.assemble_30_events_step_6(
        templates_path="templates/zero_day_templates.json",
        global_constraints_path="templates/global_constraints.json",
        output_dir=output_dir,
        output_report_path="step_6_summary.txt",
        total_events_per_table=total_events_per_table,
        false_alarm_count=false_alarm_count,
        malicious_count_per_scenario=malicious_count_per_scenario,
        benign_count_per_scenario=benign_count_per_scenario,
        random_seed=42
    )
    
    print(f"\n✓ Pipeline complete. Output in: {output_dir}")
```

### Key Insights from This Flow

1. **Benign count computed ONCE per scenario in Section B** (before calling any steps)
   - Not computed in Step 4 itself
   - All steps receive pre-computed values
   - Avoids confusion about when/how it's calculated

2. **Steps called ONCE each** (not per-scenario)
   - Steps 3, 4, 5 internally handle all 5 scenarios
   - Step 6 receives dicts of per-scenario counts

3. **Output directory created from parameters**
   - Pattern: `IDS_tables/{total}events_{fa_pct}pct_fa/`
   - Example: `IDS_tables/30events_15pct_fa/`

4. **Validation happens in main.py**
   - Before any steps run
   - Clear error messages if config is impossible
   - Stops pipeline if errors found

5. **Steps receive EXACTLY what they need**
   - Step 4 gets `benign_count_per_scenario` dict
   - Step 5 gets single `false_alarm_count` scalar
   - Step 6 gets both dicts + scalar

---

### Updating Step Function Signatures

Based on this flow, Steps need to be modified:

#### Step 3: No major changes (already iterates scenarios)
```python
def generate_malicious_events_step_3(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    random_seed=42
):
    # No new parameters needed
    # Internally loops through templates['scenarios']
```

#### Step 4: Add benign_count_per_scenario parameter
```python
def generate_benign_events_step_4(
    transformed_csv_path,
    templates_path,
    benign_count_per_scenario,  # ← NEW: dict like {'WannaCry': 14, 'Data_Theft': 16, ...}
    random_seed=42
):
    # For each scenario, use benign_count_per_scenario[scenario_name]
```

#### Step 5: Add false_alarm_count parameter
```python
def generate_false_alarms_step_5(
    transformed_csv_path,
    templates_path,
    false_alarm_count,  # ← NEW: single value (5), applied to all scenarios
    random_seed=42
):
    # Use this count for all 5 scenarios
```

#### Step 6: Add multiple parameters
```python
def assemble_30_events_step_6(
    templates_path,
    global_constraints_path,
    output_dir,  # ← NEW: "IDS_tables/30events_15pct_fa"
    output_report_path,
    total_events_per_table,  # ← NEW: 30
    false_alarm_count,  # ← NEW: 5
    malicious_count_per_scenario,  # ← NEW: dict
    benign_count_per_scenario,  # ← NEW: dict
    random_seed=42
):
    # Use all these to build temporal architecture and output CSVs
```

---

## Section 5: Validation Rules & Architecture Safety

### 5.1 Pre-Computation Validation (main.py)

Before ANY scenario computation, main.py validates user parameters:

```python
# ============================================================
# VALIDATION STEP A: Bin Lookup
# ============================================================
def validate_false_alarm_bin(bin_name):
    """Validate that bin_name exists in FALSE_ALARM_BINS"""
    if bin_name not in FALSE_ALARM_BINS:
        available = ", ".join(FALSE_ALARM_BINS.keys())
        raise ValueError(
            f"Invalid false_alarm_bin '{bin_name}'. "
            f"Available: {available}"
        )
    return True

# ============================================================
# VALIDATION STEP B: Per-Scenario Feasibility Check
# ============================================================
def validate_per_scenario(total_events, false_alarm_pct, scenario):
    """Check if benign_count ≥ 0 for this scenario"""
    mal_count = scenario["malicious_count"]
    fa_count = round(total_events * false_alarm_pct)
    ben_count = total_events - mal_count - fa_count
    
    # Feasibility rules:
    # - ben_count == 0 is allowed BUT warns
    # - ben_count < 0 is INVALID (error + stop entire config)
    if ben_count < 0:
        return False, ben_count
    if ben_count == 0:
        print(f"⚠️  WARNING: {scenario['name']} will have benign_count=0. "
              f"Temporal synthesis may skip normal traffic phase.")
    return True, ben_count

# ============================================================
# VALIDATION STEP C: Execute All Checks
# ============================================================
def main():
    # User provides only TWO parameters:
    total_events_per_table = 30
    false_alarm_bin = "standard"  # User selects from bin names
    
    # Step 1: Validate bin exists (prevents typos)
    validate_false_alarm_bin(false_alarm_bin)
    
    # Step 2: Convert bin to percentage
    false_alarm_pct = FALSE_ALARM_BINS[false_alarm_bin]["pct"]
    print(f"Using false_alarm_bin='{false_alarm_bin}' ({false_alarm_pct:.0%})")
    
    # Step 3: Load scenario definitions from templates
    with open("templates/zero_day_templates.json", 'r') as f:
        templates_data = json.load(f)
    
    # Step 4: Check EVERY scenario
    benign_count_per_scenario = {}
    for scenario in templates_data["scenarios"]:
        scenario_name = scenario["name"]
        is_valid, ben_count = validate_per_scenario(
            total_events_per_table,
            false_alarm_pct,
            scenario
        )
        
        if is_valid:
            benign_count_per_scenario[scenario_name] = ben_count
        else:
            # ❌ INVALID: Config doesn't work for all scenarios
            raise ValueError(
                f"\n❌ INVALID CONFIGURATION:\n"
                f"  total_events={total_events_per_table}\n"
                f"  false_alarm_bin='{false_alarm_bin}' ({false_alarm_pct:.0%})\n\n"
                f"Problem: {scenario_name}\n"
                f"  - malicious_count = {scenario['malicious_count']}\n"
                f"  - false_alarm_count = {round(total_events_per_table * false_alarm_pct)}\n"
                f"  - benign_count = {ben_count} ❌ (NEGATIVE!)\n\n"
                f"Solutions:\n"
                f"  1. Increase total_events to > {scenario['malicious_count'] + round(total_events_per_table * false_alarm_pct)}\n"
                f"  2. Use a LOWER false_alarm_bin (more conservative)\n\n"
                f"Hint: WannaCry requires total ≥ 22 (11 malicious + 11 false alarms)"
            )
    
    # ✅ All scenarios valid - proceed to steps
    print(f"✅ Configuration VALID for all 5 scenarios")
    return benign_count_per_scenario  # Passed to Step 4
```

### 5.2 Validation Rules Summary

| Context | Rule | Failure Mode | Error Message |
|---------|------|--------------|---------------|
| **Bin Validation** | `false_alarm_bin` must exist in FALSE_ALARM_BINS | Typo in user input | "Invalid bin {x}. Available: ..." |
| **Per-Scenario Check** | For each scenario: `benign_count ≥ 0` | Total events too low | "benign_count = {x} (NEGATIVE)" |
| **Config-Wide Rule** | If ANY scenario fails: reject entire config | User ignorant of constraints | Clear error with suggestions |
| **Edge Case: ben=0** | Allowed, but issue warning | Temporal phase skipped | "⚠️ benign_count=0. Synthese may skip..." |

### 5.3 Design Principle: No Per-Scenario Adjustment

**NEVER implement per-scenario clamping like this**:
```python
# ❌ DON'T DO THIS
false_alarm_count_per_scenario = {}
for scenario in scenarios:
    fa_count = round(total * false_alarm_pct)
    if fa_count > scenario["max_false_alarm_count"]:
        fa_count = scenario["max_false_alarm_count"]  # ← CLAMPING (bad!)
    false_alarm_count_per_scenario[scenario["name"]] = fa_count
```

**Why per-scenario adjustment is problematic:**
1. **Silent data corruption** — User thinks they're getting 15% FA everywhere, but some scenarios get 20%
2. **Debugging nightmare** — Which scenarios got clamped? Unknown to user
3. **Inconsistent results** — Same user config produces different distributions per scenario
4. **Non-monotonic** — Larger bins don't always produce larger FA counts

**Instead, implement fail-fast**:
```python
# ✅ DO THIS
if benign_count < 0:
    raise ValueError("Config impossible. Try different parameters.")
      # User makes informed decision to adjust constraints
```

This ensures:
- ✅ Transparent behavior (user knows exactly what's happening)
- ✅ Consistent distribution (same FA% everywhere)
- ✅ Debuggable failures (clear error messages)
- ✅ User control (they decide to use conservative instead of standard)

### 5.4 Metadata Columns in Output CSVs

Each CSV output includes 4 new metadata columns:

```
_total_events_param = 30
_false_alarm_pct_param = 0.15
_malicious_count_param = 11
_benign_count_param = 14
_false_alarm_count_param = 5
```

**Implementation location**: Step 6 (assemble_30_events_step_6) adds these columns when writing final CSVs

**Purpose**: Allows post-hoc verification that generated data matches requested parameters

---

## DEPRECATED: Previous Validation Section

The following validation section should be REMOVED from Section 6 (as it's now handled in main.py):

**Remove this code snippet from Step 6**:
```python
# OLD - REMOVE THIS
if false_alarm_count < 3:
    raise ValueError(f"false_alarm_count must be ≥3")
```

**Replace with**: Validation happens in main.py before calling Step 6

---

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

### Example 1: Standard Configuration (Default)
```python
# main.py
total_events_per_table = 30
false_alarm_bin = "standard"  # ← 15% (from bin, not raw percentage)
```

**Computed values per scenario**:
```
false_alarm_count = round(30 * 0.15) = 5  (same for all scenarios)

WannaCry:
  - malicious_count = 11 (fixed, from templates)
  - false_alarm_count = 5 (computed from bin)
  - benign_count = 30 - 11 - 5 = 14
  - Total: 30 ✓

Data_Theft:
  - malicious_count = 9 (fixed)
  - false_alarm_count = 5
  - benign_count = 30 - 9 - 5 = 16
  - Total: 30 ✓

Netcat_Backdoor:
  - malicious_count = 7 (fixed)
  - false_alarm_count = 5
  - benign_count = 30 - 7 - 5 = 18
  - Total: 30 ✓
```

### Example 2: Conservative Configuration (Few false alarms)
```python
# main.py
total_events_per_table = 20
false_alarm_bin = "conservative"  # ← 10% (from bin)
```

**Computed values per scenario**:
```
false_alarm_count = round(20 * 0.10) = 2  (same for all scenarios)

WannaCry:
  - malicious_count = 11 (fixed)
  - false_alarm_count = 2
  - benign_count = 20 - 11 - 2 = 7
  - Total: 20 ✓

Netcat_Backdoor:
  - malicious_count = 7 (fixed)
  - false_alarm_count = 2
  - benign_count = 20 - 7 - 2 = 11
  - Total: 20 ✓
```

### Example 3: Large Dataset (High noise for training)
```python
# main.py
total_events_per_table = 45
false_alarm_bin = "elevated"  # ← 20% (from bin)
```

**Computed values per scenario**:
```
false_alarm_count = round(45 * 0.20) = 9  (same for all scenarios)

WannaCry:
  - malicious_count = 11 (fixed)
  - false_alarm_count = 9
  - benign_count = 45 - 11 - 9 = 25
  - Total: 45 ✓

Data_Theft:
  - malicious_count = 9 (fixed)
  - false_alarm_count = 9
  - benign_count = 45 - 9 - 9 = 27
  - Total: 45 ✓
```

### Example 4: High Noise Configuration (Triage training)
```python
# main.py
total_events_per_table = 30
false_alarm_bin = "high"  # ← 30% (from bin)
```

**Computed values per scenario**:
```
false_alarm_count = round(30 * 0.30) = 9  (same for all scenarios, gets capped by max_fa scenarios)

WannaCry:
  - malicious_count = 11 (fixed)
  - false_alarm_count = 9
  - benign_count = 30 - 11 - 9 = 10  ← VALID (only possible because bin ≤ global min)
  - Total: 30 ✓

Netcat_Backdoor:
  - malicious_count = 7 (fixed)
  - false_alarm_count = 9
  - benign_count = 30 - 7 - 9 = 14  ← VALID
  - Total: 30 ✓
```

### Example 5: INVALID Configuration (Would be rejected)
```python
# User tries to set arbitrary percentage (NOT ALLOWED)
total_events_per_table = 30
false_alarm_pct = 0.75  # ← ERROR: Must use bin, not raw percentage!
```

**Result**: 
```
ERROR: false_alarm_pct parameter not recognized. Must use false_alarm_bin instead.
Available bins:
  - very_conservative: 5% (Minimal false alarms, focus on attack detection)
  - conservative: 10% (Few false alarms, realistic baseline)
  - standard: 15% (Typical enterprise SIEM baseline)
  - elevated: 20% (More noise, SOC trainer training)
  - high: 30% (High noise, triage/filtering skill development)
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

