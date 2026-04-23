# Configuration File Analysis: global_constraints_v2.json vs zero_day_templates.json

**Date**: April 23, 2026  
**Analysis Scope**: Parameterized pipeline compatibility, data freshness, and safe removal

---

## EXECUTIVE SUMMARY

**Your assumption is CORRECT**: `label_distribution` in `global_constraints_v2.json` is **NOT** being used by the current parameterized pipeline.

**Key Finding**: The current implementation contradict some design documentation (PARAMETERIZATION_CLARIFICATION.md). While that document stated certain fields should be retained, the actual code uses hardcoded values instead of reading them from global_constraints.

**Verdict**: Several sections are outdated or unused. It is **SAFE to remove or restructure** these sections, but careful verification is needed for each.

---

## DETAILED FINDINGS

### 1. UNUSED: `label_distribution` in global_constraints_v2.json ❌

**Status**: NOT USED by pipeline  
**Location**: global_constraints_v2.json, lines 6-23

**Current Content**:
```json
"label_distribution": {
    "total_events_per_table": 30,
    "malicious": {
      "count": "10-11 events",
      "percentage": "35%",
      "definition": "Network flows..."
    },
    "benign": {
      "count": 15,
      "percentage": "50%",
      "definition": "Routine enterprise traffic..."
    },
    "false_alarm": {
      "count": "4-5 events",
      "percentage": "15%",
      "definition": "Locally anomalous..."
    }
}
```

**How counts are actually determined in pipeline**:
- Line in main.py (153): `malicious_count = scenario['malicious_count']` ← From zero_day_templates
- Line in main.py (156): `false_alarm_count = round(total_events * false_alarm_pct)` ← Parameterized from FALSE_ALARM_BINS
- Line in main.py (159): `benign_count = total_events - malicious_count - false_alarm_count` ← Calculated

**Verification**: Grep search for `['label_distribution']` returns NO matches in executable code. Only found in:
- Comments in main.py
- Documentation (PARAMETERIZATION_CLARIFICATION.md)
- This JSON file itself

**Recommendation**: ✅ **SAFE TO REMOVE** or convert to reference documentation only.

---

### 2. PARTIALLY USED: `temporal_architecture_principles` in global_constraints_v2.json ⚠️

**Status**: DEFINED but NOT ACTUALLY READ by pipeline  
**Location**: global_constraints_v2.json, lines 124-180

**Current Content**:
```json
"temporal_architecture_principles": {
    "description": "5-phase temporal structure...",
    "observation_window_seconds": 1800,
    "phase_structure": {
      "phase_1_benign_baseline": {
        "timeband_seconds": "0-300",
        "event_count": "5-7 benign events",
        ...
      },
      ...
    }
}
```

**Actual Implementation**:
- `step_2.py`, line 140: `get_standard_phases()` returns **HARDCODED** phases:
```python
def get_standard_phases():
    return [
        {"name": "benign_baseline", "start": 0, "end": 300, "event_count": 6},
        {"name": "attack_phase_1", "start": 300, "end": 600, "event_count": 3},
        {"name": "attack_phase_2", "start": 600, "end": 900, "event_count": 3},
        {"name": "attack_phase_3", "start": 900, "end": 1200, "event_count": 2},
        {"name": "benign_recovery", "start": 1200, "end": 1800, "event_count": 9}
    ]
```

**Issue**: The JSON defines a 5-phase structure with configurable event counts (5-7, 3-4, etc.), but the code uses fixed counts (6, 3, 3, 2, 9).

**Evidence**:
- No code searches for `global_constraints['temporal_architecture_principles']`
- No code searches for `global_constraints['phase_structure']`
- `get_standard_phases()` is a hardcoded local function in step_2.py

**Recommendation**: ⚠️ **Needs discussion**
- If phases should be configurable → Update step_2.py to read from JSON
- If fixed-size phases are correct → Remove/simplify JSON content and document rationale

---

### 3. UNUSED: `validation_checkpoints` in global_constraints_v2.json ❌

**Status**: DEFINED but NOT REFERENCED by code  
**Location**: global_constraints_v2.json, lines 220-350+

**Current Content**:
- 15 comprehensive validation rules (CRITICAL and HIGH severity levels)
- Conditions like: `len(df) == 30`, `10 ≤ Malicious ≤ 11 AND Benign == 15`, etc.

**Verification**: No code accesses `global_constraints['validation_checkpoints']`

**What IS used**:
- `validate_30_event_table()` in step_6.py is a custom Python function
- Uses hardcoded validation logic, NOT JSON-driven

**Recommendation**: ✅ **SAFE TO REMOVE** unless you want JSON-driven validation (would require refactoring).

---

### 4. PARTIALLY USED: `false_alarm_taxonomy` in global_constraints_v2.json ⚠️

**Status**: DOCUMENTED but NOT PROGRAMMATICALLY USED  
**Location**: global_constraints_v2.json, lines 73-120

**Current Content**:
```json
"false_alarm_taxonomy": {
    "type_1": { "name": "Unusual Port + Benign Service", ... },
    "type_2": { "name": "High Volume + Low-Risk Service", ... },
    "type_3": { "name": "Rare Duration + Benign Context", ... }
}
```

**Actual Implementation**:
- FALSE_ALARM_TYPES hardcoded in `step_5.py` lines 38-52:
```python
FALSE_ALARM_TYPES = {
    'type_1_unusual_port_benign_service': {
        'count': 2,
        'description': 'Unusual port + benign service...'
    },
    ...
}
```

**Status**: Used only for description/documentation, not config-driven.

**Recommendation**: ⚠️ **KEEP for documentation**, but note it's not actively read by code.

---

### 5. USED: `network_topology_reference` in global_constraints_v2.json ✅

**Status**: MENTIONED in code comments, topology data is in helper_functions.py  
**Location**: global_constraints_v2.json, lines 24-29

**Current Content**:
```json
"network_topology_reference": {
    "note": "Network topology is now fully specified in terraform_network.json...",
    "observation_window_duration_seconds": 1800,
    ...
}
```

**Actual Usage**:
- Network topology is hardcoded in `helper_functions.py`, lines 14-41:
```python
IP_RANGES = {
    '192.168.1': ['User0', 'User1', 'User2', 'User3', 'User4'],
    '192.168.2': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'],
    '192.168.3': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],
}
SUBNET_MAPPING = {
    'User': 'Subnet 1 (User)',
    'Enterprise': 'Subnet 2 (Enterprise)',
    ...
}
```

**Recommendation**: ⚠️ **BE CAREFUL** - topology is implicit in code, not in JSON.

---

### 6. USED: `unsw_filtering` in zero_day_templates.json ✅

**Status**: ACTIVELY USED in Step 2  
**Location**: zero_day_templates.json, per scenario

**Current Content** (example WannaCry):
```json
"unsw_filtering": {
    "attack_cat": ["Exploits", "Worms"],
    "proto": [],
    "dport": [],
    "behavioral_cues": [...]
}
```

**Actual Usage**:
- `step_2.py`, line 232: `unsw_filters = scenario_template.get('unsw_filtering', {})`
- Used to filter UNSW data by attack_cat

**Recommendation**: ✅ **KEEP** - This is actively used.

---

### 7. PARTIALLY USED: `feature_constraints` in zero_day_templates.json ⚠️

**Status**: DEFINED but content NOT PROGRAMMATICALLY READ  
**Location**: zero_day_templates.json, per scenario

**Current Content** (example WannaCry):
```json
"feature_constraints": {
    "duration": { "min": 0.0, "max": 59.999046, "median": 0.48692 },
    "bytes": { "min": 60, "max": 13027669, "median": 1624 },
    "packets": { "min": 1, "max": 11068, "median": 18 },
    "rate": { "median_mbps": 0.026682 },
    "dport": { "unique_values": [20, 21, 22, ...] },
    "_notes": "To be populated in Step 2..."
}
```

**Actual Usage**:
- NOT read by step_3.py codes
- Feature constraints are defined locally in `step_3.py`, lines 24-58 (FEATURE_CONSTRAINTS dict):
```python
FEATURE_CONSTRAINTS = {
    'WannaCry': {
        'duration_range': (0.05, 2.0),
        'bytes_range': (200, 10000),
        'packets_range': (5, 100),
        ...
    },
    ...
}
```

**Issue**: Mismatch between JSON feature ranges and hardcoded values in step_3.py. 
- JSON says WannaCry bytes: 60-13,027,669 bytes (huge range)
- step_3.py says: 200-10,000 bytes (much narrower)

**Recommendation**: ⚠️ **DECISION NEEDED** - Consolidate into single source of truth.

---

### 8. REFERENCED BUT OUTDATED: UNSW Dataset Path in global_constraints_v2.json ❌

**Status**: PATH CONTAINS TYPO  
**Location**: global_constraints_v2.json, line 272

**Current Content**:
```json
"original_path": "C:\\Users\\groessli\\Documents\\GitHub\\CHART_IDS_Experiment\\IDSD_Datasets\\UNSW_NB15_training-set(in).csv"
```

**Issue**: Path references `IDSD_Datasets` (TYPO) but actual directory is `IDS_Datasets`

**Verification**:
- Actual file exists: `c:\Users\groessli\Documents\GitHub\CHART_IDS_Experiment\IDS_Datasets\UNSW_NB15_training-set(in).csv` ✅
- Referenced file: `c:\Users\groessli\Documents\GitHub\CHART_IDS_Experiment\IDSD_Datasets\...` ❌ DOES NOT EXIST

**Recommendation**: ✅ **SAFE TO FIX** - Correct the typo in the JSON.

---

### 9. POTENTIALLY OUTDATED: Dates in JSON Files

**Status**: DOCUMENTS ARE RECENT, DATES ARE VALID  

**global_constraints_v2.json**:
- Line 4: `"last_updated": "2026-04-17"` (7 days ago) ✅

**zero_day_templates.json**:
- No `last_updated` field, but content references current pipeline ✅

**Recommendation**: ✅ **DATES ARE CURRENT** - No action needed.

---

### 10. STRUCTURE: Zero-Day Template Metadata

**Status**: SOME FIELDS ARE PLANNING STATUS, NOT FINAL STATE  

**Examples**:
- Each scenario has `"expected_tier": 1` with note: `"To be determined in Step 2..."` (line 506 in zero_day_templates.json)
- Each scenario has `"_notes": "To be populated in Step 2..."` (line 105, etc.)

**Context**: These are planning notes, not configuration that needs removal. However, they flag sections that SHOULD be updated by step_2 but may not be.

**Verification Check**: 
- Does Step 2 actually populate `expected_tier`? Need to verify if `templates['scenarios'][scenario_idx]['expected_tier'] = tier` is being executed.

**Recommendation**: ⚠️ **VERIFY** - Confirm step_2 populates these fields as designed.

---

## SUMMARY TABLE

| Section | File | Used? | Status | Recommendation |
|---------|------|-------|--------|-----------------|
| `label_distribution` | global_constraints_v2.json | ❌ NO | OBSOLETE | Remove or make reference-only |
| `temporal_architecture_principles` | global_constraints_v2.json | ⚠️ PARTIAL | Contradicts code | Align JSON with hardcoded step_2.py values or refactor |
| `validation_checkpoints` | global_constraints_v2.json | ❌ NO | UNUSED | Remove (unless converting to JSON-driven) |
| `false_alarm_taxonomy` | global_constraints_v2.json | ⚠️ REFERENCE | Doc only | Keep for documentation |
| `network_topology_reference` | global_constraints_v2.json | ⚠️ REFERENCE | Topology in code | Note: topology is hardcoded in helper_functions.py |
| `unsw_filtering` | zero_day_templates.json | ✅ YES | ACTIVE | **KEEP** |
| `feature_constraints` | zero_day_templates.json | ⚠️ PARTIAL | Contradicts step_3.py | Consolidate into single source or reference only |
| `UNSW path` | global_constraints_v2.json | ❌ NO (typo) | INCORRECT | Fix typo: `IDSD_Datasets` → `IDS_Datasets` |
| `expected_tier` note | zero_day_templates.json | ⚠️ PROCESS | Planning status | Verify Step 2 populates this |
| `malicious_count` | zero_day_templates.json | ✅ YES | ACTIVE | **KEEP** |

---

## PARAMETERIZATION CONTRADICTION

**Original Design Promise** (from PARAMETERIZATION_CLARIFICATION.md, lines 27-34):
```
The PARAMETERIZATION_PLAN RETAINS global_constraints.json completely unchanged.
- label_distribution → KEEP (defines ratios, not specific counts)
- temporal_architecture → KEEP (5 phases, 1800s window)
- false_alarm_taxonomy → KEEP (3 FA types)
- validation_checkpoints → KEEP (sanity checks)
```

**Actual Implementation**:
- `label_distribution` - NOT read by pipeline ❌
- `temporal_architecture_principles` - NOT read; hardcoded in step_2.py instead ❌
- `false_alarm_taxonomy` - NOT read; hardcoded in step_5.py instead ❌
- `validation_checkpoints` - NOT read; hardcoded in step_6.py instead ❌

**Conclusion**: The code evolved differently than the documentation specified. The documentation is aspirational, not representative of current implementation.

---

## RECOMMENDATIONS

### High Priority (Data Integrity)
1. **Fix UNSW dataset path typo**: `IDSD_Datasets` → `IDS_Datasets` in global_constraints_v2.json line 272

### Medium Priority (Cleanup)
2. **Remove `label_distribution` section** from global_constraints_v2.json - it contradicts the parameterized pipeline
3. **Remove or restructure `validation_checkpoints`** - it's not used; consider making it reference documentation

### Low Priority (Clarification)
4. **Document actual feature constraint sources**: 
   - Add note in global_constraints_v2.json: "feature_constraints in zero_day_templates.json override these values"
   - Add note in step_3.py documenting why FEATURE_CONSTRAINTS are hardcoded

5. **Document temporal architecture decision**:
   - Add note in step_2.py: why `get_standard_phases()` is hardcoded instead of JSON-driven
   - Consider if parameterization of phase structure is needed in future

### Verification Tasks
6. **Verify zero_day_templates population**: Confirm step_2 is updating:
   - `expected_tier`
   - `_step2_stats`
   - Feature constraint values

---

## SAFE REMOVAL CANDIDATES

These can be removed **without breaking the pipeline**:

1. ✅ `global_constraints_v2.json` → `label_distribution` (entire section)
2. ✅ `global_constraints_v2.json` → `validation_checkpoints` (entire section, or keep as documentation)
3. ⚠️ `global_constraints_v2.json` → `temporal_architecture_principles` (keep if documenting the 5-phase design intent)

**DO NOT REMOVE** (actively used):
- ❌ `zero_day_templates.json` → `unsw_filtering`
- ❌ `zero_day_templates.json` → `malicious_count`
- ❌ `helper_functions.py` constants (IP_RANGES, SUBNET_MAPPING, etc.)

