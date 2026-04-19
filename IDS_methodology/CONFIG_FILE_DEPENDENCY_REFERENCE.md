# Config File Dependency Reference

**Date**: April 19, 2026  
**Purpose**: Quick reference for which config files are used by each pipeline component  
**Audience**: Developers, reviewers, future maintainers

---

## QUICK REFERENCE: CONFIG FILE USAGE BY STEP

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PIPELINE CONFIG FILE DEPENDENCIES                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Pre-Step           Step 1          Step 2          Step 3          Step 4  │
│  ────────           ──────          ──────          ──────          ──────  │
│  (UNSW only)   ┌─ Constraints  ┌─ Constraints  ┌─ Constraints  ┌─ Constraints
│                │  Templates    │  Templates    │  Templates    │  Templates
│                └──────────────┘  Templates     │  Templates    │  Templates
│                                  ├─ Phases ◄───┤  ├─ Phases ◄───┤  ├─ Phases
│                                  ├─ Topology    │  ├─ Topology   │  ├─ Topology
│                                  └─ TIER rules  │  └─ TIER rules │  └─ Counts
│
│  Step 5          Step 6
│  ──────          ──────
│  ┌─ Constraints  ┌─ Constraints
│  │  Templates    │  Templates
│  │  ├─ FA types  │  ├─ All counts
│  │  ├─ Phases    │  ├─ Phases
│  │  ├─ Topology  │  ├─ Topology
│  │  └─ Counts    │  ├─ Schema
│  │               │  └─ Validation
│  └───────────────┘
│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## DETAILED MATRIX: WHAT EACH STEP READS

### Step 2: Filter & Tier Classification

| Config File | Field | Purpose | Critical? |
|-------------|-------|---------|-----------|
| **global_constraints.json** | `tiered_synthesis_framework` | Determine TIER classification thresholds | ✅ YES |
| **zero_day_templates.json** | `scenarios[].attack_description` | Filter UNSW rows by scenario | ✅ YES |
| **zero_day_templates.json** | `scenarios[].features` | Extract feature ranges for statistics | ✅ YES |

### Step 3: Malicious Event Generation

| Config File | Field | Purpose | Critical? | Source |
|-------------|-------|---------|-----------|--------|
| **zero_day_templates.json** | `scenarios[].malicious_count` | How many attack events to generate | ✅ YES | **NEW** (parameterization) |
| **global_constraints.json** | `temporal_architecture.phases` | Where to place events (timestamps 300-900s) | ✅ YES | Existing |
| **global_constraints.json** | `network_topology` | Valid hosts for event assignment | ✅ YES | Existing |
| **global_constraints.json** | `tiered_synthesis_framework` | TIER 1/2/3 fallback rules if data insufficient | ⚠️ FALLBACK | Existing |

### Step 4: Benign Event Generation

| Config File | Field | Purpose | Critical? | Source |
|-------------|-------|---------|-----------|--------|
| **zero_day_templates.json** | `scenarios[].benign_count` | How many benign events to generate | ✅ YES | **Derived** (total - malicious - fa) |
| **zero_day_templates.json** | `scenarios[].features` | Feature ranges for realistic traffic | ✅ YES | Existing |
| **global_constraints.json** | `network_topology` | Enforce routing constraints (User ↔ Operational) | ✅ YES | Existing |
| **global_constraints.json** | `output_schema` | Column names for output | ⚠️ Reference | Existing |

### Step 5: False Alarm Generation

| Config File | Field | Purpose | Critical? | Source |
|-------------|-------|---------|-----------|--------|
| **zero_day_templates.json** | `scenarios[].false_alarm_count` | How many FA events to generate | ✅ YES | **NEW** (parameterization) |
| **global_constraints.json** | `false_alarm_taxonomy` | Define 3 FA types and anomaly rules | ✅ YES | Existing |
| **global_constraints.json** | `temporal_architecture` | Isolation zones for FA distribution (600-700s, 1200-1300s, etc.) | ✅ YES | Existing |
| **global_constraints.json** | `network_topology` | Valid hosts for FA injection | ✅ YES | Existing |

### Step 6: Final Assembly & Temporal Ordering

| Config File | Field | Purpose | Critical? | Source |
|-------------|-------|---------|-----------|--------|
| **zero_day_templates.json** | All scenario counts | Assemble final event pool | ✅ YES | From Steps 3-5 |
| **global_constraints.json** | `temporal_architecture` | Phase-based temporal ordering | ✅ YES | Existing |
| **global_constraints.json** | `output_schema` | Final structure and column names | ✅ YES | Existing |
| **global_constraints.json** | `validation_checkpoints` | Sanity checks before output | ⚠️ Safety net | Existing |

---

## CONFIG FILE FIELD INVENTORY

### global_constraints.json (UNCHANGED - All Retained)

**Network & Topology** (used by all steps):
- `network_topology.subnets[]` → Step 3, 4, 5, 6 (host validation)
- `network_topology.routing_constraints` → Step 4, 5 (topology enforcement)

**Temporal Structure** (used by Steps 3, 5, 6):
- `temporal_architecture.phases[].name` → Phases (baseline, attack, recovery)
- `temporal_architecture.phases[].start_time` → Timestamp allocation
- `temporal_architecture.phases[].duration` → Phase length

**Event Rules** (used by Steps 3, 5):
- `tiered_synthesis_framework` → Step 3 (TIER 1/2/3 rules)
- `false_alarm_taxonomy` → Step 5 (3 FA types definition)

**Validation & Output** (used by Steps 2, 4, 6):
- `output_schema` → Column names and format
- `label_distribution` → Reference (probabilities, now with parameterization)
- `validation_checkpoints` → Sanity check rules

### zero_day_templates.json (NEW FIELDS Added)

**Per-Scenario Event Counts** (parameterized):
- `scenarios[].malicious_count` → **NEW**: Explicit count (11, 9, 7 per attack complexity)
- `scenarios[].benign_count` → **DERIVED**: total - malicious - false_alarm
- `scenarios[].false_alarm_count` → **NEW**: Explicit count from false_alarm_pct

**Existing Fields** (unchanged):
- `scenarios[].scenario_name` → Used by all steps
- `scenarios[].attack_description` → Step 2 filtering context
- `scenarios[].features[]` → Feature ranges for generation
- `scenarios[].feature_constraints` → Min/max bounds for random generation

---

## DEPENDENCY GRAPH: Upstream ← Downstream

```
global_constraints.json                zero_day_templates.json
        ↓                                       ↓
    Step 2 ←───────────────────────── → Step 2
    (filter & tier)                   (scenarios, features)
        ↓                                       ↓
    Step 3 ←───────────────────────── → Step 3
    (phases, topology, TIER)          (malicious_count - NEW)
        ↓                                       ↓
    Step 4 ←───────────────────────── → Step 4
    (topology)                        (benign_count - DERIVED)
        ↓                                       ↓
    Step 5 ←───────────────────────── → Step 5
    (FA types, phases, topology)      (false_alarm_count - NEW)
        ↓                                       ↓
    Step 6 ←───────────────────────── → Step 6
    (phases, schema)                  (all counts)
        ↓                                       ↓
    Final CSVs with metadata columns (timestamps, event types, counts)
```

---

## PARAMETERIZATION IMPACT MAP

### What Changed

| Component | Before | After | Impact |
|-----------|--------|-------|--------|
| Malicious count | Generic "10-11" in global_constraints | Explicit per-scenario in templates | ✅ Per-scenario flexibility |
| Benign count | Hard-coded 15 per step | Derived from total - malicious - fa | ✅ Dynamic based on total |
| FA count | Hard-coded 4-5 per step | Parameterized per scenario | ✅ User-configurable |
| Total events | Hard-coded 30 | User parameter (18-45 range) | ✅ Table size flexibility |

### What Stayed the Same

| Component | Status | Why |
|-----------|--------|-----|
| Network topology | UNCHANGED | Global network design doesn't change per config |
| Temporal phases | UNCHANGED | Attack progression phases are fixed per scenario |
| FA taxonomy | UNCHANGED | 3 FA type definitions are stable |
| Output schema | UNCHANGED | CSV columns remain the same |
| main.py flow | MOSTLY SAME | Both config files still read, just new fields added |

---

## IMPLEMENTATION CHECKLIST FOR NEW FEATURES

When adding new parameters to the pipeline:

### ✅ DO
- [ ] Add new field to appropriate config file (constraints or templates)
- [ ] Document which steps read this field
- [ ] Add comments in main.py showing config dependency
- [ ] Update this reference table
- [ ] Validate field exists before using

### ❌ DO NOT
- [ ] Consolidate both config files into one (breaks separation of concerns)
- [ ] Remove global_constraints.json fields (still needed for topology/phases)
- [ ] Move topology/phases to templates (scenario-specific, not global)
- [ ] Skip configuration file validation in main.py

---

## TROUBLESHOOTING: "File Not Found" or "Field Missing" Errors

| Error Message | Check | Resolution |
|---------------|-------|-----------|
| "global_constraints.json not found" | Is Step 0 complete? | Verify file exists in `templates/` |
| "scenarios[].malicious_count undefined" | Is Step 1 validation passing? | Add field to zero_day_templates.json |
| "phases field missing" | Is Step 2 reading constraints? | Verify global_constraints.json is valid JSON |
| "network_topology.subnets is empty" | Is topology defined? | Check global_constraints.json structure |
| "benign_count computed to negative" | Is false_alarm_pct too high? | Lower false_alarm_bin or increase total_events |

---

## VALIDATION: Ensuring Both Files Are Used Correctly

### Test Step 3: Should read from BOTH files

```python
# Verify Step 3 opens both files
assert "zero_day_templates.json" in step3_file_reads  # For malicious_count
assert "global_constraints.json in step3_file_reads   # For phases, topology
```

### Test Step 6: Should validate all counts sum properly

```python
# Verify final assembly uses both configs
malicious + benign + false_alarm == total_events
# Total events from main.py param (global)
# Counts from templates per scenario
```

### Code Review Checklist

When reviewing code changes:

1. **Does the step open both JSON files?**
   - ✅ `templates = json.load(templates_path)`
   - ✅ `constraints = json.load(global_constraints_path)`

2. **Does it read from the correct config for each field?**
   - ❌ Trying to read phases from templates (should be from constraints)
   - ✅ Reading malicious_count from templates (new per-scenario)
   - ✅ Reading network_topology from constraints (global)

3. **Are both files passed to the function?**
   - ✅ Function signature includes both paths
   - ✅ Both files opened inside function
   - ❌ Only one file passed (missing dependency)

---

## SUMMARY

**Config File Architecture**:
- **global_constraints.json** = Global experimental rules (topology, phases, FA types)
- **zero_day_templates.json** = Per-scenario attack descriptions (+ NEW: event counts)

**Parameterization adds**:
- `malicious_count` per scenario (explicit, not derived)
- `false_alarm_count` per scenario (parameterized via user's false_alarm_pct)
- `benign_count` per scenario (derived: total - malicious - fa)

**Both files coexist** because they serve different purposes. Keeping them separate enables flexible scenario development without reorganizing global topology.

