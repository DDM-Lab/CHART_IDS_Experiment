# PARAMETERIZATION_PLAN Clarification Memo

**Date**: April 19, 2026  
**Purpose**: Clarify ambiguities in PARAMETERIZATION_PLAN.md to prevent misinterpretation, especially regarding global_constraints.json retention  
**Audience**: Future implementers, AI models, design reviewers

---

## EXECUTIVE SUMMARY

**The PARAMETERIZATION_PLAN RETAINS global_constraints.json completely unchanged.**

Only `zero_day_templates.json` receives a new field: `malicious_count` per scenario.

This memo clarifies confusing language in the original plan that could be misinterpreted as deprecating global_constraints.json.

---

## CRITICAL CLARIFICATIONS

### 1. GLOBAL_CONSTRAINTS.JSON: WHAT STAYS (UNCHANGED)

The following fields in `global_constraints.json` are **NOT affected** by parameterization:

```json
{
  "label_distribution": { ... },           // ✓ KEEP (defines ratios, not specific counts)
  "network_topology": { ... },             // ✓ KEEP (subnet design, routing rules)
  "unsw_grounding_principles": { ... },    // ✓ KEEP (explains UNSW usage)
  "tiered_synthesis_framework": { ... },   // ✓ KEEP (TIER 1/2/3 definitions)
  "false_alarm_taxonomy": { ... },         // ✓ KEEP (3 FA types)
  "temporal_architecture": { ... },        // ✓ KEEP (5 phases, 1800s window)
  "output_schema": { ... },                // ✓ KEEP (23 columns)
  "validation_checkpoints": { ... }        // ✓ KEEP (sanity checks)
}
```

**None of these fields change.** They are read by Steps 3, 4, 5, and 6 throughout execution.

### 2. ZERO_DAY_TEMPLATES.JSON: WHAT CHANGES (NEW FIELD ONLY)

**ONE field is added** to each scenario in `zero_day_templates.json`:

```json
{
  "scenarios": [
    {
      "scenario_name": "WannaCry",
      "malicious_count": 11,                // ← NEW FIELD (was derived before, now explicit)
      "max_false_alarm_pct": 0.63,          // ← OPTIONAL reference (not enforced)
      ... rest of scenario fields unchanged ...
    }
  ]
}
```

**Why add it here?**
- Makes scenario-specific attack complexity explicit
- Step 3 reads this directly (simpler than deriving from constraints)
- Enables per-scenario parameterization in future versions

**Why not remove from global_constraints?**
- global_constraints.json serves a different purpose (global topology + rules)
- Adding one field is less risky than reorganizing both files

### 3. CLARIFICATION OF "READ FROM TEMPLATES, NOT GLOBAL_CONSTRAINTS" STATEMENT

**ORIGINAL PLAN LANGUAGE (ambiguous)**:
> "Modification: Read `malicious_count` from scenario data via templates_path (no parameterization)"

**POTENTIAL MISINTERPRETATION**:
- "Stop reading global_constraints.json entirely" ❌ WRONG

**CORRECT INTERPRETATION**:
- "Read **scenario-specific** malicious_count from templates (new field)"
- "Continue reading network topology, phases, FA taxonomy from global_constraints (unchanged)"

**EXAMPLE: Step 3 during execution**

```python
# ✓ Correct: Step 3 reads BOTH
def generate_malicious_events_step_3(...):
    global_constraints = load_json("global_constraints.json")  # Read phases, topology
    templates = load_json("zero_day_templates.json")            # Read malicious_count
    
    for scenario in templates['scenarios']:
        mal_count = scenario['malicious_count']                 # NEW: explicit count
        phases = global_constraints['temporal_architecture']    # UNCHANGED: still needed
        
        # Generate malicious events using both
```

---

## DEPENDENCY MATRIX: WHICH CONFIG FILES ARE USED WHERE

### Per-Step Dependencies

| Step | Reads global_constraints? | Reads templates? | Purpose of Each Read |
|------|---------------------------|-----------------|----------------------|
| **Step 3** | ✅ YES (phases, topology, FA rules) | ✅ YES (malicious_count) | Generate attack events with temporal ordering |
| **Step 4** | ✅ YES (topology constraints) | ✅ YES (benign_count, network_topology copy) | Generate baseline traffic respecting topology |
| **Step 5** | ✅ YES (FA taxonomy, temporal zones) | ✅ YES (false_alarm_count) | Generate 3 FA types in isolation zones |
| **Step 6** | ✅ YES (phases, temporal architecture) | ✅ YES (all counts per scenario) | Assemble final table with temporal ordering |

### Field-Level Dependencies

**global_constraints.json fields used:**

| Field | Accessed By | Purpose |
|-------|-------------|---------|
| `temporal_architecture.phases` | Steps 3, 6 | Define phase timestamps (300-900s attack window) |
| `network_topology.subnets[]` | Steps 4, 5, 6 | Validate host assignments (no direct User ↔ Operational) |
| `false_alarm_taxonomy` | Step 5 | Define 3 FA types (unusual_port, high_volume, rare_duration) |
| `output_schema` | Steps 6 | Column names and order for final CSV |
| `tiered_synthesis_framework` | Step 3 | TIER 1/2/3 fallback rules if UNSW data insufficient |

**zero_day_templates.json fields used:**

| Field | Accessed By | Purpose |
|-------|-------------|---------|
| `scenarios[].scenario_name` | All steps | Filter data per scenario |
| `scenarios[].malicious_count` | **Steps 3, 6** | **NEW**: Explicit count (replaces derived value) |
| `scenarios[].features[]` | Steps 3, 4, 5 | Feature ranges per scenario |
| `scenarios[].attack_description` | Steps 3, 4 | Attack context for phase allocation |

---

## WHAT CHANGED: BEFORE vs. AFTER

### BEFORE Parameterization

```
global_constraints.json:
  label_distribution:
    malicious: "10-11 events"    ← Generic (applies to all scenarios)

zero_day_templates.json:
  scenarios: [ WannaCry, Data_Theft, ... ]
    (NO malicious_count field)

Step 3:
  1. Reads global_constraints → gets "10-11"
  2. Randomly samples 10-11 UNSW rows
  3. Assumes same count for all scenarios (incorrect!)
```

### AFTER Parameterization

```
global_constraints.json:
  label_distribution: (unchanged, now just reference)
  
zero_day_templates.json:
  scenarios: [
    { scenario_name: "WannaCry", malicious_count: 11, ... },
    { scenario_name: "Data_Theft", malicious_count: 9, ... },
    ...
  ]

Step 3:
  1. Reads templates → gets scenario-specific count (11 for WannaCry, 9 for Data_Theft)
  2. Samples EXACTLY that count from UNSW
  3. Assigns timestamps using global_constraints phases (unchanged)
```

**Key difference**: Malicious count is now **explicit per scenario** instead of **generic**

---

## IMPLEMENTATION LOGIC (Reference for Coding)

### DO NOT interpret this requirement as:
❌ Remove global_constraints from any step  
❌ Consolidate global_constraints into templates  
❌ Stop reading template phases from global_constraints  

### DO interpret as:
✅ Add `malicious_count` field to each scenario in templates  
✅ Continue reading topology, phases, FA taxonomy from global_constraints  
✅ Step 3 chooses between templates (`malicious_count`) and global_constraints (`phases`) based on what's needed  

### Example Implementation Pattern:

```python
def generate_malicious_events_step_3(
    transformed_csv_path,
    templates_path,                    # ← Contains new malicious_count
    global_constraints_path,           # ← Contains phases, topology (STILL NEEDED)
    random_seed=42
):
    """Generate attack events with scenario-specific counts and temporal ordering."""
    
    # Load both config files
    templates = load_json(templates_path)
    global_constraints = load_json(global_constraints_path)
    
    results = {}
    for scenario in templates['scenarios']:
        scenario_name = scenario['scenario_name']
        
        # FROM TEMPLATES: Get scenario-specific count (NEW)
        malicious_count = scenario['malicious_count']
        
        # FROM GLOBAL_CONSTRAINTS: Get phase structure (UNCHANGED)
        phases = global_constraints['temporal_architecture']['phases']
        topology = global_constraints['network_topology']
        
        # Generate events using BOTH pieces of info
        events = _generate_events_for_scenario(
            data, 
            malicious_count=malicious_count,  # Explicit count
            phases=phases,                     # Temporal structure
            topology=topology                  # Network structure
        )
        results[scenario_name] = events
    
    return results
```

---

## WHY BOTH FILES COEXIST

| Aspect | global_constraints.json | zero_day_templates.json |
|--------|-------------------------|-------------------------|
| **Scope** | Global (all scenarios) | Per-scenario |
| **Durability** | Changes rarely | Changes per scenario design |
| **Purpose** | Experimental rules | Attack descriptions |
| **Reusability** | Same topology for all scenarios | Different attacks, same topology |
| **Maintainability** | One master file | Separate scenario definition |

**Example**: To test a new attack scenario:
1. Add entry to `zero_day_templates.json` (no change to global_constraints)
2. Run pipeline with same global topology
3. Results: New scenario dataset generated

To change network topology:
1. Edit `global_constraints.json`
2. All scenarios recomputed with new topology
3. Results: All scenarios use new network

This separation enables **flexibility without duplication**.

---

## VALIDATION CHECKLIST FOR FUTURE IMPLEMENTATIONS

When implementing parameterization, verify:

- [ ] **File Independence**: Does Step 3 read from global_constraints for topology? Does it read templates for malicious_count?
- [ ] **Backward Compatibility**: Do existing scenarios in templates still load without errors?
- [ ] **Config Coverage**: Does main.py pass both config paths to all steps?
- [ ] **Temporal Logic**: Do Steps 3-6 correctly use phases from global_constraints + counts from templates?
- [ ] **No Consolidation**: Are both files still separate (not merged into one)?
- [ ] **Documentation**: Does code have comments like "# From global_constraints" and "# From templates"?

---

## SUMMARY FOR CODE REVIEWERS

**If you see code that**:
```python
# ❌ WRONG: Only reading from templates
scenario_template = templates['scenarios'][0]
phases = scenario_template['phases']  # ERROR: phases are in global_constraints!
```

**Should be**:
```python
# ✅ CORRECT: Reading from appropriate sources
scenario_template = templates['scenarios'][0]
mal_count = scenario_template['malicious_count']  # From templates
phases = global_constraints['temporal_architecture']['phases']  # From global_constraints
```

---

## Questions This Memo Addresses

**Q: Should we deprecate global_constraints.json?**  
A: **No.** It remains essential for network topology, phases, and FA taxonomy. Only add malicious_count to templates.

**Q: Can we move everything to templates.json?**  
A: Not recommended. Separating global topology (constraints) from per-scenario attacks (templates) enables independent updates.

**Q: What if Step 3 tries to read phases from templates?**  
A: **Fails silently** (field doesn't exist). Always read temporal_architecture from global_constraints.

**Q: Does parameterization require changing Step 0?**  
A: No. Step 0 (both JSON files) requires minimal changes:
- global_constraints.json: Use as-is (no changes)
- zero_day_templates.json: Add malicious_count field only

