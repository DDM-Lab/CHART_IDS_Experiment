# Parameterization Plan Review - Implementation Gaps & Ambiguities

**Review Date**: April 18, 2026  
**Status**: CRITICAL GAPS IDENTIFIED - Requires Clarification Before Implementation

---

## CRITICAL ISSUES (Must Fix Before Implementation)

### ❌ ISSUE #1: Contradictory Storage Locations
**Severity**: CRITICAL  
**Location**: Main plan vs. Step 3-4 code snippets

**Problem**:
- Main plan (Section 2) states: Store malicious_count in `zero_day_templates.json`
- Step 3 code snippet shows: `global_constraints_path` lookup → `global_constraints['scenario_malicious_events'][scenario_name]`
- Step 4 code snippet correctly shows: `templates_path` lookup

**Impact**: Code will fail at runtime - looking for data in wrong file

**Required Clarification**: 
- Should Step 3 read from `templates_path` (zero_day_templates.json) or `global_constraints_path`?
- Answer: Should be `templates_path` per user decisions

**Action Item**: Update Step 3 code snippet to use templates_path

---

### ❌ ISSUE #2: Per-Scenario Validation Logic Undefined
**Severity**: CRITICAL  
**Location**: Section 3-4 ("Validation & capping")

**Problem**:
- Plan says: "Reject configurations where malicious_count + false_alarm_count > total_events_per_table"
- But doesn't specify WHERE this validation happens
- Different scenarios have different malicious_count (7, 9, or 11)
- Plan references `max_false_alarm_pct` per scenario but doesn't show enforcement code

**Missing Details**:
- Should validation happen in main.py (once per config) or per Step?
- If per-scenario in main.py, which scenarios fail for a given config?
- Should main.py reject entire run or just problematic scenarios?
- What's the error message format?

**Example Invalid Config**:
```
total_events_per_table = 18
false_alarm_pct = 0.50  (50%)
Results:
  WannaCry: mal(11) + fa(9) = 20 > 18 ❌ REJECT
  Data_Theft: mal(9) + fa(9) = 18 ✓ OK
  Netcat_Backdoor: mal(7) + fa(9) = 16 ✓ OK
```

**Required Answer**: 
- Should main.py reject if ANY scenario fails, or allow mixed results?

**Action Item**: Add explicit validation function with per-scenario error messages

---

### ❌ ISSUE #3: When is benign_count Computed?
**Severity**: CRITICAL  
**Location**: Main.py integration (not shown in plan)

**Problem**:
- Plan says Step 4 "Receive benign_count parameter"
- But doesn't clarify: Is benign_count computed once in main.py, or per-scenario?
- Different scenarios have different malicious_count → different benign_count

**Current Logic**:
```
benign_count = total - malicious - false_alarm
```

**Question**: 
- In main.py, do we compute ONE benign_count (won't work - scenarios differ)?
- Or compute PER SCENARIO in a dict: `benign_count_per_scenario = {'WannaCry': 14, 'Data_Theft': 16, ...}`?

**Impact**: If not computed per-scenario, Step 4 will use wrong count for non-WannaCry scenarios

**Required Answer**: Main.py must build `benign_count_per_scenario` dict before calling Step 4

**Action Item**: Add code showing benign_count computation loop in main.py

---

### ❌ ISSUE #4: Step Function Signatures & Call Flow
**Severity**: CRITICAL  
**Location**: How Steps 3-6 are invoked from main.py

**Problem**: Plan shows function signatures but not HOW they're CALLED

**Questions**:
1. **Step 3**: Is it called once per scenario, or once for all scenarios?
   - Current: `generate_malicious_events_step_3(..., scenario_name=None)`
   - How does main.py loop: For each scenario? Or compute all at once?

2. **Step 4**: Same question - is it called per-scenario?
   - Needs: `benign_count_per_scenario` dict built in main.py first
   - How does main loop through scenarios and call Step 4?

3. **Step 5**: Receives global `false_alarm_pct`, applies to all scenarios?
   - Or called per-scenario with `scenario_name` parameter?

4. **Step 6**: Receives `malicious_count_per_scenario` (dict) and `benign_count_per_scenario` (dict)?
   - How are these dicts constructed?
   - When are they passed to Step 6?

**Current Flow Not Shown**:
```
main.py:
  compute total, false_alarm_pct
  ??? → compute false_alarm_count (once? per-scenario?)
  loop per scenario:
    call Step 3 (how?)
    call Step 4 (how?)
    call Step 5 (how?)
  call Step 6 (with what params?)
```

**Action Item**: Add explicit pseudocode showing main.py → Steps 3-6 control flow

---

### ❌ ISSUE #5: Output Directory Creation Not Specified
**Severity**: HIGH  
**Location**: Section on "Design directory structure"

**Missing Details**:
- **WHO creates** the output directory `IDS_tables/30events_15pct_fa/`?
  - main.py?
  - Step 6?
  - helper function?
- **WHEN is it created**?
  - Before any steps run?
  - Right before Step 6?
- **What if it exists**? Overwrite? Error?
- **How is the directory name computed**?
  - `int(false_alarm_pct * 100)` or `round(false_alarm_pct * 100)`?
  - What if false_alarm_pct=0.1234 → directory name "12pct_fa" or "12.34pct_fa"?

**Required Answer**: Specify directory naming convention and creation logic

**Action Item**: Add code showing directory creation (likely in Step 6 or helper)

---

### ❌ ISSUE #6: Metadata Columns Not Specified in Plan
**Severity**: HIGH  
**Location**: User-selected feature, missing from plan

**Problem**: User wants 5 metadata columns per CSV, but plan doesn't specify:
- **WHERE added**: Which file/function adds them? (Step 6 or helper?)
- **WHICH columns**: User said `_total_events_param`, `_false_alarm_pct_param`, etc., but what's exact format?
- **COLUMN VALUES**:
  - `_total_events_param`: Integer (30)?
  - `_false_alarm_pct_param`: Float (0.15) or string ("15%")?
  - `_malicious_count_param`: Integer, per scenario (11)?
  - `_benign_count_param`: Integer, per scenario (14)?
  - `_false_alarm_count_param`: Integer (5)?
- **WHICH STEP adds them**: Step 6 main output function?

**Action Item**: Add explicit code showing where/how metadata columns are added to CSV

---

### ❌ ISSUE #7: Step 6 Temporal Architecture Edge Cases
**Severity**: HIGH  
**Location**: `_build_temporal_architecture()` function

**Problem**: Code assumes reasonable event counts, but doesn't handle edge cases:

```python
benign_baseline_count = max(1, ben_count // 5)  # ~20% in baseline
benign_recovery_count = ben_count - benign_baseline_count
```

**Edge Cases Not Handled**:
1. If `ben_count = 0`: baseline=1, recovery=-1 ❌ (negative!)
2. If `ben_count = 1`: baseline=1, recovery=0 ✓ (OK but tight)
3. If `ben_count = 2`: baseline=1, recovery=1 ✓ (OK)
4. If `mal_count = 0`: All three attack phases get 0 events ❌ (invalid)

**Impact**: When benign hits 0 (high FA scenarios), temporal architecture breaks

**Required Answer**: 
- Should we add guards against invalid edge cases?
- If ben_count=0, what's the temporal layout?
- If mal_count=0, what's the temporal layout?

**Action Item**: Add guard clauses and test edge cases (18 events, high FA%)

---

### ❌ ISSUE #8: Step 5 False Alarm Count Bounds
**Severity**: MEDIUM  
**Location**: Step 5 validation code

**Problem**: Code says:
```python
if false_alarm_count < 3:
    raise ValueError(f"false_alarm_count must be ≥3 for meaningful triage, got {false_alarm_count}")
```

**Questions**:
- Why exactly 3? Is this a hard business requirement?
- What if user sets `total=30, false_alarm_pct=0.05` → false_alarm_count=2?
  - Should this be rejected?
  - Or allowed?
- Why not allow 1-2 false alarms?

**Required Answer**: Clarify minimum false_alarm_count or remove constraint

**Action Item**: Either justify the ≥3 constraint or lower it to ≥1

---

### ❌ ISSUE #9: Type 1/2/3 Rounding Logic
**Severity**: MEDIUM  
**Location**: Step 5 FA distribution code

**Problem**: Code distributes FA across 3 types:
```python
type_3_count = 1  # Reserved singleton
remaining = false_alarm_count - type_3_count
type_1_count = remaining // 2
type_2_count = remaining - type_1_count
```

**Examples**:
- FA=5: T1=2, T2=2, T3=1 ✓
- FA=6: T1=2, T2=3, T3=1 ✓
- FA=7: T1=3, T2=3, T3=1 ✓
- FA=8: T1=3, T2=4, T3=1 ✓

**Questions**:
- Is T2 always the "largest"? Intended?
- Should T1 and T2 be balanced? (e.g., FA=7 → 2/2/3 instead of 3/3/1)?
- What's the actual logic/requirement?

**Required Answer**: Confirm rounding/distribution strategy is intentional

**Action Item**: Document the T1/T2/T3 distribution rationale

---

## MODERATE ISSUES (Clarification Needed)

### ⚠️ ISSUE #10: Step 6 Output CSV Path Format
**Severity**: MEDIUM  
**Location**: Output file naming

**Question**: What's the exact file path format?
- Option A: `IDS_tables/30events_15pct_fa/WannaCry.csv`
- Option B: `IDS_tables/30events_15pct_fa/WannaCry_30events_15pct_fa.csv`
- Option C: Something else?

**Current Output**: Plan doesn't specify exact path template

**Action Item**: Clarify CSV output path naming convention

---

### ⚠️ ISSUE #11: Helper Function for Scenario Lookup
**Severity**: MEDIUM  
**Location**: Repeated in Steps 3, 4, 5

**Problem**: Multiple places do scenario lookup manually:
```python
for s in templates_data['scenarios']:
    if s['scenario_name'] == scenario_name:
        scenario_template = s
        break
```

**Question**: Should we add a helper function like:
```python
def get_scenario_template(templates_data, scenario_name):
    for s in templates_data['scenarios']:
        if s['scenario_name'] == scenario_name:
            return s
    raise ValueError(f"Scenario {scenario_name} not found")
```

**Action Item**: Add reusable helper in `helper_functions.py`

---

### ⚠️ ISSUE #12: Error Message Format for Invalid Configs
**Severity**: MEDIUM  
**Location**: Validation error messages

**Problem**: Plan mentions rejecting configs but doesn't show error messages

**Required Example**:
```
ERROR: Configuration invalid for scenario WannaCry
  Reason: malicious_count (11) + false_alarm_count (9) = 20 > total_events_per_table (18)
  Recommendation: Try one of:
    - Increase total_events_per_table to ≥20
    - Decrease false_alarm_pct from 0.50 to ≤0.39
    - Choose simpler scenario (Netcat_Backdoor has malicious_count=7)
```

**Action Item**: Specify exact error message format

---

### ⚠️ ISSUE #13: Backward Compatibility Strategy
**Severity**: MEDIUM  
**Location**: Migration from old pipeline

**Question**: Should existing code that reads `global_constraints.json` be updated to read `zero_day_templates.json`?
- Or maintain dual support?
- Or leave global_constraints.json alone?

**Impact**: If removing `scenario_malicious_events` from global_constraints.json, any code relying on it breaks

**Action Item**: Clarify what happens to global_constraints.json

---

## MINOR ISSUES (Documentation/Clarity)

### ℹ️ ISSUE #14: Commented-Out Default Directory
**Location**: Step 6 function signature

**Current Code**:
```python
def assemble_30_events_step_6(..., output_dir="IDS_tables", ...):
```

**Problem**: The function still says "IDS_tables" (singular root) but new design creates subdirectories

**Action Item**: Update default to reflect new structure or clarify behavior

---

### ℹ️ ISSUE #15: Missing Integration Example
**Severity**: LOW  
**Location**: Main.py flow not shown

**Missing**: A concrete pseudocode/example showing:
1. How main.py computes all values
2. How it calls each step
3. How it handles per-scenario dicts
4. Final output structure

**Action Item**: Add "Integration Example" section to plan with pseudocode

---

### ℹ️ ISSUE #16: Parameter Validation in main.py
**Location**: "User-Facing Parameters" section

**Current Code** shown: Validates total_events_per_table and false_alarm_pct ranges

**Missing**: 
- Per-scenario validation before calling steps
- Error handling for impossible configs
- Warnings for high FA% (already mentioned but not integrated)

**Action Item**: Add per-scenario validation function to plan

---

## SUMMARY: Ready for Implementation?

**Current Status**: ❌ **NOT READY** - Too many critical ambiguities

### Critical Path Blockers:
1. ✅ Resolve storage location (templates vs global_constraints)
2. ✅ Define per-scenario validation logic
3. ✅ Clarify control flow (main.py → Steps)
4. ✅ Specify output directory creation
5. ✅ Add metadata column implementation details
6. ✅ Handle temporal architecture edge cases
7. ✅ Confirm False Alarm type distribution strategy

### Recommendation:
- **Do NOT start implementation** until these 7 critical issues are resolved
- Create a small "implementation pseudocode" section showing exact main.py → Steps flow
- Add edge case handling for temporal architecture
- Specify exact directory naming and metadata column format

---

## Suggested Next Step

Create a new section in PARAMETERIZATION_PLAN.md called:
### "7. Main.py Integration & Control Flow (Pseudocode)"

Show:
```python
def main():
    # User parameters
    total_events_per_table = 30
    false_alarm_pct = 0.15
    
    # Load config
    with open("templates/zero_day_templates.json") as f:
        templates = json.load(f)
    
    # Validate user parameters
    validate_user_parameters(total_events_per_table, false_alarm_pct)
    
    # Compute global false_alarm_count (same for all scenarios)
    false_alarm_count = round(total_events_per_table * false_alarm_pct)
    
    # Per-scenario computation
    malicious_count_per_scenario = {}
    benign_count_per_scenario = {}
    
    for scenario in templates['scenarios']:
        scenario_name = scenario['scenario_name']
        mal_count = scenario['malicious_count']
        max_fa_pct = scenario['max_false_alarm_pct']
        
        # Validate per-scenario config
        validate_scenario_config(
            scenario_name,
            total_events_per_table,
            false_alarm_count,
            false_alarm_pct,
            max_fa_pct,
            mal_count
        )
        
        # Store counts for use in steps
        malicious_count_per_scenario[scenario_name] = mal_count
        benign_count_per_scenario[scenario_name] = (
            total_events_per_table - mal_count - false_alarm_count
        )
    
    # Call steps with pre-computed values
    step_3_result = step_3.generate_malicious_events_step_3(...)
    step_4_result = step_4.generate_benign_events_step_4(
        benign_count_per_scenario=benign_count_per_scenario,
        ...
    )
    step_5_result = step_5.generate_false_alarms_step_5(
        false_alarm_count=false_alarm_count,
        ...
    )
    step_6_result = step_6.assemble_30_events_step_6(
        output_dir=f"IDS_tables/{total_events_per_table}events_{int(false_alarm_pct*100)}pct_fa",
        malicious_count_per_scenario=malicious_count_per_scenario,
        benign_count_per_scenario=benign_count_per_scenario,
        false_alarm_count=false_alarm_count,
        ...
    )
```

This would eliminate most ambiguities!
