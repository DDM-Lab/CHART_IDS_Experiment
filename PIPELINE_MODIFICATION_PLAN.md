# Pipeline Modification Plan: Integration of network_topology_output.json and global_constraints_v2.json

**Date**: April 23, 2026  
**Purpose**: Document required changes to main.py and dependent code to support AWS-based network topology  
**Scope**: Modifications to accommodate global_constraints_v2.json + network_topology_output.json  
**Impact Level**: HIGH - Affects Steps 3, 4, 5, 6 (event generation and validation)

---

## EXECUTIVE SUMMARY

### Current State
- Pipeline uses **single constraint file**: `global_constraints.json` (abstract topology)
- Network topology: conceptual (host lists, routing rules, no concrete infrastructure)
- IP generation: synthetic, deterministic, not tied to real network infrastructure
- Steps 3-6: Generate events using abstract host names (User0-4, Enterprise0-2, etc.)

### Proposed State
- Replace constraint file: **`global_constraints.json` → `global_constraints_v2.json`**
- Add infrastructure reference: **`network_topology_output.json`** (AWS VPC, subnets, instances, concrete IPs)
- IP strategy: Deterministic concrete IPs from network_topology_output.json
- Topology convergence: All events grounded in realistic AWS infrastructure

### Expected Benefits
✅ **Naturalistic/standardized network structure** → Increases experimental design robustness  
✅ **Concrete infrastructure** → Easier to trace attack paths (AWS VPC context)  
✅ **Deterministic IP assignments** → Reproducible event generation with real IPs  
✅ **Reference implementation** → Downstream tools (e.g., NoDOZE) can validate against AWS topology  

### Key Risk Identified
⚠️ **Feasibility Impact**: Stricter AWS topology (concrete routing paths, security constraints) may reduce feasible event combinations in Steps 3-6  
⚠️ **Event Generation**: Cross-subnet attack paths now constricted (User1→Enterprise1→Enterprise2→OpServer0 only)  

---

## DETAILED ANALYSIS: FILE-BY-FILE COMPARISON

### 1. Global Constraints File Migration: v1 → v2

#### Current (global_constraints.json)
```json
"network_topology": {
  "subnets": {
    "subnet_1_user": {"hosts": ["User0", "User1", "User2", "User3", "User4"]},
    "subnet_2_enterprise": {"hosts": ["Enterprise0", "Enterprise1", "Enterprise2", "Defender"]},
    "subnet_3_operational": {"hosts": ["OpHost0", "OpServer0", "OpHost1", "OpHost2"]}
  },
  "routing_constraints": {
    "rule_1": "User1 is designated entry point from Subnet 1 to Subnet 2",
    "rule_2": "Enterprise2 is designated gateway from Subnet 2 to Subnet 3",
    "rule_3": "All cross-subnet transitions must follow these gateways"
  },
  "hostname_mapping_strategy": "Deterministic (MD5 hash)"
}
```

**Issues with v1**:
- Abstract host assignments (no concrete IPs or instance IDs)
- No subnet CIDR blocks
- No Internet Gateway information
- No mapping from hostname to specific AWS infrastructure
- Difficult for downstream tools to ground analysis in real infrastructure

#### Proposed (global_constraints_v2.json)
```
"network_topology_reference": {
  "note": "Network topology is now fully specified in terraform_network.json / network_topology_output.json"
}
```

**Changes in v2**:
- Delegates to `network_topology_output.json` for concrete infrastructure
- Maintains routing constraints (same semantic rules)
- Removes redundant abstract topology (consolidation for clarity)

**Migration Impact**:
- Remove abstract network_topology section from v1
- All topology lookups now reference network_topology_output.json

---

### 2. Network Topology Infrastructure File

#### New Reference: network_topology_output.json
```json
{
  "vpc_id": "vpc-0a1b2c3d4e5f6g7h8",
  "vpc_cidr": "10.0.0.0/16",
  
  "subnets": {
    "user_subnet_cidr": "10.0.1.0/24",
    "enterprise_subnet_cidr": "10.0.2.0/24",
    "operational_subnet_cidr": "10.0.3.0/24"
  },
  
  "user_private_ips": {
    "User0": "10.0.1.10",
    "User1": "10.0.1.11",
    ...
  },
  
  "enterprise_private_ips": {
    "Enterprise0": "10.0.2.10",
    "Enterprise1": "10.0.2.11",
    ...
  },
  
  "operational_private_ips": {
    "OpHost0": "10.0.3.10",
    ...
  },
  
  "routing_paths": {
    "attack_path": "User1 → Enterprise1 → Enterprise2 → OpServer0"
  }
}
```

**Key Additions**:
- Concrete VPC ID + CIDR block (AWS grounding)
- Precise subnet CIDR blocks (allows CIDR validation)
- Concrete private IPs (deterministic host-to-IP mapping)
- Instance IDs (AWS infrastructure tracking)
- Internet Gateway ID (external connectivity)
- Defender (IDS/IPS) system with VPC visibility

**Impact on Event Generation**:
1. **Host Selection**: Methods now reference concrete IPs from this file instead of generating synthetic IPs
2. **Subnet Inference**: Subnet CIDR blocks can validate host-subnet membership
3. **Cross-Subnet Validation**: Routing paths now strictly enforced
4. **External Connectivity**: Events with external_* hosts must validate against IGW rules

---

## IMPACT ANALYSIS: STEPS 3-6 CODE CHANGES

### Step 3: Malicious Events Generation
**Current Behavior**: 
- Uses abstract hostname (User1, Enterprise2, etc.)
- Maps to synthetic IPs via MD5 hashing
- Validates against routing constraints (semantic rules from global_constraints.json)

**Changes Required**:
```
1. Load concrete IPs from network_topology_output.json instead of hashing
2. Validate selected hosts exist in topology (cross-reference with concrete IPs)
3. Replace synthetic IP generation with deterministic lookup
4. Enforce routing path constraints more strictly (User1→Enterprise1→Enterprise2→OpServer0)
5. Risk: Some previously valid cross-subnet transitions may now be invalid
```

**Code Changes**:
- Replace: `generate_synthetic_ip(host, scenario_id)` 
- With: `lookup_concrete_ip(host, network_topology)` 
- Add validation: Confirm host exists in network_topology_output.json

**Feasibility Risk**:
- If v1 generated events like "User2 → Enterprise0" (direct cross-subnet), v2 will reject this
- Current code may rely on flexible routing; AWS topology more restrictive
- May need to adjust host selection logic if certain paths become infeasible

---

### Step 4: Benign Events Generation
**Current Behavior**:
- Generates 15 benign events per scenario (scenario-independent)
- Uses abstract hosts with synthetic IPs
- Validates topology constraints (intra-subnet OK, cross-subnet only via gateways)

**Changes Required**:
```
1. Load concrete IPs from network_topology_output.json
2. Host selection must prefer internal hosts from topology
3. External hosts (external_*) must be validated against IGW rules
4. Service-port assignments remain unchanged (HTTP, DNS, SSH, FTP, SMB, RDP)
5. Risk: May need more restrictive host-pair selection for realism
```

**Code Changes**:
- Replace synthetic IP generation with network_topology_output.json lookup
- For external hosts: Ensure they're routable via IGW (add validation check)
- Preserve per-service constraints (duration, bytes, etc.) - no change needed

**Feasibility Risk**: 
- LOWER than Step 3 (benign traffic more flexible)
- May limit external_* host pairs, but impact should be minimal

---

### Step 5: False Alarm Events Generation
**Current Behavior**:
- Generates 4-5 false alarms per scenario (3 types)
- Uses abstract hosts with synthetic IPs
- Validates topology during host placement

**Changes Required**:
```
1. Load concrete IPs from network_topology_output.json
2. Apply same strict routing constraints as Steps 3-4
3. Type 1 (unusual port): trusted_admin hosts must exist in topology
4. Type 2 (high volume): Service-based host selection (DNS, etc.)
5. Type 3 (rare duration): Source host must be valid internal/external
6. Risk: Host availability may be tighter; type distribution may need adjustment
```

**Code Changes**:
- Lookup concrete IPs for host selection
- Add explicit validation: `assert host in network_topology_output.json['all_hosts']`
- If host unavailable: Fall back to alternative or skip event (with warning)

**Feasibility Risk**:
- MODERATE (host pool smaller with concrete topology)
- May need to adjust false alarm count (4-5 → 3-4) if hosts become constraining

---

### Step 6: Final Assembly & Validation
**Current Behavior**:
- Combines malicious, benign, false alarm events (30 total)
- Validates timestamps, host validity, subnet consistency
- Writes CSV with 23 columns

**Changes Required**:
```
1. Add network_topology_output.json validation checkpoint
2. For each event: Confirm src_host and dst_host exist in concrete topology
3. Confirm src_subnet and dst_subnet CIDR blocks match network_topology_output.json
4. For cross-subnet events: Ensure routing path is valid per attack_path rule
5. Add new validation: event source IPs must be within correct subnet CIDR
6. Risk: May fail validation if Steps 3-5 generated topology-invalid events
```

**Code Changes**:
- Add validation checkpoint #16 (or extend existing): "Concrete IP validation"
- Check: All src_host/dst_host in network_topology_output.json
- Check: For each event, validate src subnet CIDR ✓ dst subnet CIDR routing
- Report errors vs. warnings (stricter validation)

**Feasibility Risk**:
- HIGH (validation will be stricter)
- If prior steps violated AWS topology, Step 6 will catch and fail
- May need upstream fixes if validation fails

---

## REQUIRED MAIN.PY CHANGES

### Change 1: Configuration File Loading

**Current (Lines ~316-319)**:
```python
global_constraints_path = Path("templates/global_constraints.json")
# VALIDATION
if not global_constraints_path.exists():
    raise FileNotFoundError(f"Global constraints file not found: {global_constraints_path}")
```

**Proposed**:
```python
# Load v2 constraints + AWS topology
global_constraints_path = Path("templates/global_constraints_v2.json")
network_topology_path = Path("templates/network_topology_output.json")

# VALIDATION: Both files must exist
for config_file in [global_constraints_path, network_topology_path]:
    if not config_file.exists():
        raise FileNotFoundError(f"Required config file not found: {config_file}")

# Load with validation
try:
    with open(global_constraints_path, 'r') as f:
        global_constraints = json.load(f)
    with open(network_topology_path, 'r') as f:
        network_topology = json.load(f)
except json.JSONDecodeError as e:
    raise ValueError(f"JSON parse error in config files: {e}")
```

**Impact**:
- main.py now passes TWO config files to downstream steps (not one)
- Steps must update function signatures to accept network_topology parameter

---

### Change 2: Step Function Signatures

**All affected steps** (3, 4, 5, 6) must add network_topology parameter:

**Before**:
```python
step_3_result = step_3.generate_malicious_events_step_3(
    str(output_transformed_csv),
    str(working_templates_path),
    str(global_constraints_path),
    malicious_count_per_scenario=malicious_count_per_scenario,
    random_seed=42
)
```

**After**:
```python
step_3_result = step_3.generate_malicious_events_step_3(
    str(output_transformed_csv),
    str(working_templates_path),
    str(global_constraints_path),
    network_topology=network_topology,  # NEW
    malicious_count_per_scenario=malicious_count_per_scenario,
    random_seed=42
)
```

**Affected Calls**:
- Line ~445: step_2.process_step_2() → add network_topology parameter
- Line ~470: step_3.generate_malicious_events_step_3() → add network_topology parameter
- Line ~495: step_4.generate_benign_events_step_4() → add network_topology parameter
- Line ~515: step_5.generate_false_alarms_step_5() → add network_topology parameter
- Line ~540: step_6.assemble_30_events_step_6() → add network_topology parameter

---

### Change 3: Helper Function Updates

**New helper functions needed** in helper_functions.py:

```python
def load_network_topology(network_topology_json_path):
    """Load and validate network_topology_output.json"""
    
def get_concrete_ip_for_host(hostname, network_topology):
    """
    Returns concrete IP from network_topology_output.json
    Replaces previous MD5-based synthetic IP generation
    """
    
def get_subnet_cidr_for_host(hostname, network_topology):
    """
    Get subnet CIDR block for hostname validation
    E.g., User0 → "10.0.1.0/24"
    """
    
def validate_host_in_topology(hostname, network_topology):
    """
    Confirm hostname exists in concrete topology_output.json
    Raises ValueError if not found
    """
    
def validate_ip_in_subnet(ip_address, subnet_cidr):
    """
    Check if IP belongs to subnet using CIDR validation
    E.g., "10.0.1.15" in "10.0.1.0/24" → True
    """
    
def validate_routing_path(src_host, dst_host, network_topology):
    """
    Enforce routing constraints from network_topology_output.json
    Cross-subnet must follow: User1→Enterprise1→Enterprise2→OpServer0
    """
```

---

## FEASIBILITY IMPACT: EVENT GENERATION CONSTRAINTS

### Current Flexibility (v1)
- **Host Connectivity**: Any internal host can reach any other host
- **Cross-Subnet Paths**: Multiple possible paths (flexible routing)
- **External Hosts**: Minimal constraints on external_* assignments
- **Host Pool Size**: Abstract (theoretically unlimited named hosts)

### AWS-Constrained Flexibility (v2)
- **Host Connectivity**: Strict routing via gateway hosts only
- **Cross-Subnet Paths**: Single defined path (User1→Enterprise1→Enterprise2→OpServer0)
- **External Hosts**: Must be routable via IGW (limited set)
- **Host Pool Size**: Concrete (15 internal + external_XXX external hosts)

### Potential Feasibility Issues

#### Issue 1: Cross-Subnet Attack Path Restrictions
**Problem**: Current code may generate events like:
```
User0 → OpServer0 (direct cross-subnet jump, bypasses gateways)
User3 → Enterprise2 (direct User→Enterprise, not User1)
```

**Solution**:
- Step 3 (malicious events) must enforce: src→dst only if path exists in routing_paths
- For multi-step attacks: validate each link is valid
- Single-event validation: User1 MUST be source for User→*cross-subnet* events

**Risk**: If Step 3 previously generated 10-11 events using flexible paths, AWS constraints may reduce feasible combinations to < 10

#### Issue 2: Host Pool Size
**Current**: Abstract (unlimited named hosts User0-4, Enterprise0-2, Defender, OpHost0-2, OpServer0 = 14 concrete + external_*)  
**New**: Concrete (exactly these 14 + any number of external_* hosts)

**Impact**: MINIMAL (host pool size remains sufficient)

#### Issue 3: Gateway Host Saturation
**Problem**: User1 is the ONLY gateway from User subnet to Enterprise subnet  
**Scenario**: All malicious events that cross User→Enterprise must use User1  
**Risk**: All malicious events same source (User1) may reduce realism

**Solution**: Allow events with src_host ≠ User1 IF they's internal-only or external-originating
- Enforce: Only CROSS-SUBNET events from User→Enterprise must use User1

#### Issue 4: Temporal Phase Compliance with Routing
**Problem**: Phase-based timestamp allocation (Steps 3-6) doesn't account for routing path duration  
**Example**: If attack path is User1→Enterprise1(at 350s)→Enterprise2(at 700s)→OpServer0(at 900s), then each phase must align

**Solution**: Maintain current phase timing (no change needed - AWS routing is instantaneous in network model)

### Feasibility Adjustment Recommendations

1. **Monitor Step 3 output**: If malicious event count drops below 10, adjust host selection logic
2. **Loosen routing for benign traffic**: Step 4 can use any host pair (not just gateways)
3. **Track violations**: Add warning if event fails routing validation (vs. hard error)
4. **Document constraints**: Update zero_day_templates.json with AWS routing assumptions

---

## IMPLEMENTATION CHECKLIST

### Phase 1: Configuration Management (main.py)
- [ ] Line ~316-319: Update global_constraints file path (v2)
- [ ] Line ~316-319: Add network_topology file load
- [ ] Add JSON validation for both files
- [ ] Create helper function: `load_network_topology()`

### Phase 2: Helper Functions (helper_functions.py)
- [ ] `get_concrete_ip_for_host(hostname, network_topology)`
- [ ] `get_subnet_cidr_for_host(hostname, network_topology)`
- [ ] `validate_host_in_topology(hostname, network_topology)`
- [ ] `validate_ip_in_subnet(ip_address, subnet_cidr)`
- [ ] `validate_routing_path(src_host, dst_host, network_topology)`
- [ ] Unit tests for each helper (test_helpers.py)

### Phase 3: Step 2 Updates (step_2.py)
- [ ] Add network_topology parameter to function signature
- [ ] Add validation checkpoint for AWS topology
- [ ] Update summary report to reference network_topology_output.json

### Phase 4: Step 3 Updates (step_3.py)
- [ ] Add network_topology parameter
- [ ] Replace IP generation: MD5 hashing → concrete IP lookup
- [ ] Add strict routing validation for malicious sources
- [ ] Monitor for feasibility issues; log warnings if event count drops

### Phase 5: Step 4 Updates (step_4.py)
- [ ] Add network_topology parameter
- [ ] Replace IP generation: synthetic → concrete IP lookup
- [ ] Update external host selection (validate routing via IGW)
- [ ] Preserve service-port logic (no change needed)

### Phase 6: Step 5 Updates (step_5.py)
- [ ] Add network_topology parameter
- [ ] Replace IP generation: synthetic → concrete IP lookup
- [ ] Validate host availability for false alarm types
- [ ] Add fallback logic if host becomes unavailable

### Phase 7: Step 6 Updates (step_6.py)
- [ ] Add network_topology parameter
- [ ] Add validation checkpoint #16: "Concrete IP + subnet CIDR validation"
- [ ] For each event: confirm src/dst in network_topology_output.json
- [ ] Validate cross-subnet routing paths
- [ ] Add detailed error messages for failed validations

### Phase 8: Testing & Validation
- [ ] Update templates/zero_day_templates.json with AWS assumptions
- [ ] Run full pipeline with v2 constraints + network_topology
- [ ] Verify feasibility: event counts remain 10-11 malicious, 15 benign, 4-5 false alarms
- [ ] Check all validation checkpoints pass
- [ ] Compare output CSVs: should differ from v1 (concrete IPs used)
- [ ] Document any changes to event counts or distributions

### Phase 9: Documentation
- [ ] Update methodology docs with AWS grounding explanation
- [ ] Document routing constraints for attack scenarios
- [ ] Create migration guide: v1 → v2 (for future reference)
- [ ] Add comments in code explaining concrete IP strategy

---

## RISK MITIGATION STRATEGIES

### Risk 1: Event Count Mismatch
**If Step 3 generates < 10 malicious events** (due to routing constraints):
- **Option A**: Relax routing validation (allow single hops for events outside attack path)
- **Option B**: Adjust malicious_count downward (9 events instead of 10-11)
- **Option C**: Add additional internal hosts to network_topology

### Risk 2: High Feasibility Friction
**If tests reveal multiple infeasible event combinations**:
- Create "synthetic gateway hosts" (allow Host1→OpServer0 if marked as such)
- Extend network_topology_output.json with additional enterprise hosts
- Document constraint in zero_day_templates.json (attack relies on internal routes)

### Risk 3: Reproducibility Issues
**If concrete IP assignments lose determinism**:
- Ensure network_topology_output.json is deterministic (hardcoded IPs, not generated)
- Fix random seed (already done in main.py with seed=42)
- Add checksum validation for network_topology file

---

## TESTING STRATEGY

### Unit Tests (New)
```python
# test_network_topology.py
test_load_network_topology()
test_get_concrete_ip_valid_host()
test_get_concrete_ip_invalid_host()
test_validate_ip_in_subnet()
test_validate_routing_path_valid()
test_validate_routing_path_invalid()
```

### Integration Tests
```python
# Run pipeline with v2 + network_topology
test_full_pipeline_with_v2_constraints()
    - Verify all 5 scenarios generate 30-event tables
    - Confirm all events use concrete IPs from network_topology
    - Check subnet assignments match CIDR blocks
    - Validate routing paths for cross-subnet events
    
test_feasibility_comparison_v1_vs_v2()
    - Compare event counts between v1 and v2 outputs
    - Flag any feasibility regressions
    
test_validation_checkpoints_v2()
    - Ensure Step 6 validation passes
    - Confirm AWS routing rules enforced
```

### Regression Tests
```python
test_backward_compatibility()
    - Ensure v1 pipeline still works (fallback mode)
    - Document differences in output
```

---

## MODIFIED ARCHITECTURE DIAGRAM

### Current (v1):
```
main.py
├─→ global_constraints.json (abstract topology)
├─→ step_2.py (filter + tier)
├─→ step_3.py (generate malicious with synthetic IPs)
├─→ step_4.py (generate benign with synthetic IPs)
├─→ step_5.py (generate false alarms with synthetic IPs)
└─→ step_6.py (assemble + validate)
```

### Proposed (v2):
```
main.py
├─→ global_constraints_v2.json (event generation rules)
├─→ network_topology_output.json (AWS infrastructure + concrete IPs)
├─→ step_2.py (filter + tier, + AWS topology validation)
├─→ step_3.py (generate malicious with CONCRETE IPs from topology)
├─→ step_4.py (generate benign with CONCRETE IPs from topology)
├─→ step_5.py (generate false alarms with CONCRETE IPs from topology)
└─→ step_6.py (assemble + validate AGAINST AWS topology strictly)
```

---

## SUMMARY TABLE: Changes by Component

| Component | Current (v1) | Proposed (v2) | Impact |
|-----------|--------------|--------------|--------|
| **Config File** | global_constraints.json | global_constraints_v2.json | File path change in main.py |
| **Topology Source** | global_constraints.json (abstract) | network_topology_output.json (concrete) | New file dependency |
| **IP Generation** | Synthetic MD5-based | Concrete lookup from topology | All steps affected |
| **Host Pool** | Unlimited named hosts | 14 fixed + external_* | More restrictive |
| **Routing** | Flexible multi-path | Strict single path (gateways) | Steps 3,5 may fail feasibility |
| **Validation** | Semantic checks | AWS topology checks | Step 6 stricter |
| **Step 2** | Filter UNSW | Filter + AWS validation | +1 checkpoint |
| **Step 3** | Generate malicious | Generate + AWS route validation | Feasibility risk |
| **Step 4** | Generate benign | Generate + AWS route validation | Low risk |
| **Step 5** | Generate false alarms | Generate + AWS host validation | Moderate risk |
| **Step 6** | Assemble + validate | Assemble + AWS strict validation | +1 critical checkpoint |

---

## NEXT STEPS

1. **Review this document** with team; confirm direction aligns with experimental goals
2. **Create branch**: `feature/aws-topology-v2` for development
3. **Implement Phase 1-2**: Configuration management + helper functions
4. **Test Phase 3-7**: Update steps individually; test after each
5. **Integration testing**: Full pipeline with v2 + network_topology
6. **Document feasibility findings**: If event counts change, update constraints
7. **Merge to main** once all tests pass and feasibility validated
8. **Update project README**: References to new config files

---

## APPENDIX: File Dependencies

### Files to Modify
- `main.py` (Lines ~316-540)
- `helper_functions.py` (Add 5 new functions)
- `step_2.py` (Add network_topology param + validation)
- `step_3.py` (Replace IP generation; add route validation)
- `step_4.py` (Replace IP generation; handle external hosts)
- `step_5.py` (Replace IP generation; add fallback logic)
- `step_6.py` (Add AWS topology validation checkpoint)

### Files to Create
- `templates/global_constraints_v2.json` (exists - no action needed)
- `templates/network_topology_output.json` (exists - no action needed)
- `test_network_topology.py` (new unit tests)

### Files to Keep (No Change)
- `templates/zero_day_templates.json`
- `templates/dataset_mapping.json`
- `templates/global_constraints.json` (deprecated but kept for reference)
- `pre_step.py` (no topology changes needed)
- `step_1.py` (no topology changes needed)

---

## Conclusion

Integrating AWS topology into the pipeline is **feasible but requires careful coordination** across 6 Python modules (main.py + 5 steps). The **key risks are feasibility constraints** on event generation (particularly Step 3 malicious events due to strict routing). 

**Estimated effort**: 20-30 hours (implementation + testing + documentation)  
**Estimated risk**: MODERATE (requires careful validation; tight routing may affect event realism)  
**Estimated benefit**: HIGH (concrete infrastructure grounding; reproducibility; compatibility with AWS-based downstream tools)

