# Heuristic IDS Model - User Guide

## Overview

This guide explains how to use the **Heuristic IDS Model** system, which detects network anomalies and topology violations without knowledge of attack ground truth. The system is designed for **transparent, rule-based anomaly detection** where humans can review model outputs and provide feedback.

---

## Prerequisites: Data Preparation

Before running the heuristic model, you must prepare the input data by removing ground truth labels. This ensures the model is truly **blind to ground truth** during anomaly detection.

### Step 0: Data Preparation

**Prerequisite:** Start with raw network flow dataset with ground truth labels.

**Goal:** Remove ground truth labels to ensure the model operates completely blind to attack types.

**Process:**
1. Generate IDS tables from the dataset
2. Remove all ground truth/attack labels from tables
3. Verify that only network flow features remain (source/destination IPs, ports, service types, bytes, duration, etc.)

**Critical:** The model must NOT have access to any ground truth information at this stage. This ensures unbiased anomaly detection.

---

## Workflow Steps

**Step 0: Data Preparation**  
Remove ground truth labels. Model must be blind to attack types.

**Step 1: Generate Predictions**  
Run anomaly detection on clean data. Output: `prediction`, `confidence`, `reason`.

**Step 2: Create Feedback Template**  
Generate empty feedback form for each prediction file.

**Step 3: Collect Expert Feedback** (Optional)  
Experts fill in: `human_feedback` ("malicious"/"not malicious"), `human_confidence` (0.0-1.0), `human_explanation` (optional).

**Step 4: Apply Feedback**  
Merge feedback into predictions. Outputs: `confidence_adjusted`, `confidence_gap`, `adjustment_reason`, `rule_override_count`.  
**Key:** `prediction` column NEVER changes; only `confidence_adjusted` varies.



## Definitions

**"Malicious"** = Anomalous behavior deviating from normal patterns (topology violations, unusual ports/volumes, rare durations). NOT based on attack signatures or ground truth.

**"Not Malicious"** = Normal traffic matching expected patterns (standard ports, expected behaviors, intra-subnet).

## Anomaly Detection Rules

Each rule evaluates network flows and assigns `prediction` and `confidence`:

| Rule | Trigger Condition | Output `confidence` |
|------|-------------------|---------------------|
| **Unusual Port** | `dport ≥ 10000` AND `service` ∈ {http, dns, smtp, ssh} | 0.75 |
| **High Volume** | `service` ∈ {dns, smtp} AND `bytes > 100KB` | 0.70 |
| **Rare Duration** | `service` = ssh AND (`duration < 0.1s` OR `duration > 1.0s`) | 0.65 |
| **Topology Violation** | Cross-subnet communication violates network policy | 0.85 |

**Outputs if rule triggers:**
- `prediction` = "malicious"
- `confidence` = value from table
- `reason` = rule explanation

## Confidence Adjustment Rules

**Key:** `confidence_adjusted` = adjusted confidence. `prediction` never changes.

**When `human_feedback == prediction` (Agreement):**

| Human `human_confidence` | Formula | Result |
|--------------------------|---------|--------|
| ≥ 0.85 | `min(confidence + 0.10, 0.95)` | Boosted |
| 0.70–0.84 | `confidence` | Unchanged |
| < 0.70 | `confidence + 0.05` | Slight boost |

**When `human_feedback ≠ prediction` (Disagreement):**

Let `gap = |confidence - human_confidence|`

| Human `human_confidence` | Tier | Penalty Formula | Result |
|--------------------------|------|-----------------|--------|
| ≥ 0.80 | Strong | `max((1.0-conf)×0.50 + gap×0.20, 0.30)` | Significant reduction |
| 0.70–0.79 | Moderate | `max((1.0-conf)×0.35 + gap×0.15, 0.30)` | Moderate reduction |
| 0.55–0.69 | Weak | `max((1.0-conf)×0.25 + gap×0.10, 0.30)` | Slight reduction |
| < 0.55 | Very Weak | `max(confidence - 0.05, 0.30)` | Minimal change |

**Defaults:** `confidence_gap` = gap, `adjustment_reason` = explanation of tier and formula applied.

## Output Columns

| Column | Source | Description |
|--------|--------|-------------|
| `prediction` | Model | Original (never flips) |
| `confidence` | Model | Original confidence |
| `reason` | Model | Which rule triggered |
| `human_feedback` | Expert | Assessment if reviewed |
| `human_confidence` | Expert | Expert's confidence |
| `human_explanation` | Expert | Optional notes |
| `confidence_adjusted` | System | After human feedback |
| `confidence_gap` | System | \|confidence - human_confidence\| |
| `adjustment_reason` | System | Tier and formula applied |
| `rule_override_count` | System | How many times rule questioned |

## Interpretation Examples

| Scenario | Observation | Implication |
|----------|-------------|-------------|
| `confidence=0.85` + no feedback | Rule unreviewed | Validate with expert |
| `confidence=0.75`, `human_confidence=0.88`, same prediction | Strong agreement | Rule reliable |
| `confidence=0.85`, `human_confidence=0.82`, opposite prediction | Strong disagreement → `confidence_adjusted=0.30` | Rule may be too strict |
| `confidence=0.60`, `human_confidence=0.70`, opposite prediction | Both uncertain → `confidence_adjusted=0.30` | Insufficient signal |
| Many rows with `confidence_adjusted` at 0.30 floor | Consistent expert pushback | Verify rule thresholds |

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| No anomalies detected | Thresholds too strict | Loosen rule thresholds |
| Too many false positives | Thresholds too loose | Tighten rule thresholds |
| Topology violations undetected | Network policy mismatch | Verify topology rules |
| `prediction` unchanged despite feedback | Design (predictions never flip) | Check `confidence_adjusted` column |
| No `confidence_adjusted` change | No feedback provided or all agree | Verify feedback data loaded |
| All rows at floor (0.30) | Consistent strong disagreement | Verify feedback accuracy |


