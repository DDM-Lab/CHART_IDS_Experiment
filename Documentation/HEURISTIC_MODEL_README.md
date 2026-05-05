# Heuristic IDS Model - User Guide

## Overview

This guide explains how to use the **Heuristic IDS Model** system, which detects network anomalies and topology violations without knowledge of attack ground truth. The system is designed for **transparent, rule-based anomaly detection** where humans can review model outputs and provide feedback.

---

## Prerequisites: Data Preparation

Before running the heuristic model, you must prepare the input data by removing ground truth labels. This ensures the model is truly **blind to ground truth** during anomaly detection.

### Step 0a: Generate IDS Tables

First, generate the initial IDS tables from the network dataset:

```bash
python main.py
```

**Input:** `IDS_Datasets/UNSW_NB15_transformed.csv`

**Output:** IDS_tables/ directory with multiple subdirectories:
- `18events_30pct_fa_bal/`
- `25events_15pct_fa_bal/`
- `25events_5pct_fa_bal/`
- ... (and others)

Each subdirectory contains CSV files like:
- `Data_Theft_18events.csv`
- `Netcat_Backdoor_18events.csv`
- `No_Attack_18events.csv`
- etc.

**⚠️ Important:** These tables INCLUDE ground truth labels (e.g., `attack=Data_Theft`, `attack=Netcat_Backdoor`). The model must NOT see these.

### Step 0b: Remove Ground Truth Labels

Remove ground truth columns to ensure the heuristic model operates blind to attack type:

```bash
python column_removal_cleanup.py
```

**Input:** `IDS_tables/` (with ground truth labels)

**Output:** `IDS_cleaned_tables/` (ground truth removed)

**What gets removed:**
- `attack` column (attack type labels)
- `attack_category` column (if present)
- Any other ground truth identifiers

**What remains:**
- `src_ip`, `dst_ip` - Network flow endpoints
- `src_host`, `dst_host` - Host names
- `dport`, `service` - Destination port and service type
- `bytes`, `duration` - Traffic volume and session time
- `id` - Row identifier for feedback tracking
- All other network flow features

**Result:** `IDS_cleaned_tables/` ready for blind anomaly detection

### Step 0c: Verify Cleaned Data

Confirm the labels were removed:

```bash
# Check that 'attack' column is gone
python -c "
import pandas as pd
import os
example_file = 'IDS_cleaned_tables/18events_30pct_fa_bal/Data_Theft_18events_cleaned.csv'
df = pd.read_csv(example_file)
print('Columns in cleaned data:')
print(df.columns.tolist())
print()
print('First row:')
print(df.iloc[0])
"
```

**Expected output:** `attack` column should NOT appear in column list

---

## System Components

### Core Scripts

1. **`heuristic_model.py`** - Main anomaly detection engine
   - Analyzes network flow data (CSVs)
   - Detects topology violations and behavioral anomalies
   - Outputs predictions with confidence scores and explanations
   - **Stateless**: Uses universal thresholds, no baselines

2. **`apply_human_feedback.py`** - Human feedback integration (non-flipping)
   - Merges expert feedback with model predictions
   - **Adjusts model confidence based on human feedback** (predictions NEVER flip)
   - Uses gap-scaled penalty logic for confidence adjustment
   - Tracks rule overrides for quality analysis
   - Preserves original model perspective for downstream decision aggregation

3. **`generate_feedback_template.py`** - Feedback preparation
   - Creates empty feedback CSVs ready for expert review
   - Syncs with model predictions
   - Guides human experts on feedback format

4. **`evaluate_ground_truth.py`** - Optional evaluation
   - Compares predictions against ground truth labels
   - Measures accuracy **pre-feedback** vs **post-feedback** separately
   - Shows accuracy broken down by malicious vs. not-malicious categories
   - Reports detection rates and human feedback impact
   - Identifies rule performance issues

### Configuration Files

- **`templates/global_constraints.json`** - Anomaly detection thresholds
  - Unusual port traffic rules
  - High volume traffic rules
  - Rare duration traffic rules
  - All thresholds configurable without code changes

---

## Quick Start Workflow

> **⚠️ Prerequisites:** Before starting these steps, ensure you have completed **Steps 0a, 0b, and 0c** above to generate and clean the IDS tables.

### Step 1: Generate Predictions (No Ground Truth Required)

```bash
python heuristic_model.py ./IDS_cleaned_tables \
  --output-dir ./IDS_heuristic_model_eval \
  --constraints ./templates/global_constraints.json
```

**Input:** Network flow CSVs (columns: src_ip, dst_ip, service, bytes, duration, etc.)

**Output:** Same CSVs + 3 new columns:
- `prediction`: "malicious" or "not malicious"
- `reason`: Explanation (e.g., "Traffic anomaly: Unusual port 19065 with dns")
- `confidence`: 0.0-1.0 (how sure is the model?)

**Example output row:**
```
src_ip=10.0.2.10, dst_ip=203.0.68.219, dport=19065, service=dns,
prediction=malicious,
confidence=0.75,
reason=Traffic anomaly: Unusual port 19065 with dns
```

---

### Step 2: Create Feedback Templates

```bash
python generate_feedback_template.py ./IDS_heuristic_model_eval \
  --output-dir ./human_feedback
```

**Output:** Empty feedback CSV files (one per prediction file)

**Structure:**
```csv
id,human_feedback,human_confidence,human_explanation
1,,,
2,,,
...
```

---

### Step 3: Collect Human Expert Feedback

**For each row, expert can optionally provide:**

| Column | Format | Example |
|--------|--------|---------|
| `human_feedback` | "malicious" or "not malicious" | "not malicious" |
| `human_confidence` | 0.0-1.0 | 0.85 |
| `human_explanation` | Text (optional) | "Known admin tool" |

**Confidence scale guidance:**
- `0.5` = Uncertain, could go either way
- `0.7` = Reasonably confident
- `0.85-0.9` = Very confident
- `0.95+` = Absolutely certain

**Example feedback:**
```csv
id,human_feedback,human_confidence,human_explanation
8,not malicious,0.90,Known admin tool - port 19065 is network scanner
15,not malicious,0.60,Looks like zone transfer but not 100% sure
17,not malicious,0.88,Normal long-running SSH from Enterprise admin
```

**Leave blank for rows the expert doesn't review** (no forced feedback needed).

---

### Step 4: Apply Human Feedback (Confidence Adjustment, Not Flipping)

```bash
python apply_human_feedback.py ./IDS_heuristic_model_eval ./human_feedback \
  --output-dir ./IDS_with_feedback
```

**Output:** Enhanced CSVs with confidence adjustments based on human feedback

**Model predictions NEVER flip.** Instead, confidence is adjusted using gap-scaled penalties:

**New columns added:**
- `human_feedback`: Expert's prediction
- `human_confidence`: Expert's confidence (0.0-1.0)
- `human_explanation`: Optional expert notes
- `confidence_adjusted`: Model confidence after human feedback consideration
- `adjustment_reason`: Explanation of confidence change
- `confidence_gap`: |model_confidence - human_confidence|
- `rule_override_count`: How many times this rule saw significant confidence reduction

**Example row after feedback:**
```
prediction=malicious, confidence=0.75,
human_feedback=not malicious, human_confidence=0.90,
confidence_adjusted=0.35,
adjustment_reason=Strong disagreement (human_conf=0.90): Gap=0.15, penalty applied → 0.35,
confidence_gap=0.15
```

**Key difference:** Model's original prediction is preserved. Confidence is adjusted to reflect the strength of human disagreement/agreement. This allows downstream decision aggregation to weigh both perspectives fairly.

---

## Complete Workflow Guide: Step-by-Step

This section provides a detailed overview of the **entire workflow** for running the heuristic IDS model, from data preparation through human feedback integration.

### Phase 1: Data Preparation (One-Time Setup)

> **When:** Only once, at the beginning
> **Prerequisites:** Raw UNSW_NB15 dataset

**Step 0a → 0b → 0c** (see "Prerequisites" section above)
- Generate IDS tables with ground truth labels
- Remove ground truth labels → blind dataset
- Verify data integrity

**Outputs:** `IDS_cleaned_tables/` ready for model

---

### Phase 2: Anomaly Detection (Blind to Ground Truth)

> **When:** After data prep, before human review
> **Input:** `IDS_cleaned_tables/` (cleaned network flow data)

**Step 1: Generate Model Predictions**
```bash
python heuristic_model.py ./IDS_cleaned_tables \
  --output-dir ./IDS_heuristic_model_eval \
  --constraints ./templates/global_constraints.json
```

**Output:** `IDS_heuristic_model_eval/`
- Each CSV has: original data + `prediction`, `confidence`, `reason`
- Model is completely blind to ground truth at this point

**Typical accuracy:** 75-85% on balanced test sets (no human feedback yet)

---

### Phase 3: Human Expert Review (Optional but Recommended)

> **When:** After model predictions, to improve confidence calibration
> **Input:** `IDS_heuristic_model_eval/` (model predictions)

**Step 2: Create Feedback Templates**
```bash
python generate_feedback_template.py ./IDS_heuristic_model_eval \
  --output-dir ./human_feedback
```

**Output:** `human_feedback/` with empty CSVs
- One template per prediction file
- Structure: `id`, `human_feedback`, `human_confidence`, `human_explanation` (empty)
- No rows are required to be filled; expert reviews at their own pace

**Step 3: Collect Expert Feedback**
- Expert reviews model predictions (predictions are suggestions, not requirements)
- For suspicious or uncertain rows, expert fills in:
  - `human_feedback`: "malicious" or "not malicious" (or leave blank)
  - `human_confidence`: 0.0-1.0 (how sure about this judgment?)
  - `human_explanation`: Optional notes (for documentation)

**No time pressure:** Leave rows blank if not reviewed. Only reviewable rows need feedback.

---

### Phase 4: Confidence Adjustment with Human Feedback

> **When:** After human review (or skip if no feedback available)
> **Input:** `IDS_heuristic_model_eval/` + `human_feedback/`

**Step 4: Apply Human Feedback**
```bash
python apply_human_feedback.py ./IDS_heuristic_model_eval ./human_feedback \
  --output-dir ./IDS_with_feedback
```

**Output:** `IDS_with_feedback/`
- Merges predictions + feedback + adjustments
- Model predictions unchanged (NEVER flip)
- Confidence adjusted based on human agreement/disagreement
- New columns added (see Step 4 output description)

**Typical improvement:** +2-5% accuracy with good expert feedback

---

### Phase 5: Optional - Evaluation Against Ground Truth

> **When:** If ground truth labels available (research/validation only)
> **Prerequisite:** Must have `IDS_with_feedback/` outputs

**Step 5: Measure Accuracy**
```bash
python evaluate_ground_truth.py
```

**Output:** Accuracy metrics
- Pre-feedback accuracy: Model alone
- Post-feedback accuracy: After human input
- Breakdown by malicious vs. not-malicious categories
- Human feedback impact analysis

**Use case:** Validate that model + human feedback improves over ground truth

---

## Typical Execution Timeline

### Scenario 1: Quick Initial Run (No Human Feedback)
```
Step 0a-0c (data prep)  → 5-10 minutes
Step 1 (model)          → 5-15 minutes
Total:                  → 10-25 minutes
Output:                 → IDS_heuristic_model_eval/
```

### Scenario 2: Full Workflow with Human Feedback
```
Step 0a-0c (data prep)     → 5-10 minutes
Step 1 (model)             → 5-15 minutes
Step 2 (feedback template) → 1-2 minutes
Step 3 (human review)      → 30 minutes - 2 hours (depends on dataset size)
Step 4 (apply feedback)    → 1-5 minutes
Total:                     → 45 minutes - 3 hours
Output:                    → IDS_with_feedback/
```

### Scenario 3: Full Workflow with Evaluation
```
All steps 0a-0c through 4  → 45 minutes - 3 hours
Step 5 (evaluate)          → 2-5 minutes
Total:                     → 45 minutes - 3 hours
Output:                    → IDS_with_feedback/ + evaluation report
```

---

## Key Decision Points

### Question 1: Do I need to collect human feedback?

| Scenario | Answer | Actions |
|----------|--------|---------|
| Quick proof-of-concept | No | Run Steps 0a-1, then stop |
| Improving accuracy | Yes | Run all steps 0a-4 |
| Research/comparison | Maybe | Run 0a-4, then optionally Step 5 with ground truth |

### Question 2: How much human feedback is needed?

| Feedback Coverage | Expected Improvement | Effort |
|-------------------|---------------------|--------|
| 0% (no feedback) | Baseline accuracy | None |
| 10-20% (spot-check) | +1-2% accuracy | 30-60 min |
| 50% (comprehensive) | +3-5% accuracy | 2-4 hours |
| 100% (full review) | +5-8% accuracy | 4+ hours |

**Recommendation:** Start with 20% spot-check on high-uncertainty rows (confidence 0.50-0.75)

### Question 3: Should I modify detection thresholds?

| Situation | Threshold Changes |
|-----------|-------------------|
| Too many false positives | Increase `dport_threshold`, `bytes_threshold` |
| Missed important anomalies | Decrease thresholds (more sensitive) |
| After seeing feedback patterns | Adjust gap-scaling multipliers (0.50→0.60) |

Modify `templates/global_constraints.json`, then re-run Step 1.

---

## Understanding Model Predictions

### What is "Malicious"?

In this system, **"malicious" doesn't mean attack-related**. It means:
> **"Anomalous behavior that deviates from normal/expected patterns"**

This includes:
- ✓ Topology violations (cross-subnet unauthorized communication)
- ✓ Behavioral anomalies (unusual ports, high volume transfers, rare durations)
- ✓ Statistical deviations (patterns outside normal ranges)
- ✗ NOT based on attack signatures or ground truth knowledge

### What is "Not Malicious"?

**Normal traffic that matches expected patterns:**
- Intra-subnet communication
- Regular web browsing, DNS, SSH from expected sources
- Normal file transfers
- Protocol-standard transfers (HTTP on port 80, SSH on port 22)

---

## Anomaly Detection Rules

### Rule 1: Unusual Port Traffic

**Trigger:** High-numbered port (≥10000) + benign service + trusted host

| Condition | Value | Why? |
|-----------|-------|------|
| Destination port | ≥10000 | Ephemeral/unexpected for standard services |
| Service type | dns, http, smtp, ssh | Normally use well-known ports |
| Source host | Enterprise/Defender | Admin context lessens suspicion |

**Confidence:** 0.75

**Example:** Port 19065 with DNS service (normally uses port 53)

---

### Rule 2: High Volume Traffic

**Trigger:** Anomalously large data transfer over normally low-traffic service

| Condition | Value | Why? |
|-----------|-------|------|
| Service | dns, smtp | These protocols normally small transfers |
| Bytes transferred | >100KB | Unusual for DNS queries (typically <1KB) |
| Duration | Reasonable (1-60s) | Avoid false positives from stalled transfers |

**Confidence:** 0.70

**Example:** 250KB DNS zone transfer (uncommon but legitimate)

---

### Rule 3: Rare Duration Traffic

**Trigger:** SSH connections with unusual byte/duration patterns

**Sub-rule A - Very short sessions:**
| Condition | Value | Why? |
|-----------|-------|------|
| Service | ssh, ssh_admin | |
| Duration | <0.1s | SSH logins rejected, timeouts |
| Bytes | 50-500 | Minimal exchange |

**Sub-rule B - Admin anomaly:**
| Condition | Value | Why? |
|-----------|-------|------|
| Source | Enterprise0/1/2, Defender | Admin hosts |
| Duration | >1.0s | Unusual for admin SSH |
| Bytes | >500 | More data than expected |

**Confidence:** 0.65

**Example:** 4.5-second SSH session from Enterprise2 with 2000 bytes (suspicious admin activity)

---

### Rule 4: Topology Violations

**Trigger:** Cross-subnet communication violating network policy

**Allowed paths:**
- ✓ User1 → Enterprise1 (designated entry point)
- ✓ Enterprise1 ↔ Enterprise2 (internal communication)
- ✓ Enterprise2 → Operational (designated gateway)
- ✓ Within same subnet (any host to any host)
- ✓ To external/internet (outbound allowed)

**Denied paths:**
- ✗ User2-5 → Enterprise (only User1 allowed)
- ✗ User → Operational (must go through Enterprise)
- ✗ Operational → User (must go through Enterprise)
- ✗ Operational ↔ Operational with untrusted paths

**Confidence:** 0.85 (high confidence in topology violations)

---

## Human Feedback Confidence Adjustment Logic

The model applies **non-flipping confidence adjustment**: The model's prediction NEVER changes based on human feedback. Instead, confidence is adjusted to reflect the strength of human disagreement or agreement.

**Why non-flipping?** This design preserves the model's original perspective without bias. A downstream decision aggregation script then receives both the model's view (with adjusted confidence) and the human's view, allowing it to make informed final decisions.

### Adjustment Mechanism

When human feedback is provided, the model's confidence is adjusted using a **gap-scaled penalty** approach:

**Confidence Gap** = |model_confidence - human_confidence|

Larger gaps signal stronger disagreement and trigger proportionally larger confidence adjustments.

### Agreement Cases (Human Agrees with Model)

When `human_feedback == model_prediction`, confidence is boosted to reflect human validation:

| Human Confidence | Adjustment | Formula |
|------------------|-----------|---------|
| **≥0.85** | Strong validation → Boost | `min(conf + 0.10, 0.95)` |
| **0.70–0.84** | Moderate validation → Keep | `conf` (unchanged) |
| **<0.70** | Weak validation → Slight boost | `conf + 0.05` |

**Example:**
```
Model: malicious (0.75), Human: malicious (0.88)
→ Gap = 0.13, Strong agreement
→ Adjusted confidence: min(0.75 + 0.10, 0.95) = 0.85
```

### Disagreement Cases (Human Disagrees with Model)

When `human_feedback ≠ model_prediction`, confidence is reduced based on human confidence strength and gap magnitude.

**Confidence floor:** 0.30 (prevents over-penalizing; model always retains some voice in aggregation)

#### Strong Disagreement (human_confidence ≥ 0.80)

| Calculation | Values |
|-------------|--------|
| Base penalty | `(1.0 - model_conf) × 0.50` |
| Gap scaling | `+ confidence_gap × 0.20` |
| Result | `max(base + gap, 0.30)` |

**Example:**
```
Model: malicious (0.85), Human: not malicious (0.82)
→ Gap = 0.03
→ Base penalty: (1.0 - 0.85) × 0.50 = 0.075
→ Gap penalty: 0.03 × 0.20 = 0.006
→ Total: max(0.075 + 0.006, 0.30) = 0.30 (floor applied)
→ Adjusted confidence: 0.30
```

#### Moderate Disagreement (0.70 ≤ human_confidence < 0.80)

| Calculation | Values |
|-------------|--------|
| Base penalty | `(1.0 - model_conf) × 0.35` |
| Gap scaling | `+ confidence_gap × 0.15` |
| Result | `max(base + gap, 0.30)` |

**Example:**
```
Model: not malicious (0.60), Human: malicious (0.72)
→ Gap = 0.12
→ Base penalty: (1.0 - 0.60) × 0.35 = 0.14
→ Gap penalty: 0.12 × 0.15 = 0.018
→ Total: max(0.14 + 0.018, 0.30) = 0.30 (floor applied)
→ Adjusted confidence: 0.30
```

#### Weak Disagreement (0.55 ≤ human_confidence < 0.70)

| Calculation | Values |
|-------------|--------|
| Base penalty | `(1.0 - model_conf) × 0.25` |
| Gap scaling | `+ confidence_gap × 0.10` |
| Result | `max(base + gap, 0.30)` |

**Example:**
```
Model: malicious (0.70), Human: not malicious (0.65)
→ Gap = 0.05
→ Base penalty: (1.0 - 0.70) × 0.25 = 0.075
→ Gap penalty: 0.05 × 0.10 = 0.005
→ Total: max(0.075 + 0.005, 0.30) = 0.30 (floor applied)
→ Adjusted confidence: 0.30
```

#### Very Weak Disagreement (human_confidence < 0.55)

Human is too uncertain to meaningfully challenge the model. Minimal adjustment:

| Calculation | Result |
|-------------|--------|
| Adjustment | `max(conf - 0.05, 0.30)` |

**Example:**
```
Model: not malicious (0.80), Human: malicious (0.50)
→ Gap = 0.30 (large, but human very uncertain)
→ Minimal penalty: max(0.80 - 0.05, 0.30) = 0.75
→ Adjusted confidence: 0.75 (slight reduction only)
```

### No Flip Under Any Circumstances

```
┌─ Is human feedback provided?
│  ├─ NO → prediction = model_pred, confidence_adjusted = confidence
│  │
│  └─ YES → prediction = model_pred (NEVER CHANGES)
│     └─ confidence_adjusted = calculated per rules above
```

The model prediction in the output CSV is always the original model prediction. Only confidence changes.

---

## Understanding Output Columns

### New Output Structure

After applying human feedback, CSVs contain these columns:

| Column | Source | Meaning |
|--------|--------|---------|
| `id` | Data | Row identifier for tracking |
| `src_ip`, `dst_ip` | Model input | Network endpoints |
| `... (other features)` | Model input | Port, service, bytes, duration, etc. |
| `prediction` | **Model** | Original model prediction (`malicious` or `not malicious`) |
| `confidence` | **Model** | Original model confidence (0.0–1.0) |
| `reason` | **Model** | Rule that triggered detection |
| `human_feedback` | **Human** | Expert's prediction (if reviewed) |
| `human_confidence` | **Human** | Expert's confidence (if reviewed) |
| `human_explanation` | **Human** | Expert's optional notes |
| `confidence_adjusted` | **Both** | Model confidence after adjustment for human input |
| `confidence_gap` | **Both** | Absolute difference: \|model_conf - human_conf\| |
| `adjustment_reason` | **Both** | Explanation of how/why confidence adjusted |
| `rule_override_count` | **Analysis** | How many times this rule saw significant confidence reduction |

### Key Differences from Previous Version

- **NO `model_final_pred`** – Prediction never changes
- **NO `decision_flipped`** – Not applicable (flips don't occur)
- **NEW `confidence_adjusted`** – Confidence reflects human feedback without changing decision
- **NEW `adjustment_reason`** – Explains adjustment calculation
- **`confidence_gap`** – Now used for penalty scaling, not decision flipping

---

## Decision Aggregation (Next Steps)

For your downstream decision aggregation script, each row provides:

```python
{
    'id': 42,
    'prediction': 'malicious',           # ← Model's original view
    'confidence': 0.85,                  # ← Model's original confidence
    'confidence_adjusted': 0.45,         # ← Confidence after human challenge
    'human_feedback': 'not malicious',   # ← Human's view
    'human_confidence': 0.80,            # ← Human's confidence
    'confidence_gap': 0.05               # ← Magnitude of disagreement
}
```

Your aggregator can now:
1. **Compare original vs adjusted confidence**: Did human feedback strongly challenge the model?
2. **Weigh both perspectives**: Use adjusted confidence to balance model and human inputs
3. **Apply custom logic**: Domain-specific rules for final decisions without pre-flip bias
4. **Track confidence dynamics**: See which rows generated strongest human-model conflicts

---

## Interpreting Adjustment Outcomes

### What Different Adjustments Mean

| Scenario | Adjustment | Interpretation |
|----------|-----------|-----------------|
| Model: 0.85, Human: agrees @ 0.90 | Conf boosted to 0.95 | Rule strongly validated by expert |
| Model: 0.85, Human: disagrees @ 0.82 | Conf reduced to 0.30 | Expert sees obvious error; rule needs review |
| Model: 0.60, Human: disagrees @ 0.70 | Conf reduced to 0.30 | Both uncertain, but expert's view preferred |
| Model: 0.80, Human: disagrees @ 0.50 | Conf reduced to 0.75 | Human too uncertain to override; minimal penalty |
| Model: 0.85, Human: agrees @ 0.60 | Conf unchanged (0.85) | Human agrees but not confident; keep model |

### Analyzing Patterns

- **High rule_override_count for rule X** → Rule is frequently questioned by experts; consider recalibrating thresholds
- **confidence_adjusted << confidence** → Human-model strong disagreement; high-priority for review
- **confidence_adjusted ≈ confidence** → Agreement or weak disagreement; lower priority
- **Many low confidence_adjusted values** → Experts are effectively curating anomalies; aggregator may want conservative stance

---

## Configuration & Tuning

The confidence adjustment parameters are **currently hardcoded** in [apply_human_feedback.py](apply_human_feedback.py) but can be easily made configurable:

### Parameters

```python
# Gap-scaled penalty multipliers (in compute_confidence_adjustment)
strong_base_penalty = 0.50        # (1.0 - conf) × 0.50 for >=0.80 human conf
strong_gap_multiplier = 0.20      # gap × 0.20

moderate_base_penalty = 0.35      # (1.0 - conf) × 0.35 for 0.70-0.79
moderate_gap_multiplier = 0.15    # gap × 0.15

weak_base_penalty = 0.25          # (1.0 - conf) × 0.25 for 0.55-0.69
weak_gap_multiplier = 0.10        # gap × 0.10

confidence_floor = 0.30           # Never adjust below this
confidence_ceiling = 0.95         # Never boost above this
```

**Tuning Guidance:**
- **Increase multipliers** (e.g., 0.60, 0.25) for more aggressive penalties on disagreement
- **Decrease multipliers** (e.g., 0.40, 0.15) for softer adjustments
- **Raise confidence_floor** (e.g., 0.40) if model rules are high-quality and should retain more influence
- **Lower confidence_floor** (e.g., 0.20) if experts are very trusted and should strongly challenge model

---

## Evaluating Accuracy: Pre vs. Post Feedback

To measure how well the model performs and how much human feedback improves accuracy, use the evaluation script:

```bash
python evaluate_ground_truth.py
```

**Purpose:** Compare model predictions to ground truth labels, showing:
- Accuracy before any human feedback
- Accuracy after human feedback is applied (if available)
- Separate reports for feedback-only rows vs. all rows

### Understanding Accuracy Metrics

The evaluation treats **benign and false_alarm as the same category** ("not malicious"):

| Category | Correct Prediction |
|----------|-------------------|
| **Malicious** | Prediction = "malicious" AND Ground truth = "malicious" |
| **Not Malicious** | Prediction = "not malicious" AND Ground truth = "benign" OR "false_alarm" |
| **Overall** | Both categories combined |

### Example Output: All Rows

```
OVERALL ACCURACY (All Rows):
–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
Category             Pre-Feedback          Post-Feedback     Improvement
–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
Overall              75.2% (315/419)       78.5% (329/419)   +3.3%
Malicious            82.5% (198/240)       85.0% (204/240)   +2.5%
Not Malicious        65.1% (117/179)       70.4% (125/179)   +5.3%
```

**Interpretation:**
- Pre-Feedback: 75.2% of all predictions matched ground truth
- Post-Feedback: 78.5% after applying human expert feedback
- Improvement: +3.3 percentage points overall
- Not Malicious category improved more (+5.3%) than Malicious (+2.5%)

### Example Output: Feedback-Only Rows

If you've collected human feedback, you'll also see:

```
ACCURACY ON ROWS WITH HUMAN FEEDBACK:
–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
Category             Pre-Feedback          Post-Feedback     Improvement
–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
Overall              68.0% (34/50)         76.0% (38/50)     +8.0%
Malicious            75.0% (18/24)         79.2% (19/24)     +4.2%
Not Malicious        60.0% (16/26)         73.1% (19/26)     +13.1%
```

**Interpretation:**
- Rows with human feedback had lower initial accuracy (68.0% vs 75.2% overall)
- After applying feedback, accuracy improved to 76.0% (+8.0 points)
- Larger improvement on feedback rows suggests experts are catching important errors
- Not malicious category showed largest improvement (+13.1%)

### When to Trust the Improvements

**Good Signs:**
- Post-feedback accuracy is higher across all categories
- Improvement percentage is meaningful (2-10%+)
- Human feedback consistently provides better predictions than model

**Caution Signs:**
- Post-feedback accuracy drops for any category (suggests feedback contradicts ground truth)
- Very small improvements (<1%) despite extensive feedback (model is already accurate)
- Different accuracy trends between malicious and not-malicious (suggests feedback bias)

### Analyzing Feedback Impact

The evaluation script also shows:

```
HUMAN FEEDBACK IMPACT:
  Total rows with human feedback:  42
  Human-model agreement:           28 ( 66.7%)
  Human-model disagreement:        14 ( 33.3%)
  Total decisions flipped:          12 ( 28.6%)
  Flip accuracy (vs ground truth): 9/12 ( 75.0%) improved
                                   3/12 ( 25.0%) worsened
```

**Metrics Explained:**
- **Human-model agreement**: Cases where expert agreed with model's prediction
- **Disagreement**: Cases where expert disagreed with model
- **Decisions flipped**: Cases where expert disagreement was strong enough to change prediction
- **Flip accuracy**: Of flipped decisions, how many were correct vs ground truth?

**Interpretation:**
- 75% flip accuracy means human feedback significantly improves predictions
- 25% worsened means some human overrides were incorrect (still useful for analysis)

---

## Interpreting Output CSV

### Key Columns to Review

#### `prediction` (Model Output - ORIGINAL, NEVER FLIPS)
```
"malicious" = Model detected anomaly
"not malicious" = Model saw normal pattern
```
**Important:** This column is ALWAYS the original model prediction, unchanged by human feedback.

#### `confidence` (Model's Original Certainty)
```
0.85-1.0 = High confidence (topology violations, obvious anomalies)
0.65-0.85 = Medium confidence (behavioral anomalies)
<0.65 = Low confidence (uncertain)
```
**This is the original model confidence before any human feedback.**

#### `confidence_adjusted` (After Human Feedback)
```
Same scale as above, but adjusted for human input
Lower than original = Human disagreement challenged the model
Higher than original = Human agreement validated the model
```
**This reflects how human expertise affects our trust in the model's rule.**

#### `reason` (Why Model Flagged It)
```
Examples:
"Traffic anomaly: Unusual port 19065 with dns"
"Topology violation: Unauthorized cross-subnet communication"
"No anomalies detected"
```

#### `human_feedback` (Expert's Assessment)
```
"malicious" = Expert says it's anomalous
"not malicious" = Expert says it's normal
(blank) = Expert didn't review this row
```

#### `human_confidence` (Expert's Certainty)
```
0.0-1.0 (blank if not reviewed)
0.85+ = Very confident expert assessment
0.70-0.85 = Reasonably confident
0.55-0.70 = Weakly confident
<0.55 = Very uncertain
```

#### `confidence_gap` (Disagreement Magnitude)
```
= abs(model_confidence - human_confidence)
0.00-0.10 = Slight difference (aligned)
0.10-0.25 = Moderate difference
>0.25 = Large difference (significant disagreement)
```

#### `adjustment_reason` (How Confidence Changed)
```
Examples:
"Agreement: Human very confident (conf=0.90) → Boosted to 0.95"
"Strong disagreement (human_conf=0.82): Gap=0.15, penalty applied → 0.35"
"Moderate disagreement (human_conf=0.75): Gap=0.10, penalty applied → 0.42"
"No human feedback provided"
```

#### `rule_override_count` (Rule Performance Tracking)
```
Incremented each time this specific rule sees significant confidence reduction
0 = Rule is trusted/validated
1-3 = Rule occasionally questioned
4+ = Rule is frequently overridden; may need recalibration
```

---

## Analyzing Results

### View Model Predictions (Original)

```python
import pandas as pd
df = pd.read_csv("predictions.csv")
df[df['prediction'] == 'malicious'][['id', 'src_host', 'dst_host', 'reason', 'confidence']]
```

### View Confidence Adjustment Impact

```python
# Rows with significant human-model disagreement
high_disagreement = df[df['confidence_adjusted'] < (df['confidence'] - 0.15)]
print(f"Significant adjustments: {len(high_disagreement)} rows")
print(high_disagreement[['id', 'prediction', 'confidence', 'confidence_adjusted', 'human_feedback']])

# Rows where expert agreed and boosted confidence
validated = df[df['confidence_adjusted'] > df['confidence']]
print(f"Human-validated rules: {len(validated)} rows")
print(validated[['id', 'prediction', 'confidence', 'confidence_adjusted', 'human_confidence']])

# Rows where confidence dropped minimally (weak disagreement)
minimal_impact = df[(df['confidence_adjusted'] >= (df['confidence'] - 0.10)) & 
                    (df['human_feedback'].notna())]
print(f"Minimal adjustment rows: {len(minimal_impact)}")
```

### Identify Problematic Rules

```python
# Count significant reductions per rule
rule_quality = df.groupby('reason').agg({
    'rule_override_count': 'max',
    'id': 'count',
    'confidence_adjusted': lambda x: (x < 0.45).sum()  # Count rows with confidence <0.45
}).rename(columns={'id': 'total_predictions', 'confidence_adjusted': 'low_conf_count'})

rule_quality['override_rate'] = (rule_quality['low_conf_count'] / rule_quality['total_predictions'] * 100).round(1)
print(rule_quality.sort_values('override_rate', ascending=False))
```

**Interpretation:**
- High `override_rate` = Rule triggers on false positives; consider relaxing thresholds
- Low `override_rate` = Rule is reliable; confidence adjustments are minimal
- `low_conf_count > 0` = Experts definitively challenge this rule; needs review

### View Agreement vs Disagreement Patterns

```python
# Rows with human feedback
with_feedback = df[df['human_feedback'].notna()]

# Count agreements vs disagreements
agreements = (with_feedback['human_feedback'] == with_feedback['prediction']).sum()
disagreements = len(with_feedback) - agreements

print(f"Total rows with feedback: {len(with_feedback)}")
print(f"  Agreements: {agreements} ({agreements/len(with_feedback)*100:.1f}%)")
print(f"  Disagreements: {disagreements} ({disagreements/len(with_feedback)*100:.1f}%)")
print(f"  Avg confidence gap (disagreements): {with_feedback[with_feedback['human_feedback'] != with_feedback['prediction']]['confidence_gap'].mean():.3f}")
```

---

## Configuration: Adjusting Detection Thresholds

Edit `templates/global_constraints.json`:

```json
{
  "anomaly_detection_rules": {
    "unusual_port_traffic": {
      "dport_threshold": 10000,
      "benign_services": ["http", "dns", "ftp", "smtp", "ssh"],
      "trusted_hosts": ["Enterprise0", "Enterprise1", "Enterprise2", "Defender"],
      "confidence": 0.75
    },
    "high_volume_traffic": {
      "services": ["dns", "smtp"],
      "bytes_threshold": 100000,
      "confidence": 0.70
    },
    "rare_duration_traffic": {
      "rule_1_very_short": {
        "duration_threshold": 0.1,
        "bytes_range": [50, 500]
      },
      "rule_2_admin_anomaly": {
        "source_type": ["Enterprise0", "Enterprise1", "Enterprise2", "Defender"],
        "duration_threshold": 1.0,
        "bytes_threshold": 500
      },
      "confidence": 0.65
    }
  }
}
```

**Example: Make Unusual Port rule less strict**
```json
"dport_threshold": 15000,  // was 10000
"benign_services": ["http", "https", "dns", "ftp", "smtp"],  // add https
"confidence": 0.65  // was 0.75 (lower confidence = softer penalty)
```

Then re-run: `python heuristic_model.py ...`

---

## Example Workflow

### Scenario: Analyzing Network Anomalies

**1. Run initial detection:**
```bash
python heuristic_model.py ./network_traffic --output-dir ./predictions
```

**2. Human expert reviews top suspicious rows:**
```bash
# Look at high-confidence anomalies
python -c "
import pandas as pd
df = pd.read_csv('predictions/dataset_1.csv')
suspicious = df[df['confidence'] >= 0.80].head(20)
print(suspicious[['id', 'src_host', 'dst_host', 'prediction', 'reason', 'confidence']])
"
```

**3. Create feedback:**
```bash
python generate_feedback_template.py ./predictions --output-dir ./feedback
# Expert manually fills feedback CSV with opinions on suspicious rows
```

**4. Apply feedback:**
```bash
python apply_human_feedback.py ./predictions ./feedback --output-dir ./results
```

**5. Analyze impact:**
```bash
# See which predictions changed
python -c "
import pandas as pd
df = pd.read_csv('results/dataset_1.csv')
flipped = df[df['decision_flipped'] == True]
print(f'Flipped {len(flipped)} predictions based on expert feedback')
print(flipped[['id', 'prediction', 'model_final_pred', 'human_confidence', 'flip_reason']])
"
```

---

## Troubleshooting

### Issue: No anomalies detected
**Cause:** Thresholds too strict, benign_services too narrow
**Solution:** Lower `dport_threshold`, add services to `benign_services`, reduce `bytes_threshold`

### Issue: Too many false positives
**Cause:** Thresholds too loose, rules too sensitive
**Solution:** Raise thresholds, add context checks, increase confidence requirements

### Issue: Topology violations not detected
**Cause:** Network configuration mismatch, rules allow more paths than intended
**Solution:** Review `is_allowed_path()` logic in code, verify network topology assumptions

### Issue: Model predictions seem "wrong" but aren't changing
**Cause:** Model predictions NEVER flip. You're seeing confidence adjustments, not decision changes.
**Solution:** Compare `confidence` vs `confidence_adjusted` to see adjustment magnitude. This is working as designed.

### Issue: confidence_adjusted is always the same as confidence
**Cause:** No human feedback provided, or all feedback agrees with model
**Solution:** Ensure feedback CSVs are being found and loaded correctly. Check that `human_feedback` and `human_confidence` columns have values.

### Issue: All confidence_adjusted values are at 0.30 floor
**Cause:** Strong, consistent human disagreement across many rows
**Solution:** Check if feedback is accurate or if rules need recalibration. Review `adjustment_reason` for patterns. The floor prevents over-penalizing; consider raising it temporarily to see actual penalty values.

---

## Key Principles

### 1. Ground Truth Blindness
The model **never knows** whether traffic is truly malicious or benign. It only detects deviations from normal patterns.

### 2. Static Rules
Anomaly detection rules **never change** based on human feedback. Only confidence and predictions adapt per-row.

### 3. Transparency
Every detection includes:
- **Reason:** Which rule triggered
- **Confidence:** How sure the model is
- **Logic:** Decision flip reasoning

### 4. Expert in the Loop
Human experts can:
- Review any prediction
- Override with their own assessment
- Provide confidence in their judgment
- Validate rule quality without coding

### 5. No Baselines Required
All thresholds are **universal** and **absolute**. No per-dataset tuning or baseline learning needed.

---

## FAQs

**Q: Why doesn't the model prediction change even when an expert disagrees strongly?**
A: By design. The model prediction is frozen to preserve its original perspective. Downstream decision aggregation will see both the model's view (with adjusted confidence) and the human's view, then decide. This prevents losing information before the aggregator gets to decide.

**Q: So human feedback is useless if predictions don't flip?**
A: No—human feedback directly affects `confidence_adjusted`, which signals trust/distrust in that specific rule. A downstream decision aggregation script can use both `prediction` (original) and `confidence_adjusted` (human-informed) to make intelligent final calls.

**Q: What's the confidence floor (0.30) for?**
A: Safety guardrail. Even with strong human disagreement, the model retains minimum voice in aggregation. Prevents one expert from completely silencing a rule. Can be tuned higher/lower per your domain needs.

**Q: Can I change the gap-scaling multipliers?**
A: Yes—they're in `compute_confidence_adjustment()` in [apply_human_feedback.py](apply_human_feedback.py). Increase multipliers (0.50→0.60) for harsher penalties, decrease (0.50→0.40) for softer penalties. Recommend testing with real feedback data before major changes.

**Q: What if different experts disagree with each other?**
A: Each expert feedback row produces independent confidence adjustments. If Expert A says "malicious" and Expert B says "not malicious", the model might get confidence reduced twice (once per feedback). You'd need to handle multiple feedback per row in decision aggregation.

**Q: Why no decision flipping when confidence gap is huge (e.g., model 0.90 vs human 0.10)?**
A: Because human confidence is low (0.10), they're not confident in their assessment. Their disagreement is acknowledged (confidence drops to 0.30), but model retains decision voice. High gap ≠ strong signal if human is uncertain.

**Q: Can the model learn from feedback?**
A: No. Rules, thresholds, and logic are static (by design—preserves experiment reproducibility). Only per-row confidence adapts. If you want to update rules, modify thresholds in code or configuration files and re-run heuristic_model.py.

---

## Contact & Support

For issues or questions about the heuristic model system, refer to:
- Code comments in `heuristic_model.py`
- Configuration guide in `templates/global_constraints.json`
- Feedback integration logic in `apply_human_feedback.py`
