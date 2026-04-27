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

2. **`apply_human_feedback.py`** - Human feedback integration
   - Merges expert feedback with model predictions
   - Applies intelligent decision-flip logic
   - Adapts model confidence based on human input
   - Tracks rule overrides for analysis

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

### Step 4: Apply Human Feedback

```bash
python apply_human_feedback.py ./IDS_heuristic_model_eval ./human_feedback \
  --output-dir ./IDS_with_feedback
```

**Output:** Enhanced CSVs with feedback integration

**New columns added:**
- `human_feedback`: Expert's prediction
- `human_confidence`: Expert's confidence (0.0-1.0)
- `human_explanation`: Optional expert notes
- `model_final_pred`: Decision after considering human input
- `model_final_conf`: Confidence after adjustment
- `decision_flipped`: True if prediction changed due to feedback
- `flip_reason`: Why the prediction changed (or didn't)
- `rule_override_count`: How many times this rule was overridden
- `confidence_gap`: abs(model_confidence - human_confidence)

**Example row after feedback:**
```
prediction=malicious, confidence=0.75,
human_feedback=not malicious, human_confidence=0.90,
model_final_pred=not malicious, model_final_conf=0.55,
decision_flipped=True,
flip_reason=Human very confident (conf=0.90) → FLIP,
rule_override_count=1
```

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

## Human Feedback Decision Logic

The model adapts its predictions based on expert feedback using this logic:

### When Expert AGREES with Model
No change needed. Confidence may be boosted if expert is very confident.

### When Expert DISAGREES with Model

**Decision flip rules:**
```
IF expert_confidence >= 0.80:
    → FLIP to expert's prediction (expert is very confident)

ELIF expert_confidence >= 0.70:
    IF model_confidence < 0.75:
        → FLIP (both uncertain, expert wins)
    ELSE:
        → KEEP model (model confident, expert only moderate)

ELIF expert_confidence >= 0.55:
    IF model_confidence < 0.65:
        → FLIP (model very weak, expert overrides)
    ELSE:
        → KEEP model (model moderate, expert too uncertain)

ELSE (expert_confidence < 0.55):
    → KEEP model (expert too uncertain, trust model)
```

### Confidence Adjustment

After feedback, model confidence is re-calibrated:

| Scenario | Formula | Meaning |
|----------|---------|---------|
| Expert agrees, very confident | conf + 0.10 | Rule validated |
| Expert agrees, moderate conf | conf (unchanged) | Rule confirmed |
| Expert disagrees, very confident | (1 - conf) + 0.15-0.30 | Heavy penalty for being wrong |
| Expert disagrees, moderate conf | (1 - conf) + 0.40 | Medium penalty |
| Expert disagrees, weak conf | (1 - conf) + 0.45 | Soft penalty |
| Expert very uncertain | conf + 0.05 | Slight trust boost to model |

**Result:** Lower confidence = model is less certain about its rule going forward

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

#### `prediction` (Model Output)
```
"malicious" = Anomaly detected
"not malicious" = Normal pattern
```

#### `confidence` (Model's Certainty)
```
0.85-1.0 = High confidence (topology violations, obvious anomalies)
0.65-0.85 = Medium confidence (behavioral anomalies)
<0.65 = Low confidence (uncertain)
```

#### `reason` (Why Model Flagged It)
```
Examples:
"Traffic anomaly: Unusual port 19065 with dns"
"Topology violation: Unauthorized cross-subnet communication"
"No anomalies detected"
```

#### `decision_flipped` (Human Impact)
```
True = Expert overrode model's prediction
False = Expert either agreed or didn't review
```

#### `flip_reason` (How Decision Changed)
```
Examples:
"Human very confident (conf=0.90) → FLIP"
"Both uncertain (model_conf=0.75, human_conf=0.60) → FLIP"
"Model moderate (conf=0.75), human weak → KEEP model"
```

#### `rule_override_count` (Rule Performance)
```
Incremented each time this specific rule is overridden
High count = Rule may need recalibration
```

---

## Analyzing Results

### View Model Predictions Only

```python
import pandas as pd
df = pd.read_csv("predictions.csv")
df[df['prediction'] == 'malicious'][['id', 'src_host', 'dst_host', 'reason', 'confidence']]
```

### View Feedback Impact

```python
# Rows where expert overrode model
df[df['decision_flipped'] == True][['id', 'prediction', 'model_final_pred', 'flip_reason']]

# Rows where expert agreed
df[df['decision_flipped'] == False][['id', 'prediction', 'human_feedback']]

# High disagreement (confidence gap)
df.nlargest(10, 'confidence_gap')[['id', 'confidence', 'human_confidence', 'flip_reason']]
```

### Identify Problematic Rules

```python
# Count overrides per rule
df.groupby('reason').agg({
    'rule_override_count': 'sum',
    'id': 'count'
}).rename(columns={'id': 'total_predictions'})
```

**Interpretation:**
- High override count = Rule triggers on false positives
- Low override count = Rule is accurate
- **Action:** Relax threshold or add context checks for high-override rules

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

### Issue: Human feedback not merging
**Cause:** Filename mismatch (feedback CSV name doesn't match prediction CSV)
**Solution:** Feedback files should be named `[prediction_name]_feedback.csv`

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

**Q: Why does the model flag benign traffic as malicious?**
A: It detects statistical deviations, not attack signatures. A 250KB DNS transfer is anomalous (unusual but legitimate).

**Q: Can I disable rules?**
A: Set their confidence to 0.00 in `global_constraints.json` (or leave threshold unmet). Better: adjust thresholds.

**Q: What if the expert is wrong?**
A: The system flags high-confidence conflicts for review. If expert_conf ≥0.80 and model_conf ≥0.80 and disagree, it's flagged.

**Q: Can the model learn from feedback?**
A: No. Rules and logic are static. Only per-row confidence adapts (by design, for experiment reproducibility).

**Q: What's a good confidence score?**
A: 0.75+ indicates high-confidence detections. 0.65-0.75 indicates medium-confidence anomalies.

---

## Contact & Support

For issues or questions about the heuristic model system, refer to:
- Code comments in `heuristic_model.py`
- Configuration guide in `templates/global_constraints.json`
- Feedback integration logic in `apply_human_feedback.py`
