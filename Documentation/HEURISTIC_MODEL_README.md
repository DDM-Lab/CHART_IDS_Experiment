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

## Workflow Overview

> **Prerequisites:** Complete data preparation (Step 0) to ensure the model is blind to ground truth.

### Step 1: Generate Model Predictions

**Goal:** Run the anomaly detection model on clean (unlabeled) network flow data.

**What happens:**
- Model analyzes network flows against static rules
- Detects anomalies based on topology violations and behavioral patterns
- Produces a prediction ("malicious" or "not malicious") + confidence score + explanation for each flow

**Output:** Prediction dataset with confidence scores and reasoning

---

### Step 2: Create Feedback Template

**Goal:** Prepare empty feedback form for human expert review.

**What happens:**
- System generates a template for each prediction file
- Template has columns: flow ID, expert feedback, confidence level, notes

**Output:** Empty feedback form ready for expert review

---

### Step 3: Collect Human Expert Feedback

**Goal:** Have domain experts review model predictions and provide judgments.

**Process:**
- Expert reviews model predictions (suggestions, not requirements)
- For suspicious or uncertain rows, expert provides:
  - Prediction: "malicious" or "not malicious" (or leave blank)
  - Confidence: 0.0-1.0 scale (how sure about this assessment?)
  - Notes: Optional explanation (for documentation)

**Confidence scale:**
- 0.5 = Uncertain, could go either way
- 0.7 = Reasonably confident
- 0.85-0.9 = Very confident
- 0.95+ = Absolutely certain

**⚠️ Important:** Experts only review rows they're confident about. No forced feedback on all rows.

---

### Step 4: Apply Human Feedback

**Goal:** Integrate expert feedback into model predictions. **Important: Model predictions NEVER flip.**

**What happens:**
- System compares human feedback with model predictions
- For agreements: Confidence boosted slightly (validation)
- For disagreements: Confidence reduced using gap-scaled penalty
  - Larger disagreement gaps → larger confidence reductions
  - Confidence floor (0.30) ensures model retains minimum voice
- Original prediction is always preserved

**Output:** Enhanced predictions with adjusted confidence scores and detailed reasoning for each adjustment

---

## Workflow Phases

The complete workflow has 5 phases:

### Phase 1: Data Preparation
**Goal:** Remove ground truth labels to ensure blind anomaly detection.
**When:** One-time, at the beginning.

### Phase 2: Generate Predictions
**Goal:** Run anomaly detection on clean data.
**When:** After data preparation.

### Phase 3: Human Expert Review (Optional)
**Goal:** Have experts review and assess model predictions.
**When:** If improving confidence calibration is desired.

### Phase 4: Apply Feedback
**Goal:** Integrate expert feedback to adjust model confidence.
**When:** After expert reviews (or skip if no expert available).

### Phase 5: Evaluate (Optional)
**Goal:** Measure accuracy against ground truth labels.
**When:** In research/validation scenarios where ground truth is available.

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

**Concept:** When a service normally associated with standard well-known ports appears on unexpectedly high-numbered ports, it suggests anomalous behavior.

**Why it matters:** Legitimate services have predictable port usage. Deviations may indicate misconfiguration or malicious activity.

---

### Rule 2: High Volume Traffic

**Concept:** Services that typically involve small data transfers (like DNS queries) exhibit unusually large data volumes.

**Why it matters:** Protocols with predictable transfer sizes (queries, lookups) using abnormal amounts of data suggests data exfiltration or other anomalies.

---

### Rule 3: Rare Duration Patterns

**Concept:** Network sessions with unusual temporal characteristics—extremely short or unexpectedly long—relative to normal behavior for that traffic type.

**Why it matters:** Different protocols have expected interaction patterns. Sessions that deviate significantly from these patterns may indicate connection failures, timeouts, or suspicious activity.

---

### Rule 4: Topology Violations

**Concept:** Network communication that violates expected cross-subnet or cross-boundary rules.

**Why it matters:** Well-designed networks restrict traffic flows to specific paths. Any communication outside these paths may represent unauthorized lateral movement or privilege escalation attempts.

---

## Human Feedback Confidence Adjustment Logic

The model applies **non-flipping confidence adjustment**: The model's prediction NEVER changes based on human feedback. Instead, confidence is adjusted to reflect the strength of human disagreement or agreement.

**Why non-flipping?** This design preserves the model's original perspective without bias. A downstream decision aggregation script then receives both the model's view (with adjusted confidence) and the human's view, allowing it to make informed final decisions.

### Core Principle: Gap-Scaled Penalties

When human feedback is provided, adjustments are based on:

1. **How much the expert agrees or disagrees** (prediction alignment)
2. **How confident the expert is** (confidence level)
3. **The magnitude of disagreement** (confidence gap between model and human)

Larger disagreement gaps signal stronger signals of potential error, so confidence is adjusted accordingly.

### Agreement Cases (Human Agrees with Model)

When expert agrees with the model's prediction:
- **Strong agreement (expert very confident):** Model confidence is boosted (validation)
- **Moderate agreement:** Model confidence stays unchanged
- **Weak agreement:** Model confidence receives slight boost

### Disagreement Cases (Human Disagrees with Model)

When expert disagrees with the model's prediction:
- **Strong disagreement (expert very confident):** Model confidence is significantly reduced
- **Moderate disagreement:** Model confidence is moderately reduced
- **Weak disagreement:** Model confidence is slightly reduced
- **Very weak disagreement (expert uncertain):** Model confidence barely changes

**Important:** There is a confidence floor (minimum value) that prevents the model from being completely discounted, even with strong disagreement. The model always retains some voice in downstream decision aggregation.

---

## Understanding Output CSV

When predictions are generated and feedback is applied, the output includes several columns to help interpret results:

**From the Model:**
- `prediction`: Original model prediction ("malicious" or "not malicious")
- `confidence`: Original model confidence score
- `reason`: Explanation of which detection rule(s) triggered

**From the Expert (if feedback provided):**
- `human_feedback`: Expert's assessment
- `human_confidence`: Expert's confidence level
- `human_explanation`: Expert's optional notes

**Calculated by System:**
- `confidence_adjusted`: Model confidence after considering human feedback
- `confidence_gap`: Magnitude of disagreement between model and expert
- `adjustment_reason`: Explanation of how/why confidence adjusted
- `rule_override_count`: Tracks how often a specific rule is challenged

---

## Interpreting Results

### Key Patterns to Look For

**High Model Confidence + No Feedback**
- Model is confident but unreviewed
- Consider if expert review would validate or challenge

**Model and Expert Agree**
- Confidence usually increased (validation)
- Strong signal that rule is reliable

**Model and Expert Disagree Strongly**
- Confidence significantly reduced
- Suggests rule may need refinement
- Rule quality should be analyzed if this occurs frequently

**Model and Expert Both Uncertain**
- Both have low confidence
- Neither is strongly pushing for a particular decision
- May need more data or clearer distinguishing features

### Identifying Problematic Rules

If the same detection rule repeatedly gets strong human pushback:
- The rule thresholds may be too strict
- The rule may be triggering on benign patterns
- Consider adjusting rule logic or thresholds

If most human feedback validates the model:
- Rules are working well
- Feedback provides confidence confirmation rather than correction

---

## Fine-Tuning the System

The system has configurable parameters for controlling how strictly detection rules are applied and how strongly human feedback influences confidence adjustments. Key areas where tuning helps:

**Detection Rule Thresholds:**
- Stricter thresholds = fewer alerts (lower false positive rate)
- Looser thresholds = more alerts (higher sensitivity)
- Adjust based on operational priorities

**Confidence Adjustment Parameters:**
- More aggressive penalties = Human feedback has stronger influence
- Softer penalties = Model retains more confidence even with disagreement
- Adjust based on how much you trust expert judgment relative to model

Consult implementation documentation or code comments for specific parameter names and adjustment guidance.

---

## Troubleshooting

### General Workflow Issues

**No anomalies detected**
- Detection rules may be too strict (high thresholds)
- Solution: Loosen thresholds or broaden the services/patterns being monitored

**Too many false positives**
- Detection rules may be too loose (low thresholds)
- Solution: Tighten thresholds, add additional context checks, increase confidence requirements

**Topology violations not detected**
- Network policy rules may not match actual network layout
- Solution: Review and update network topology assumptions

**Model predictions seem unchanged despite human feedback**
- This is expected by design. Predictions never flip.
- Solution: Check `confidence_adjusted` column to see confidence changes. This is working correctly.

**Confidence scores show no adjustment from human feedback**
- Human feedback may not be provided or may uniformly agree with model
- Solution: Verify feedback data is loaded correctly. Check that feedback columns have values.

**All adjusted confidence values at minimum floor**
- Strong, consistent human disagreement across many rows
- Solution: Verify feedback accuracy. Review adjustment reasons. Consider adjusting the confidence floor parameter if appropriate.

---

## Key System Principles

### 1. Ground Truth Blindness
The model **never knows** whether traffic is truly malicious or benign. It only detects deviations from expected/normal patterns.

### 2. Static Detection Rules
Anomaly detection rules **never change** based on human feedback. Only per-row confidence and final decisions adapt.

### 3. Transparency
Every detection includes:
- Which rule(s) triggered
- Model's confidence level
- Detailed reasoning

### 4. Expert Review Option
Human experts can:
- Review any prediction
- Provide their own assessment
- Indicate confidence in their judgment
- Validate rule quality

### 5. Model Perspective Preservation
The original model prediction is always available for downstream decision aggregation. Confidence adjustments signal rule reliability without hiding the model's original perspective.

---

## Frequently Asked Questions

**Q: Why don't model predictions change when experts disagree?**

A: By design. The model's original perspective is preserved for downstream systems. Confidence adjustments signal the strength of expert disagreement without losing the model's view. A separate decision aggregation system can then weigh both perspectives intelligently.

**Q: If predictions don't flip, what does human feedback do?**

A: Human feedback directly adjusts confidence scores, which signals how much to trust that particular rule. These adjusted scores are used by downstream decision aggregation to make final calls that combine model and expert perspectives.

**Q: Why is there a minimum confidence floor?**

A: It prevents any single expert from completely silencing a rule. Even with strong disagreement, the model retains a voice in downstream aggregation. This prevents one dissenting expert from overriding consistent model behavior.

**Q: Can I adjust how strongly human feedback influences confidence?**

A: Yes. The confidence adjustment parameters (penalty multipliers, floor, ceiling) can be configured. More aggressive penalties = human feedback has stronger influence. Softer penalties = model retains more confidence even with disagreement.

**Q: What if multiple experts review the same row?**

A: Each expert feedback produces independent confidence adjustments. Multiple reviews could result in confidence being adjusted several times, reflecting the consensus (or lack thereof) among expert reviewers.

**Q: What if an expert has low confidence in their feedback?**

A: The adjustment is proportional to expert confidence. Low expert confidence = minimal confidence adjustment to the model. High expert confidence + strong disagreement = significant adjustment. This prevents uncertain experts from strongly challenging the model.

**Q: Can the model learn and improve over time from feedback?**

A: No. Detection rules and thresholds are static by design (preserves reproducibility). Only per-row confidence adapts. To update rules, modify configuration/code and re-run detection on the data.

**Q: How do I know if a particular detection rule is working well?**

A: Analyze patterns in human feedback:
- If experts consistently validate a rule → rule is reliable
- If experts frequently disagree with a rule → rule may need refinement
- If experts rarely review a rule → rule's predictions may be uncontroversial or ignored

**Q: How much human feedback is needed?**

A: It depends on your goals:
- Quick validation: 10-20 rows per attack type
- Thorough assessment: 30-50 rows per rule
- Complete calibration: 50+ rows across all rule combinations
- More feedback provides more robust confidence adjustments

**Q: Can I modify detection rules based on feedback?**

A: Yes, but that's a separate step. Analyze feedback patterns to identify problematic rules, then modify rule logic/thresholds in the implementation and re-run detection.

---

## Contact & Implementation Details

For detailed information about configuration, implementation, or troubleshooting at the code level, refer to project documentation files and code comments in the implementation.
