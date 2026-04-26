# CHART IDS Experiment - Intrusion Detection System Benchmark Dataset Generator

A Python-based pipeline for generating realistic, parameterized network traffic datasets for testing and evaluating intrusion detection systems (IDS). This tool creates balanced datasets with labeled attack traffic, benign activity, and false alarms grounded in real network behavior.

## 🎯 What This Repository Does

This pipeline synthesizes network traffic datasets by combining:

1. **Real-world attack patterns** — extracted from the UNSW-NB15 dataset
2. **Realistic benign traffic** — diverse services (HTTP, DNS, SSH, FTP, SMTP, RDP)
3. **Configurable false alarms** — anomalous-looking benign traffic that tricks signature-based IDS

The generated datasets respect:
- **AWS network topology** — realistic subnet routing constraints
- **Temporal causality** — attack phases with phase-based event ordering
- **Operational timing** — events distributed across a 1800-second observation window

**Output**: CSV files with network traffic records labeled by event type (Malicious, Benign, False Alarm), ready for IDS training/evaluation.

---

## ⚠️ Important: Dataset Storage on Google Drive

The UNSW-NB15 datasets are **too large to store in GitHub** and are hosted on Google Drive instead. This pipeline supports two workflows:

### 📦 Default Workflow: Using Pre-Transformed Dataset (Recommended)

By default, the pipeline uses the **pre-transformed dataset**, which has already been processed and is ready to use immediately:

**Transformed Dataset Location**:
```
G:\.shortcut-targets-by-id
  └─ 1zFPkx_p8sPRshZUcZ95mHkYUPR3dh1-i
     └─ 2025GraceRoessling
        └─ 2025FriendFoeCollaborationYinuo
           └─ Documentation
              └─ IDS_zero_day_generation
                 └─ ground_truth_dataset
                    └─ UNSW_NB15_transformed.csv  ← Default dataset used
```

**Setup**:
1. Ensure Google Drive is mounted/accessible on your machine
2. Open File Explorer and navigate to `G:\` — you should see `.shortcut-targets-by-id` folder
3. If the path doesn't work, update `output_transformed_csv` in `helper_functions.py` with your actual Google Drive path

### 🔬 Advanced Workflow: Transforming from Original Dataset

If you want to start from the original UNSW-NB15 dataset and transform it yourself, this section explains how.

#### Original Dataset Location (Google Drive)

Both the original and transformed datasets are stored in the same Google Drive folder:

**Original Dataset**:
```
G:\.shortcut-targets-by-id
  └─ 1zFPkx_p8sPRshZUcZ95mHkYUPR3dh1-i
     └─ 2025GraceRoessling
        └─ 2025FriendFoeCollaborationYinuo
           └─ Documentation
              └─ IDS_zero_day_generation
                 └─ ground_truth_dataset
                    └─ UNSW_NB15_training-set(in).csv  ← Original dataset (input)
```

#### Where the Original Dataset Comes From

The original UNSW-NB15 dataset is sourced from the official UNSW project website:

**Website**: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

**How to Download from the Website**:
1. Visit https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. Follow the path: **OneDrive → CVS Files → Training and Testing Sets →** `UNSW_NB15_training-set.csv`
3. Download the CSV file and save it to your Google Drive at the path shown above

**Note**: The Google Drive folder already contains this file, so you don't need to download it unless you want to refresh the original dataset.

#### Running the Transformation (pre_step.py)

The `pre_step.py` file contains the transformation logic that converts the original dataset into the format used by the pipeline:

**What pre_step.py does**:
- Takes `UNSW_NB15_training-set(in).csv` as input
- Adds scenario labels (WannaCry, Data_Theft, ShellShock, etc.)
- Assigns network topology information (subnets, hosts, IPs)
- Expands each UNSW row across 5 scenarios
- Outputs `UNSW_NB15_transformed.csv`

**When to run pre_step.py**:
- **Not normally** — the transformed file already exists on Google Drive
- **Only if** you want to:
  - Start from the original UNSW dataset instead of using the pre-transformed version
  - Understand how the transformation works
  - Modify the transformation logic for your own research

**How to run pre_step.py manually**:
1. Ensure the original dataset exists at the Google Drive path above
2. Edit `helper_functions.py` and update these paths:
   ```python
   input_unsw_csv = Path(r"G:\.shortcut-targets-by-id\1zFPkx_p8sPRshZUcZ95mHkYUPR3dh1-i\..\ground_truth_dataset\UNSW_NB15_training-set(in).csv")
   output_transformed_csv = Path(r"G:\.shortcut-targets-by-id\1zFPkx_p8sPRshZUcZ95mHkYUPR3dh1-i\..\ground_truth_dataset\UNSW_NB15_transformed.csv")
   ```
3. Run: `python pre_step.py`
4. Wait for the transformation to complete (may take several minutes)
5. The transformed CSV will be saved to the output path

## 📊 Quick Start

### Prerequisites

- Python 3.8+
- Required packages: `pandas`, `numpy`, `scikit-learn`

### Installation

1. **Clone/download the repository**:
```bash
cd CHART_IDS_Experiment
```

2. **Install Python dependencies**:
```bash
pip install pandas numpy scikit-learn
```

3. **Verify Google Drive setup**:
   - Ensure Google Drive is mounted/accessible on your machine
   - The pipeline uses the transformed UNSW dataset by default (see section above)
   - If your Google Drive path differs, update `output_transformed_csv` in `helper_functions.py`

4. **Verify other required files**:
   - Template files in `templates/` should already be present
   - No other external datasets needed beyond what's on Google Drive

### Generate a Dataset (5 minutes)

Edit `main.py` to configure your experiment:

```python
# main.py - Configuration Section

TOTAL_EVENTS_PER_TABLE = 30          # 18-45 events per scenario
FALSE_ALARM_BIN = "standard"         # 0%, 5%, 10%, 15% (standard), 20%, or 30%
FA_TYPE_RATIO_MODE = "balanced"      # balanced, port_heavy, volume_heavy, or duration_heavy
```

Then run the pipeline:

```bash
python main.py
```

**Output**: Five CSV files generated in `IDS_tables/` with ~ 30 events per scenario
- `WannaCry_30_events.csv`
- `Data_Theft_30_events.csv`
- `ShellShock_30_events.csv`
- `Netcat_Backdoor_30_events.csv`
- `passwd_gzip_scp_30_events.csv`

## 🎛️ Configuration Parameters

### Total Events Per Table

Controls the total event count per scenario (scales all event types proportionally):

| Value | Effect |
|-------|--------|
| **18-25** | Small datasets (tight learning regime) |
| **26-35** | Medium datasets (default range: 30) |
| **36-45** | Large datasets (comprehensive coverage) |

Example: Setting `TOTAL_EVENTS_PER_TABLE = 45` generates ~18 malicious + 23 benign + 7 false alarm events.

### False Alarm Rate (FALSE_ALARM_BIN)

Controls how much benign traffic looks anomalous (IDS triage training):

| Bin | Rate | Use Case |
|-----|------|----------|
| **zero** | 0% | Pure attack detection (no triage needed) |
| **very_conservative** | 5% | High-confidence scenarios |
| **conservative** | 10% | Standard IDS operation |
| **standard** | 15% | **Default** — balanced challenge |
| **elevated** | 20% | Real-world noise conditions |
| **high** | 30% | Maximum safe level (all scenarios valid) |

Higher rates = More benign traffic that looks suspicious = Harder for IDS to distinguish = More training data for triage.

### False Alarm Type Distribution (FA_TYPE_RATIO_MODE)

Controls what *kinds* of anomalies appear in the false alarms:

| Mode | Distribution | Detection Difficulty |
|------|--------------|---------------------|
| **balanced** | 40% Type 1 (port anomalies) + 40% Type 2 (high volume) + 20% Type 3 (long duration) | Medium — mix of easy/hard patterns |
| **port_heavy** | 60% Type 1 + 20% Type 2 + 20% Type 3 | Easier — obvious port anomalies |
| **volume_heavy** | 20% Type 1 + 60% Type 2 + 20% Type 3 | Harder — requires baselines |
| **duration_heavy** | 20% Type 1 + 20% Type 2 + 60% Type 3 | Hardest — subtle timing anomalies |

Choose based on your IDS's detection strategy.

## 📋 Example Configurations

### Scenario 1: Minimal False Alarm Dataset (Research)
```python
TOTAL_EVENTS_PER_TABLE = 30
FALSE_ALARM_BIN = "zero"
FA_TYPE_RATIO_MODE = "balanced"
```
→ Pure attack vs. benign (no misleading signals)

### Scenario 2: Challenging Balanced Dataset (Default)
```python
TOTAL_EVENTS_PER_TABLE = 30
FALSE_ALARM_BIN = "standard"      # 15% false alarm rate
FA_TYPE_RATIO_MODE = "balanced"
```
→ Realistic mix of attacks, benign traffic, and confusing false alarms

### Scenario 3: Large Dataset with High Noise (Stress Test)
```python
TOTAL_EVENTS_PER_TABLE = 45
FALSE_ALARM_BIN = "high"          # 30% false alarm rate
FA_TYPE_RATIO_MODE = "volume_heavy"  # Hard-to-detect anomalies
```
→ Maximum complexity: many events, lots of noise, subtle anomalies

## 📊 Output Dataset Format

Each CSV file contains **parameterized number of network traffic records** (18-45 events per scenario, configurable via `TOTAL_EVENTS_PER_TABLE` in main.py) with **33 columns**:

**Column Groups**:
- **Metadata (5)**: `id`, `_total_events_param`, `_false_alarm_pct_param`, `_malicious_count_param`, `_benign_count_param`
- **Core Schema (23)**: Network flow data (listed below)
- **Tracking (2)**: `_unsw_row_id`, `scenario_name` (audit trail)
- **Event Context (2)**: `_source` (event origin), `phase` (temporal phase for malicious events)

**Core Schema Columns (23)**:

| Column | Type | Example | Meaning |
|--------|------|---------|---------|
| `timestamp` | float | 123.45 | Seconds since observation window start (0-1800s) |
| `src_host` | str | User1 | Source hostname |
| `dst_host` | str | Enterprise0 | Destination hostname |
| `src_ip` | str | 10.0.1.11 | Source IP address |
| `dst_ip` | str | 10.0.2.10 | Destination IP address |
| `src_subnet` | str | Subnet 1 (User) | Source subnet |
| `dst_subnet` | str | Subnet 2 (Enterprise) | Destination subnet |
| `proto` | str | tcp | Protocol (tcp/udp) |
| `sport` | int | 52341 | Source port |
| `dport` | int | 22 | Destination port |
| `service` | str | ssh_admin | Inferred service |
| `duration` | float | 45.3 | Connection duration (seconds) |
| `bytes` | int | 12500 | Total bytes transferred |
| `packets` | int | 87 | Total packets |
| `sttl` | int | 64 | Source TTL |
| `dttl` | int | 62 | Destination TTL |
| `state` | str | FIN | Connection state |
| `sloss` | int | 0 | Source packet loss |
| `dloss` | int | 0 | Destination packet loss |
| `ct_src_dport_ltm` | int | 2 | Count connections by source to same dest port |
| `ct_dst_src_ltm` | int | 3 | Count unique dest IPs from same source |
| `attack_cat` | str | Normal | Attack category (from UNSW) |
| **`label`** | **str** | **Malicious** | **Class label: Malicious / Benign / False Alarm** |

**Key fields**:
- `label` — use for supervised learning / IDS evaluation
- `_source` — identifies event provenance (real UNSW vs. synthetic)
- `phase` — temporal phase annotation for malicious events

*Full column documentation: [templates/global_constraints.json](templates/global_constraints.json) (output_schema section)*

## 🔍 Understanding Your Dataset

### Event Composition (Parameterized)

**Configuration** (set in main.py):
```python
TOTAL_EVENTS_PER_TABLE = 18           # Range: 18-45
FALSE_ALARM_BIN = "high"             # 0%-30% false alarm rate
FA_TYPE_RATIO_MODE = "balanced"      # Type 1:2:3 ratio
```

**Example: With total=18, FA_pct=30%**:
```
Total: 18 events
├─ Malicious attacks: 7-11 (scenario-specific, fixed)
├─ Benign traffic: computed as (total - malicious - false_alarm)
└─ False alarms: round(18 × 0.30) = 5 (configurable)
```

**Malicious event counts per scenario** (fixed in templates):
- WannaCry: 11 | Data_Theft: 9 | ShellShock: 9
- Netcat_Backdoor: 7 | passwd_gzip_scp: 7 | No_Attack: 0

### Attack Scenarios (5 per run)
- **WannaCry**: Ransomware propagation pattern
- **Data_Theft**: Exfiltration via network tunneling
- **ShellShock**: Remote code execution via HTTP
- **Netcat_Backdoor**: Reverse shell backdoor
- **passwd_gzip_scp**: Credential compromise + data copy

### Network Topology
- **3 AWS Subnets**: User (client layer), Enterprise (app layer), Operational (infrastructure)
- **15 internal hosts**: Distributed roles (web servers, databases, workstations, admin boxes)
- **Realistic routing**: Not all subnets communicate directly (respects AWS VPC structure)

## 📁 Directory Structure

```
CHART_IDS_Experiment/
├── main.py                          # Entry point: configure parameters here
├── helper_functions.py              # Utilities (network topology, validation)
├── pre_step.py                      # UNSW transformation (reference, not executed)
├── step_1.py through step_6.py       # Pipeline stages
├── IDS_Datasets/                    # Folder (empty — data sourced from Google Drive)
│   └── [Data stored on Google Drive, not in repo]
├── templates/
│   ├── global_constraints.json           # Experiment rules
│   ├── zero_day_templates.json           # Scenario definitions
│   ├── network_topology_output.json      # AWS topology
│   └── *.json                            # Other templates
├── IDS_tables/
│   ├── {scenario}_30_events.csv          # Generated outputs (per run)
│   └── ...
└── IDS_methodology/
    └── IMPLEMENTATION_REVIEW.md          # Detailed technical docs
```

## 🚀 Advanced Usage

### Parameter Sweep (Generate Multiple Variants)

To test your IDS against different difficulty levels, run the pipeline with different parameter combinations:

```python
# bash/PowerShell
for $events in 18, 30, 45 {
    for $fa_bin in "zero", "standard", "high" {
        # Edit main.py with ($events, $fa_bin)
        python main.py
        # Results are saved in IDS_tables/
    }
}
```

### Custom Network Topology

Edit `templates/network_topology_output.json` to define your own:
- Host names and IP addresses
- Subnet structure (CIDR blocks)
- Routing constraints

Then regenerate datasets — all event generation respects the new topology.

## 📖 Documentation

For deeper technical details:

- **[IMPLEMENTATION_REVIEW.md](IDS_methodology/IMPLEMENTATION_REVIEW.md)** — Architecture, validation logic, false alarm taxonomy
- **[IDS_generation_method.md](IDS_methodology/IDS_generation_method.md)** — Step-by-step synthesis methodology
- **[global_constraints.json](templates/global_constraints.json)** — Experiment rules and UNSW grounding principles

## ⚙️ Dependencies & Versions

- **Python**: 3.8+ (tested on 3.11)
- **pandas**: For CSV I/O and data manipulation
- **numpy**: Array operations and random sampling
- **scikit-learn**: KDE-based synthesis for small event groups

Install all at once:
```bash
pip install pandas numpy scikit-learn
```

## ✅ Verification

After running `python main.py`, verify your dataset:

```python
import pandas as pd

df = pd.read_csv("IDS_tables/WannaCry_30_events.csv")

# Check event composition
print(df['label'].value_counts())
# Output should show: Malicious (~10), Benign (15), False Alarm (~5)

# Check temporal ordering
print((df['timestamp'].diff() >= 0).all())
# Output should be: True (events ordered by time)

# Check label distribution matches expectation
print(df.groupby('label').size() / len(df))
# Output should be close to: Malicious 33%, Benign 50%, False Alarm 15%
```

## 🐛 Troubleshooting

**Issue**: "Pre-transformed UNSW dataset not found at: G:\..."
- **Solution**: Verify Google Drive is mounted and accessible. Check that the path in `helper_functions.py` matches your Google Drive setup. You may need to mount Google Drive differently depending on your system.

**Issue**: "No such file or directory: UNSW_NB15_transformed.csv"
- **Solution**: This is a Google Drive path issue. Ensure the dataset file exists at the location specified in `helper_functions.py` (see the "Dataset Storage on Google Drive" section above).

**Issue**: "Want to transform from the original UNSW dataset"
- **Solution**: See the "Advanced Workflow: Transforming from Original Dataset" section above. Download the original dataset from the UNSW website, or use the copy in the Google Drive folder. Then run `pre_step.py` to transform it.

**Issue**: "Invalid false_alarm_bin" error
- **Solution**: Check spelling in main.py — must be one of: zero, very_conservative, conservative, standard, elevated, high

**Issue**: "Network topology violations" during generation
- **Solution**: Check `network_topology_output.json` for routing rule definitions; ensure all internal hosts are defined

## 📧 Questions?

Refer to inline code comments (especially in `helper_functions.py`) or detailed docs in `IDS_methodology/`.

---

**Generated**: April 2026 | **Status**: Production (Steps 0-6 complete)
