# UNSW-NB15 Column Derivation Assessment

## Summary
**All recommended additions are ALREADY PRESENT in the UNSW-NB15 dataset.** This is excellent news for enriching your IDS schema.

---

## Detailed Column Mapping

### **Priority 1: TTL Indicators** ✅ FULLY AVAILABLE

| Recommendation | UNSW Column | Position | Derivable? | Notes |
|---|---|---|---|---|
| `sttl` (source TTL) | `sttl` | Col 11 | ✅ **Yes** | Direct pass-through. Range: 0-254 (from sample data: 62, 252, 254, etc.) |
| `dttl` (destination TTL) | `dttl` | Col 12 | ✅ **Yes** | Direct pass-through. Range: 0-254 (from sample: 252, 254, etc.) |
| **TTL Anomaly Derivation** | Computed | - | ✅ **Derived** | TTL parity mismatch: `(sttl - dttl) % 64 != 0` → suggests spoofing/tunneling |

**Sample Values from UNSW:**
```
Row 1: sttl=252, dttl=254 → difference=2 (suspicious)
Row 2: sttl=62, dttl=252 → difference=190 (very suspicious—suggests different network hops)
Row 3: sttl=62, dttl=252 → typical for cross-subnet (internal→external)
```

**Action:** Add `sttl` and `dttl` directly to your output schema. Optionally compute `ttl_anomaly` flag for downstream NoDOZE scoring.

---

### **Priority 2: Connection Count Features** ✅ FULLY AVAILABLE

| Recommendation | UNSW Column | Position | Derivable? | Notes |
|---|---|---|---|---|
| `ct_src_dport_ltm` | `ct_src_dport_ltm` | Col 34 | ✅ **Yes** | Count: source IPs connecting to same destination port in last time interval. Range: 1-40 (from data) |
| `ct_dst_src_ltm` | `ct_dst_src_ltm` | Col 36 | ✅ **Yes** | Count: unique destination IPs reached by same source in last time interval. Range: 1-40 |
| `ct_srv_src` | `ct_srv_src` | Col 31 | ✅ **Yes** | Count: same source-service flows. Detects service-specific scanning. Range: 1-43 |
| `ct_state_ttl` | `ct_state_ttl` | Col 32 | ✅ **Yes** | Count of flows with same state and TTL. Detects consistent connection patterns. Range: 0-6 |
| `ct_dst_ltm` | `ct_dst_ltm` | Col 33 | ✅ **Yes** | Count: same destination in last time interval. Range: 1-3 |

**Sample Values from UNSW:**
```
Row 1: ct_src_dport_ltm=1, ct_dst_src_ltm=1 → isolated connection (benign)
Row 2: ct_src_dport_ltm=1, ct_dst_src_ltm=2 → dest reached from 2 sources (potential scan)
Row 72: ct_src_dport_ltm=43, ct_dst_src_ltm=40 → massive scanning activity (MALICIOUS)
```

**Action:** Add all five count features. These are powerful for detecting reconnaissance (port scans) and lateral movement (WannaCry, Netcat Backdoor scenarios).

---

### **Priority 3: State/Flag Indicators** ✅ FULLY AVAILABLE

| Recommendation | UNSW Column | Position | Present? | Possible Values | Malicious Signal |
|---|---|---|---|---|---|
| `state` (TCP/protocol state) | `state` | Col 5 | ✅ **Yes** | FIN, CON, INT, REQ, RST, URP, FOU, FSRA | FIN (incomplete connections), RST, FSRA (reset anomalies) |

**Sample Values from UNSW:**
```
Row 1: state=FIN → incomplete/closed connection
Row 3: state=FIN → normal benign traffic
Row 23: state=CON → active connection (normal)
Row 54: state=CON → sustained connection (check other features)
```

**Interpretation Guide:**
- `FIN` = Client initiated close (normal or attacker fled)
- `CON` = Active connection (could be data exfiltration if bytes high)
- `INT` = Intermediate/incomplete (possible connection drop, DoS indicator)
- `RST` = Reset (possible scan or evasion)
- `FSRA` = Flag sequence anomaly (highly suspicious)

**Action:** Add `state` directly. Consider deriving `is_suspicious_state` flag: state ∈ {RST, FSRA, INT} → higher alert score.

---

### **Priority 4: Loss Metrics** ✅ FULLY AVAILABLE

| Recommendation | UNSW Column | Position | Derivable? | Notes |
|---|---|---|---|---|
| `sloss` (source packets lost) | `sloss` | Col 15 | ✅ **Yes** | Count of lost packets from source. Range: 0-28 (from data) |
| `dloss` (destination packets lost) | `dloss` | Col 16 | ✅ **Yes** | Count of lost packets to destination. Range: 0-27 |
| **Loss Ratio** | Computed | - | ✅ **Derived** | `(sloss + dloss) / (spkts + dpkts)` → high ratio = congestion/DoS |

**Sample Values from UNSW:**
```
Row 1: sloss=0, dloss=0 → clean connection
Row 2: sloss=2, dloss=17 → moderate packet loss (possible congestion or attack)
Row 3: sloss=1, dloss=6 → minor packet loss
```

**Action:** Add both `sloss` and `dloss`. Optionally compute `loss_ratio` for anomaly flagging.

---

## Summary Integration Table

### **Which Recommended Columns to Add to Your Output Schema**

| Feature Category | Columns to Add | Source in UNSW | Priority | Complexity |
|---|---|---|---|---|
| **TTL Indicators** | `sttl`, `dttl` | Direct | ⭐⭐⭐ HIGH | Trivial (pass-through) |
| **Connection Counts** | `ct_src_dport_ltm`, `ct_dst_src_ltm`, `ct_srv_src`, `ct_state_ttl` | Direct | ⭐⭐⭐ HIGH | Trivial (pass-through) |
| **State/Flags** | `state` | Direct | ⭐⭐⭐ HIGH | Trivial (pass-through) |
| **Loss Metrics** | `sloss`, `dloss` | Direct | ⭐⭐ MEDIUM | Trivial (pass-through) |
| **Derived Anomaly Flags** | `ttl_anomaly`, `is_suspicious_state`, `loss_ratio` | Computed | ⭐⭐ MEDIUM | Simple computation |

---

## Updated Recommended Schema (20 columns total, +6 from original 14)

**Original 14:**
```
timestamp, src_host, dst_host, src_subnet, dst_subnet, proto, sport, dport, 
service, duration, bytes, packets, attack_cat, label
```

**Recommended Additions (+6):**
```
sttl, dttl, state, sloss, dloss, ct_src_dport_ltm, ct_dst_src_ltm
```

**Optional Derived Columns (+3, for enhanced debugging):**
```
ttl_anomaly, is_suspicious_state, loss_ratio
```

**Total: 20-23 columns** (depending on whether you include derived flags)

---

## Impact on NoDOZE Alignment

### **Strength Multiplier by Adding These Columns**

| Column | NoDOZE Benefit | Why |
|---|---|---|
| `sttl`, `dttl` | Detects tunneling/spoofing attacks | NoDOZE looks for protocol anomalies; TTL mismatches are classic indicators |
| `ct_src_dport_ltm`, `ct_dst_src_ltm` | Detects reconnaissance & lateral movement | WannaCry worm spreads via port scans (high ct_src_dport_ltm) |
| `state` | Flags unusual connection patterns | RST/FSRA states indicate evasion or scan responses |
| `sloss`, `dloss` | Detects congestion/DoS activity | Sustained packet loss → possible exfiltration or attack traffic |

**Verdict:** Adding these columns **significantly strengthens** your ability to create realistic, NoDOZE-validated zero-day scenarios. All recommended additions are **zero-cost** (already in UNSW) but **high-value**.

---

## Derivation Strategy for Pre-Step Transformation

In your Pre-Step (UNSW→Transformed CSV), implement these mappings:

```python
# Direct pass-through from UNSW
transformed['sttl'] = unsw['sttl']
transformed['dttl'] = unsw['dttl']
transformed['state'] = unsw['state']
transformed['sloss'] = unsw['sloss']
transformed['dloss'] = unsw['dloss']
transformed['ct_src_dport_ltm'] = unsw['ct_src_dport_ltm']
transformed['ct_dst_src_ltm'] = unsw['ct_dst_src_ltm']

# Optional derived anomaly flags
transformed['ttl_anomaly'] = ((unsw['sttl'] - unsw['dttl']) % 64 != 0).astype(int)
transformed['is_suspicious_state'] = unsw['state'].isin(['RST', 'FSRA', 'INT']).astype(int)
transformed['loss_ratio'] = (unsw['sloss'] + unsw['dloss']) / (unsw['spkts'] + unsw['dpkts'])
```

---

## Recommendation

✅ **ADD ALL 7 columns** (sttl, dttl, state, sloss, dloss, ct_src_dport_ltm, ct_dst_src_ltm).

This brings your schema to **21 columns**, significantly enriching NoDOZE validation while maintaining 100% UNSW data fidelity.
