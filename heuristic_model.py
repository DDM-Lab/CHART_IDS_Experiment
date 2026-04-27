import pandas as pd
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import sys
import argparse
from pathlib import Path
import json

class HeuristicIDS:
    def __init__(self, global_constraints_path=None):

        # --- Network topology (from your JSON) ---
        self.user_subnet = "10.0.1."
        self.enterprise_subnet = "10.0.2."
        self.operational_subnet = "10.0.3."

        self.user1_ip = "10.0.1.11"
        self.enterprise1_ip = "10.0.2.11"
        self.enterprise2_ip = "10.0.2.12"
        self.opserver_ip = "10.0.3.20"
        self.defender_ip = "10.0.2.20"

        # Allowed OT ports (example – adjust as needed)
        self.allowed_ot_ports = {502, 44818}

        # --- Stateful tracking ---
        self.connection_history = defaultdict(list)
        self.failed_connections = defaultdict(int)
        self.port_history = defaultdict(set)
        self.event_log = defaultdict(deque)

        # Track attack progression
        self.seen_enterprise1_to_2 = set()

        # Time window for rate-based rules
        self.time_window = timedelta(seconds=10)

    # --- Load anomaly detection rules from global_constraints.json ---
        self.anomaly_rules = self._load_anomaly_rules(global_constraints_path)

    def _load_anomaly_rules(self, global_constraints_path):
        """Load anomaly detection thresholds from global_constraints.json."""
        default_rules = {
            'unusual_port_traffic': {
                'dport_threshold': 10000,
                'benign_services': ['http', 'https', 'dns', 'ftp', 'smtp', 'ssh', 'rdp', 'ssh_admin'],
                'trusted_hosts': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender']
            },
            'high_volume_traffic': {
                'services': ['dns', 'smtp'],  # Both services can have zone transfers
                'bytes_threshold': 100000  # 100KB (realistic zone transfer threshold)
            },
            'rare_duration_traffic': {
                'rule_1_very_short': {
                    'duration_threshold': 0.1,
                    'bytes_range': [50, 500]
                },
                'rule_2_admin_anomaly': {
                    'source_type': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'],
                    'duration_threshold': 1.0,
                    'bytes_threshold': 500
                }
            }
        }
        
        if global_constraints_path is None or not Path(global_constraints_path).exists():
            return default_rules
        
        try:
            with open(global_constraints_path, 'r') as f:
                constraints = json.load(f)
            if 'anomaly_detection_rules' in constraints:
                return constraints['anomaly_detection_rules']
        except Exception as e:
            logger.warning(f"Could not load anomaly detection rules: {e}. Using defaults.")
        
        return default_rules

    # -----------------------------
    # Utility functions
    # -----------------------------
    def get_subnet(self, ip):
        if ip.startswith(self.user_subnet):
            return "user"
        elif ip.startswith(self.enterprise_subnet):
            return "enterprise"
        elif ip.startswith(self.operational_subnet):
            return "operational"
        return "unknown"

    def is_allowed_path(self, src, dst):
        src_subnet = self.get_subnet(src)
        dst_subnet = self.get_subnet(dst)
        
        # ===== RULE 1: Intra-subnet communication is always allowed =====
        if src_subnet == dst_subnet:
            return True
        
        # ===== RULE 2: Communication with external (internet) is allowed =====
        if dst_subnet == "unknown":  # External IPs
            return True
        
        # ===== RULE 3: User subnet cross-subnet rules =====
        if src_subnet == "user":
            # User1 can initiate to Enterprise1
            if src == self.user1_ip and dst == self.enterprise1_ip:
                return True
            # No other users can cross subnets
            return False
        
        # ===== RULE 4: Enterprise subnet cross-subnet rules =====
        if src_subnet == "enterprise":
            # Enterprise can respond to User subnet (request-response pattern)
            if dst_subnet == "user":
                return True
            
            # Enterprise1 ↔ Enterprise2 allowed (intra-enterprise communication)
            if (src == self.enterprise1_ip and dst == self.enterprise2_ip) or \
               (src == self.enterprise2_ip and dst == self.enterprise1_ip):
                return True
            
            # Enterprise2 can access Operational
            if src == self.enterprise2_ip and dst == self.opserver_ip:
                return True
            
            # No other enterprise cross-subnet paths
            return False
        
        # ===== RULE 5: Operational subnet cross-subnet rules =====
        if src_subnet == "operational":
            # Operational can respond to Enterprise (request-response pattern)
            if dst_subnet == "enterprise":
                return True
            
            # No Operational → User (must go through Enterprise)
            return False
        
        # Default: deny any other cross-subnet communication
        return False

    def update_state(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]
        ts = event["timestamp"]

        self.connection_history[src].append((dst, ts))

        if event.get("state") == "FAILED":
            self.failed_connections[src] += 1

        self.port_history[src].add(event["dport"])

        # Maintain sliding window
        self.event_log[src].append(ts)
        while self.event_log[src] and (ts - self.event_log[src][0]) > self.time_window:
            self.event_log[src].popleft()

        # Track attack progression
        if src == self.enterprise1_ip and dst == self.enterprise2_ip:
            self.seen_enterprise1_to_2.add(src)

    # ----------------------------- 
    # Anomaly Detection Rules (Traffic Anomalies)
    # (Check these FIRST - traffic anomalies before topology violations)
    # ----------------------------- 
    def detect_unusual_port_traffic(self, event):
        """
        Traffic Anomaly: Ephemeral port used with service that normally uses well-known ports.
        """
        rules = self.anomaly_rules.get('unusual_port_traffic', {})
        dport_threshold = rules.get('dport_threshold', 10000)
        benign_services = rules.get('benign_services', ['dns', 'http', 'ftp'])
        trusted_hosts = rules.get('trusted_hosts', ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'])
        
        dport = event.get("dport", 0)
        service = event.get("service", "")
        src_host = event.get("src_host", "")
        
        if dport >= dport_threshold and service in benign_services and src_host in trusted_hosts:
            confidence = 0.75  # High confidence for this obvious anomaly
            return True, f"Traffic anomaly: Unusual port {dport} with {service}", confidence
        
        return False, None, 0.0

    def detect_high_volume_traffic(self, event):
        """
        Traffic Anomaly: Anomalously large data transfer over normally low-traffic protocol.
        Realistic: Detects zone transfers (250KB DNS/SMTP over 1-2 seconds).
        """
        rules = self.anomaly_rules.get('high_volume_traffic', {})
        services = rules.get('services', ['dns', 'smtp'])  # Both DNS and SMTP
        bytes_threshold = rules.get('bytes_threshold', 100000)  # 100KB (not 10MB)
        
        event_service = event.get("service", "")
        bytes_total = event.get("bytes", 0)
        
        # Check if service matches and bytes exceed threshold
        if event_service in services and bytes_total > bytes_threshold:
            confidence = 0.70  # Medium-high confidence (zone transfers are rare but legitimate)
            return True, f"Traffic anomaly: High volume ({bytes_total} bytes) over {event_service}", confidence
        
        return False, None, 0.0

    def detect_rare_duration_traffic(self, event):
        """
        Traffic Anomaly: Unusually short connection duration OR unusual admin SSH patterns.
        Detects both obvious failures (very short SSH) and suspicious admin activity.
        """
        rules = self.anomaly_rules.get('rare_duration_traffic', {})
        
        service = event.get("service", "")
        duration = event.get("duration", 0)
        bytes_total = event.get("bytes", 0)
        src_host = event.get("src_host", "")
        src_ip = event.get("src_ip", "")
        
        # Check if it's SSH or SSH admin
        if service not in ['ssh', 'ssh_admin']:
            return False, None, 0.0
        
        # RULE 1: Very short SSH (rejected login attempt)
        ssh_short = rules.get('rule_1_very_short', {})
        duration_threshold = ssh_short.get('duration_threshold', 0.1)
        bytes_range = ssh_short.get('bytes_range', [50, 500])
        
        if duration < duration_threshold and bytes_range[0] <= bytes_total <= bytes_range[1]:
            src_subnet = self.get_subnet(src_ip)
            if src_subnet in ["user", "enterprise"]:
                confidence = 0.65
                return True, f"Traffic anomaly: Very short duration ({duration}s) for {service}", confidence
        
        # RULE 2: Admin SSH with unusual characteristics (longer duration + more bytes)
        admin_anomaly = rules.get('rule_2_admin_anomaly', {})
        admin_hosts = admin_anomaly.get('source_type', ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'])
        
        if src_host in admin_hosts:
            # Suspicious pattern: longer duration (>1s) + more bytes (>500)
            if duration > 1.0 and bytes_total > 500:
                confidence = 0.65
                return True, f"Traffic anomaly: Unusual SSH pattern from admin host (duration={duration}s, bytes={bytes_total})", confidence
        
        return False, None, 0.0

    # ----------------------------- 
    # Topology Violation Rules (Network Security Anomalies)
    # ----------------------------- 
    def violates_topology(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]

        src_subnet = self.get_subnet(src)
        dst_subnet = self.get_subnet(dst)

        if src_subnet != dst_subnet:
            if not self.is_allowed_path(src, dst):
                return True, "Unauthorized cross-subnet communication"

        return False, None

    def non_user1_lateral_movement(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]

        if self.get_subnet(src) == "user" and src != self.user1_ip:
            dst_subnet = self.get_subnet(dst)
            # External access (internet) is allowed for all users
            if dst_subnet == "unknown":
                return False, None
            # Non-User1 users attempting to access internal subnets is suspicious
            if dst_subnet != "user":
                return True, "Non-User1 attempting to access internal subnet"

        return False, None

    def invalid_ot_access(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]

        if self.get_subnet(dst) == "operational":
            if src != self.enterprise2_ip:
                return True, "Unauthorized access to operational subnet"

        return False, None

    def invalid_attack_sequence(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]

        if dst == self.opserver_ip:
            if src != self.enterprise2_ip:
                return True, "Invalid attack sequence (skipped stages)"

        return False, None

    def port_scan_detected(self, event):
        src = event["src_ip"]

        if len(self.port_history[src]) > 10:
            return True, "Port scanning behavior detected"

        return False, None

    def excessive_failures(self, event):
        src = event["src_ip"]

        if self.failed_connections[src] > 5:
            return True, "Excessive failed connections"

        return False, None

    def unusual_ot_port(self, event):
        dst = event["dst_ip"]
        port = event["dport"]

        if self.get_subnet(dst) == "operational":
            if port not in self.allowed_ot_ports:
                return True, "Unusual port used for OT system"

        return False, None

    def data_exfiltration(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]
        bytes_tx = event.get("bytes", 0)

        if self.get_subnet(src) == "operational" and self.get_subnet(dst) == "user":
            if bytes_tx > 10000:
                return True, "Potential data exfiltration"

        return False, None

    def defender_should_not_initiate(self, event):
        if event["src_ip"] == self.defender_ip and event.get("action") == "CONNECT":
            return True, "Defender initiating traffic"

        return False, None

    def burst_activity(self, event):
        src = event["src_ip"]

        if len(self.event_log[src]) > 20:
            return True, "Burst activity detected"

        return False, None

    # -----------------------------
    # Main classification
    # -----------------------------
    def classify_event(self, event):

        # Apply traffic anomaly detection FIRST (check for behavioral anomalies)
        traffic_anomaly_rules = [
            self.detect_unusual_port_traffic,
            self.detect_high_volume_traffic,
            self.detect_rare_duration_traffic
        ]
        
        for anomaly_rule in traffic_anomaly_rules:
            triggered, reason, confidence = anomaly_rule(event)
            if triggered:
                return "malicious", reason, confidence

        # Apply topology violation rules (check for network policy violations)
        topology_rules = [
            self.violates_topology,
            self.non_user1_lateral_movement,
            self.invalid_ot_access,
            self.invalid_attack_sequence,
            self.port_scan_detected,
            self.excessive_failures,
            self.unusual_ot_port,
            self.data_exfiltration,
            self.defender_should_not_initiate,
            self.burst_activity
        ]

        for rule in topology_rules:
            triggered, reason = rule(event)
            if triggered:
                confidence = 0.85  # High confidence for topology violations
                return "malicious", f"Topology violation: {reason}", confidence

        return "not malicious", "No anomalies detected", 1.0

    # -----------------------------
    # Run on dataset
    # -----------------------------
    def run(self, df):

        results = []

        for _, row in df.iterrows():

            # Convert timestamp
            event = row.to_dict()
            event["timestamp"] = pd.to_datetime(event["timestamp"])

            # Update state BEFORE classification (or after, depending on design)
            self.update_state(event)

            label, reason, confidence = self.classify_event(event)

            results.append({
                **event,
                "prediction": label,
                "reason": reason,
                "confidence": confidence
            })

        return pd.DataFrame(results)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_output_directory(output_dir: str) -> Path:
    """Create output directory if it doesn't exist."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {output_path.absolute()}")
    return output_path


def process_csv_file(input_file: Path, output_file: Path, global_constraints_path: str = None) -> bool:
    """
    Process a single CSV file with the heuristic IDS model.
    
    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file
        global_constraints_path: Path to global_constraints.json for anomaly thresholds
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Read the CSV
        df = pd.read_csv(input_file)
        
        # Create a fresh HeuristicIDS instance for this file with anomaly rules
        ids = HeuristicIDS(global_constraints_path=global_constraints_path)
        result_df = ids.run(df)
        
        # Save to output file
        result_df.to_csv(output_file, index=False)
        
        logger.info(f"✓ {input_file.name}: Processed {len(df)} events")
        return True
        
    except Exception as e:
        logger.error(f"✗ Failed to process {input_file.name}: {str(e)}")
        return False


def process_directory(input_dir: str, output_dir: str, global_constraints_path: str = None) -> tuple:
    """
    Recursively process all CSV files in the input directory.
    
    Args:
        input_dir: Input directory path
        output_dir: Output directory path
        global_constraints_path: Path to global_constraints.json for anomaly thresholds
        
    Returns:
        Tuple of (successful_count, failed_count)
    """
    input_path = Path(input_dir)
    output_path = setup_output_directory(output_dir)
    
    # Validate input directory
    if not input_path.is_dir():
        logger.error(f"Input directory does not exist: {input_path}")
        return 0, 1
    
    # Find all CSV files recursively
    csv_files = list(input_path.rglob("*.csv"))
    
    if not csv_files:
        logger.warning(f"No CSV files found in {input_path}")
        return 0, 0
    
    logger.info(f"Found {len(csv_files)} CSV files to process")
    
    successful = 0
    failed = 0
    
    # Process each CSV file
    for csv_file in sorted(csv_files):
        # Preserve relative directory structure in output
        relative_path = csv_file.relative_to(input_path)
        relative_output_dir = output_path / relative_path.parent
        relative_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create output filename with _predicted suffix
        stem = csv_file.stem
        output_filename = f"{stem}_predicted.csv"
        output_file = relative_output_dir / output_filename
        
        if process_csv_file(csv_file, output_file, global_constraints_path=global_constraints_path):
            successful += 1
        else:
            failed += 1
    
    return successful, failed


def main():
    parser = argparse.ArgumentParser(
        description="Apply heuristic IDS model to all CSV files in a directory"
    )
    parser.add_argument(
        "input_directory",
        help="Input directory containing cleaned CSV files"
    )
    parser.add_argument(
        "--output-dir",
        default="./IDS_heuristic_model_eval",
        help="Output directory for classified CSV files (default: ./IDS_heuristic_model_eval)"
    )
    parser.add_argument(
        "--constraints",
        default="./templates/global_constraints.json",
        help="Path to global_constraints.json for anomaly detection thresholds (default: ./templates/global_constraints.json)"
    )
    
    args = parser.parse_args()
    
    logger.info("=" * 70)
    logger.info("Heuristic IDS Model - Batch Processing")
    logger.info("=" * 70)
    logger.info(f"Constraints file: {args.constraints}")
    logger.info("")
    
    # Process directory
    successful, failed = process_directory(
        args.input_directory,
        args.output_dir,
        global_constraints_path=args.constraints
    )
    
    # Summary
    logger.info("")
    logger.info("=" * 70)
    logger.info(f"Processing complete: {successful} successful, {failed} failed")
    logger.info("=" * 70)
    
    return 0 if failed == 0 else 1


# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    sys.exit(main())