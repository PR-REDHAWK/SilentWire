from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class ScanningDetector(BaseDetector):
    """
    Reconnaissance & Scanning Detector.
    Tracks Vertical Port Scans (single src -> multi dst ports)
    and Horizontal Host Scans (single src -> multi dst IPs).
    """

    def __init__(self, port_thresh: int = 15, host_thresh: int = 15):
        super().__init__(name="ScanningDetector", version="scan-rule-v1.0")
        self.port_thresh = port_thresh
        self.host_thresh = host_thresh
        self.src_dst_ports: Dict[str, set] = {}
        self.src_dst_hosts: Dict[str, set] = {}

    def reset(self):
        """Clears scanning history tracking."""
        self.src_dst_ports.clear()
        self.src_dst_hosts.clear()

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        src_ip = flow_features.get("initiator_ip")
        dst_ip = flow_features.get("responder_ip")
        dst_port = flow_features.get("responder_port")

        if not src_ip or not dst_port:
            return None

        if src_ip not in self.src_dst_ports:
            self.src_dst_ports[src_ip] = set()
            self.src_dst_hosts[src_ip] = set()

        self.src_dst_ports[src_ip].add(dst_port)
        self.src_dst_hosts[src_ip].add(dst_ip)

        unique_ports = len(self.src_dst_ports[src_ip])
        unique_hosts = len(self.src_dst_hosts[src_ip])

        # Vertical Port Scan (single src targeting many ports on few hosts)
        if unique_ports >= self.port_thresh and unique_hosts < self.host_thresh:
            confidence = min(0.97, 0.70 + (unique_ports / (self.port_thresh * 3.0)) * 0.27)
            return DetectionResult(
                threat_class="PORT_SCAN",
                detected=True,
                confidence=round(confidence, 2),
                severity="MEDIUM",
                evidence={
                    "unique_ports_contacted": unique_ports,
                    "target_host": dst_ip,
                    "scanned_ports_sample": list(self.src_dst_ports[src_ip])[:10]
                },
                contributing_features={
                    "unique_ports_count": 0.70,
                    "connection_attempts": 0.30
                },
                model_version=self.version
            )

        # Horizontal Host Scan
        if unique_hosts >= self.host_thresh:
            confidence = min(0.96, 0.70 + (unique_hosts / (self.host_thresh * 3.0)) * 0.26)
            return DetectionResult(
                threat_class="HOST_SCAN",
                detected=True,
                confidence=round(confidence, 2),
                severity="MEDIUM",
                evidence={
                    "unique_hosts_contacted": unique_hosts,
                    "target_port": dst_port,
                    "scanned_hosts_sample": list(self.src_dst_hosts[src_ip])[:10]
                },
                contributing_features={
                    "unique_hosts_count": 0.75,
                    "connection_attempts": 0.25
                },
                model_version=self.version
            )

        return None
