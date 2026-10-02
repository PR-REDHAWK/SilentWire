from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult

class DDoSDetector(BaseDetector):
    """
    Volumetric & Protocol DDoS Detector.
    Detects SYN Floods, UDP Floods, and UDP Reflection/Amplification attacks.
    """

    def __init__(self, syn_rate_thresh: float = 50.0, syn_ack_ratio_max: float = 0.2, udp_rate_thresh: float = 100.0, min_udp_packets: int = 5):
        super().__init__(name="DDoSDetector", version="ddos-rule-v1.0")
        self.syn_rate_thresh = syn_rate_thresh
        self.syn_ack_ratio_max = syn_ack_ratio_max
        self.udp_rate_thresh = udp_rate_thresh
        self.min_udp_packets = min_udp_packets

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        duration = flow_features.get("duration", 1.0)
        fwd_syn = flow_features.get("fwd_syn", 0)
        syn_ack_ratio = flow_features.get("syn_ack_ratio", 1.0)
        pkts_per_sec = flow_features.get("packets_per_sec", 0.0)
        total_pkts = flow_features.get("total_packets", 0)
        protocol = str(flow_features.get("protocol", "IP")).upper()

        syn_rate = fwd_syn / max(duration, 0.1)

        # 1. SYN Flood Detection
        if protocol == "TCP" and syn_rate >= self.syn_rate_thresh and syn_ack_ratio <= self.syn_ack_ratio_max:
            confidence = min(0.99, 0.70 + (syn_rate / (self.syn_rate_thresh * 2.0)) * 0.29)
            return DetectionResult(
                threat_class="SYN_FLOOD",
                detected=True,
                confidence=round(confidence, 2),
                severity="CRITICAL",
                evidence={
                    "syn_rate_per_sec": round(syn_rate, 1),
                    "syn_ack_completion_ratio": round(syn_ack_ratio, 3),
                    "fwd_syn_count": fwd_syn,
                    "packets_per_sec": round(pkts_per_sec, 1)
                },
                contributing_features={
                    "fwd_syn_rate": 0.55,
                    "syn_ack_ratio": 0.35,
                    "packets_per_sec": 0.10
                },
                model_version=self.version
            )

        # 2. UDP Flood / Amplification Detection (Requires minimum 5 packets to prevent false positives on single-packet DNS)
        if protocol == "UDP" and total_pkts >= self.min_udp_packets and pkts_per_sec >= self.udp_rate_thresh:
            bytes_ratio = flow_features.get("bytes_ratio", 1.0)
            confidence = min(0.98, 0.75 + (pkts_per_sec / (self.udp_rate_thresh * 3.0)) * 0.23)
            threat = "UDP_AMPLIFICATION" if bytes_ratio > 4.0 or bytes_ratio < 0.25 else "UDP_FLOOD"
            return DetectionResult(
                threat_class=threat,
                detected=True,
                confidence=round(confidence, 2),
                severity="HIGH" if threat == "UDP_FLOOD" else "CRITICAL",
                evidence={
                    "total_packets": total_pkts,
                    "packets_per_sec": round(pkts_per_sec, 1),
                    "bytes_per_sec": round(flow_features.get("bytes_per_sec", 0.0), 1),
                    "bytes_direction_ratio": round(bytes_ratio, 2)
                },
                contributing_features={
                    "packets_per_sec": 0.60,
                    "bytes_per_sec": 0.25,
                    "bytes_ratio": 0.15
                },
                model_version=self.version
            )

        return None
