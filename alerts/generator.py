import time
from typing import Dict, Optional, Tuple, List, Any
from alerts.schema import Alert
from detection.base_detector import DetectionResult
from flows.flow_key import Flow

class AlertGenerator:
    """Generates standardized Alert models with deduplication logic."""

    def __init__(self, dedup_window_seconds: float = 10.0):
        self.dedup_window = dedup_window_seconds
        self.recent_alerts: Dict[Tuple[str, str, str], float] = {}  # (src_ip, dst_ip, threat_class) -> timestamp
        self.alert_counter = 0

    def generate(self, flow: Flow, result: DetectionResult, all_results: Optional[List[DetectionResult]] = None, flow_features: Optional[Dict[str, Any]] = None) -> Optional[Alert]:
        now = time.time()
        dedup_key = (flow.initiator_ip, flow.responder_ip, result.threat_class)

        # Deduplication check
        if dedup_key in self.recent_alerts:
            last_time = self.recent_alerts[dedup_key]
            if (now - last_time) < self.dedup_window:
                return None  # Suppress duplicate alert

        self.recent_alerts[dedup_key] = now
        self.alert_counter += 1

        alert_id = f"ALT-2026-{self.alert_counter:06d}"

        # 1. Compile Detector Attribution
        attribution: Dict[str, Any] = {}
        if all_results:
            for r in all_results:
                if "rule" in r.model_version:
                    attribution["rule_detector"] = f"{r.threat_class} ({r.confidence*100:.0f}%, {r.model_version})"
                elif "rf" in r.model_version:
                    attribution["supervised_ml"] = f"{r.threat_class} ({r.confidence*100:.0f}%, {r.model_version})"
                elif "isoforest" in r.model_version:
                    attribution["isolation_forest"] = f"{r.threat_class} ({r.confidence*100:.0f}%, {r.model_version})"
                elif "tls" in r.model_version:
                    attribution["encrypted_session_detector"] = f"{r.threat_class} ({r.confidence*100:.0f}%, {r.model_version})"
                elif "dga" in r.model_version or "dns" in r.model_version:
                    attribution["dns_detector"] = f"{r.threat_class} ({r.confidence*100:.0f}%, {r.model_version})"

        if not attribution:
            attribution["primary_detector"] = f"{result.threat_class} ({result.model_version})"

        # 2. Compile Complete Evidence Chain (Flow -> Features -> Detector -> Evidence -> Confidence -> Severity)
        feat_dict = flow_features or {}
        evidence_chain = {
            "flow_summary": {
                "flow_id": flow.flow_id,
                "protocol": flow.protocol,
                "src": f"{flow.initiator_ip}:{flow.initiator_port}",
                "dst": f"{flow.responder_ip}:{flow.responder_port}",
                "total_packets": flow.total_packets,
                "total_bytes": flow.total_bytes,
                "duration_seconds": round(flow.duration, 3)
            },
            "extracted_features_sample": {
                "packets_per_sec": round(feat_dict.get("packets_per_sec", 0.0), 1),
                "bytes_per_sec": round(feat_dict.get("bytes_per_sec", 0.0), 1),
                "bytes_ratio": round(feat_dict.get("bytes_ratio", 1.0), 2),
                "periodicity_score": round(feat_dict.get("periodicity_score", 0.0), 3),
                "max_dns_entropy": round(feat_dict.get("max_dns_entropy", 0.0), 2),
                "sni_entropy": round(feat_dict.get("sni_entropy", 0.0), 2),
                "byte_zscore": round(feat_dict.get("byte_zscore", 0.0), 2)
            },
            "detector_attribution": attribution,
            "detector_evidence": result.evidence,
            "confidence_assessment": {
                "confidence_score": result.confidence,
                "severity_classification": result.severity,
                "model_version": result.model_version
            }
        }

        return Alert(
            alert_id=alert_id,
            flow_id=flow.flow_id,
            src_ip=flow.initiator_ip,
            dst_ip=flow.responder_ip,
            src_port=flow.initiator_port,
            dst_port=flow.responder_port,
            protocol=flow.protocol,
            threat_class=result.threat_class,
            severity=result.severity,
            confidence=result.confidence,
            evidence=result.evidence,
            contributing_features=result.contributing_features,
            model_version=result.model_version,
            detector_attribution=attribution,
            evidence_chain=evidence_chain
        )
