from typing import List, Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult
from detection.ddos_detector import DDoSDetector
from detection.scanning_detector import ScanningDetector
from detection.beacon_detector import BeaconDetector
from detection.dga_detector import DGADetector
from detection.dns_tunnel_detector import DNSTunnelDetector
from detection.exfiltration_detector import ExfiltrationDetector
from detection.encrypted_session_detector import EncryptedSessionDetector
from detection.ml_detector import MLDetector
from detection.anomaly_detector import AnomalyDetector
from alerts.generator import AlertGenerator
from alerts.schema import Alert
from flows.flow_key import Flow
from detection.correlation_engine import CorrelationEngine, global_correlation_engine

class RiskEngine:
    """
    Central Ensemble Risk Engine combining Rule Detectors, Supervised ML Detector,
    Dedicated Encrypted Session Detector, Unsupervised Isolation Forest Anomaly Detector,
    and Multi-Event Host Correlation Layer.
    """

    def __init__(self, correlation_engine: Optional[CorrelationEngine] = None):
        self.detectors: List[BaseDetector] = [
            DDoSDetector(),
            ScanningDetector(),
            BeaconDetector(),
            DGADetector(),
            DNSTunnelDetector(),
            ExfiltrationDetector(),
            EncryptedSessionDetector(),
            MLDetector(),
            AnomalyDetector()
        ]
        self.alert_generator = AlertGenerator()
        self.correlation_engine = correlation_engine or global_correlation_engine

    def register_detector(self, detector: BaseDetector):
        self.detectors.append(detector)

    def analyze(self, flow: Flow, flow_features: Dict[str, Any]) -> Optional[Alert]:
        results: List[DetectionResult] = []

        for detector in self.detectors:
            try:
                res = detector.analyze_flow(flow_features)
                if res and res.detected:
                    results.append(res)
            except Exception:
                pass

        if not results:
            return None

        # Sort results by severity priority, specific threat over generic anomaly, and confidence
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        results.sort(
            key=lambda r: (
                severity_rank.get(r.severity, 0),
                1 if r.threat_class != "UNKNOWN_ANOMALY" else 0,
                r.confidence
            ),
            reverse=True
        )

        top_result = results[0]

        # Generate alert with full evidence chain
        alert = self.alert_generator.generate(flow, top_result, all_results=results, flow_features=flow_features)
        if alert and self.correlation_engine:
            incident, correlation_ctx = self.correlation_engine.process_alert(alert)
            alert.correlation = correlation_ctx
            alert.correlated_alerts_count = correlation_ctx.get("related_alert_count", 1)

        return alert
