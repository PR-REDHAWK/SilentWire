import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional
from detection.base_detector import BaseDetector, DetectionResult
from features.feature_pipeline import FeaturePipeline

CLASS_MAP = {
    0: "BENIGN",
    1: "SYN_FLOOD",
    2: "C2_BEACONING",
    3: "DGA_DOMAIN",
    4: "EXFILTRATION",
    5: "PORT_SCAN",
    6: "DNS_TUNNELING",
    7: "UDP_AMPLIFICATION"
}

SEVERITY_MAP = {
    "SYN_FLOOD": "CRITICAL",
    "UDP_AMPLIFICATION": "CRITICAL",
    "DNS_TUNNELING": "CRITICAL",
    "EXFILTRATION": "CRITICAL",
    "C2_BEACONING": "HIGH",
    "DGA_DOMAIN": "HIGH",
    "PORT_SCAN": "MEDIUM",
    "HOST_SCAN": "MEDIUM"
}

class MLDetector(BaseDetector):
    """
    Supervised Machine Learning Detector loading serialized Random Forest model.
    Evaluates feature vectors using predict_proba() to report honest model probabilities.
    """

    def __init__(self, model_path: str = "models/trained/oracle_shield_rf.joblib"):
        super().__init__(name="MLDetector", version="rf-v1.0")
        self.model_path = os.path.abspath(model_path)
        self.pipeline = FeaturePipeline()
        self.model = None
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
            except Exception:
                self.is_loaded = False
        else:
            self.is_loaded = False

    def analyze_flow(self, flow_features: Dict[str, Any]) -> Optional[DetectionResult]:
        if not self.is_loaded or self.model is None:
            return None

        # Build feature DataFrame matching canonical FEATURE_NAMES ordering and names
        vector = [float(flow_features.get(name, 0.0)) for name in self.pipeline.FEATURE_NAMES]
        X = pd.DataFrame([vector], columns=self.pipeline.FEATURE_NAMES)

        # Execute Random Forest prediction & proba
        probas = self.model.predict_proba(X)[0]
        pred_class_id = int(np.argmax(probas))
        confidence = float(probas[pred_class_id])

        pred_class_name = CLASS_MAP.get(pred_class_id, "UNKNOWN_THREAT")

        if pred_class_name == "BENIGN" or confidence < 0.65:
            return None  # Normal flow or low confidence prediction

        # Protocol & domain semantic validation to prevent physically impossible cross-triggers
        protocol = str(flow_features.get("protocol", "IP")).upper()
        total_pkts = flow_features.get("total_packets", 0)
        dns_count = flow_features.get("dns_query_count", 0)

        # 1. UDP Amplification must be UDP protocol and multi-packet
        if pred_class_name == "UDP_AMPLIFICATION" and (protocol != "UDP" or total_pkts < 5):
            return None

        # 2. SYN Flood must be TCP protocol
        if pred_class_name == "SYN_FLOOD" and protocol != "TCP":
            return None

        # 3. DNS-specific threats must contain DNS queries
        if pred_class_name in ["DGA_DOMAIN", "DNS_TUNNELING"] and dns_count == 0:
            return None

        severity = SEVERITY_MAP.get(pred_class_name, "HIGH")

        # Feature importances from model if available
        feature_importances = {}
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            top_indices = np.argsort(importances)[::-1][:3]
            for idx in top_indices:
                feat_name = self.pipeline.FEATURE_NAMES[idx]
                feature_importances[feat_name] = round(float(importances[idx]), 3)

        return DetectionResult(
            threat_class=pred_class_name,
            detected=True,
            confidence=round(confidence, 2),
            severity=severity,
            evidence={
                "model_predicted_class": pred_class_name,
                "class_probability": round(confidence, 4),
                "detector_source": "SUPERVISED_ML",
                "byte_zscore": flow_features.get("byte_zscore", 0.0),
                "packet_zscore": flow_features.get("packet_zscore", 0.0)
            },
            contributing_features=feature_importances,
            model_version=self.version
        )
