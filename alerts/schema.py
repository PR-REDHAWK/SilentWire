from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class Alert(BaseModel):
    """Standardized OracleShield Alert Schema."""
    alert_id: str = Field(description="Unique alert ID e.g. ALT-2026-000123")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    threat_class: str
    severity: str
    confidence: float
    evidence: Dict[str, Any]
    contributing_features: Dict[str, float] = Field(default_factory=dict)
    model_version: str = "v1.0"
    correlated_alerts_count: int = 0
    detector_attribution: Dict[str, Any] = Field(default_factory=dict)
    evidence_chain: Dict[str, Any] = Field(default_factory=dict)
    correlation: Optional[Dict[str, Any]] = None
