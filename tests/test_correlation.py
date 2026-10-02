import pytest
import time
from flows.flow_key import CanonicalFlowKey, Flow
from ingest.models import PacketMetadata
from features.feature_pipeline import FeaturePipeline
from detection.ensemble import RiskEngine
from detection.correlation_engine import CorrelationEngine, CorrelatedIncident
from alerts.schema import Alert

def make_dummy_alert(alert_id: str, src_ip: str, threat_class: str, severity: str = "HIGH", confidence: float = 0.90, dst_ip: str = "192.168.1.10", dst_port: int = 80) -> Alert:
    return Alert(
        alert_id=alert_id,
        flow_id=f"FLOW-{alert_id}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        threat_class=threat_class,
        severity=severity,
        confidence=confidence,
        evidence={"sample_metric": 123.4},
        model_version="test-v1.0"
    )

def test_same_host_alerts_correlate():
    """Alerts from the same source host within correlation window must group into the same incident."""
    engine = CorrelationEngine(window_seconds=60.0)

    a1 = make_dummy_alert("ALT-001", "172.16.0.50", "PORT_SCAN", "MEDIUM", 0.80)
    a2 = make_dummy_alert("ALT-002", "172.16.0.50", "C2_BEACONING", "HIGH", 0.92)

    inc1, ctx1 = engine.process_alert(a1)
    inc2, ctx2 = engine.process_alert(a2)

    assert inc1.incident_id == inc2.incident_id
    assert len(inc2.alerts) == 2
    assert "PORT_SCAN" in inc2.threat_classes
    assert "C2_BEACONING" in inc2.threat_classes
    assert inc2.correlation_label == "RECON_TO_C2_ACTIVITY"
    assert ctx2["incident_id"] == inc1.incident_id
    assert "ALT-001" in ctx2["related_alerts"]

def test_unrelated_hosts_do_not_correlate():
    """Alerts from different source hosts must produce distinct correlated incidents."""
    engine = CorrelationEngine(window_seconds=60.0)

    a1 = make_dummy_alert("ALT-001", "172.16.0.50", "PORT_SCAN")
    a2 = make_dummy_alert("ALT-002", "192.168.1.99", "PORT_SCAN")

    inc1, _ = engine.process_alert(a1)
    inc2, _ = engine.process_alert(a2)

    assert inc1.incident_id != inc2.incident_id
    assert inc1.host_ip == "172.16.0.50"
    assert inc2.host_ip == "192.168.1.99"
    assert len(engine.active_incidents) == 2

def test_alerts_outside_window_do_not_correlate():
    """Alerts occurring after the correlation window has elapsed must start a new incident."""
    engine = CorrelationEngine(window_seconds=1.0)

    a1 = make_dummy_alert("ALT-001", "172.16.0.50", "PORT_SCAN")
    inc1, _ = engine.process_alert(a1)

    # Fast-forward past window
    inc1.last_seen_epoch -= 5.0

    a2 = make_dummy_alert("ALT-002", "172.16.0.50", "C2_BEACONING")
    inc2, _ = engine.process_alert(a2)

    assert inc1.incident_id != inc2.incident_id
    assert inc2.correlation_label == "ISOLATED_C2_BEACONING"

def test_repeated_same_class_alerts_aggregate_correctly():
    """Repeated alerts of the same threat class must aggregate into a burst pattern."""
    engine = CorrelationEngine(window_seconds=60.0)

    for i in range(1, 6):
        alert = make_dummy_alert(f"ALT-{i:03d}", "10.0.0.15", "PORT_SCAN", dst_port=80+i)
        inc, ctx = engine.process_alert(alert)

    assert len(inc.alerts) == 5
    assert inc.correlation_label == "REPEATED_PORT_SCAN_BURST"
    assert inc.score_breakdown["repetition_weight"] > 0.0
    assert inc.correlation_score >= 0.50

def test_multi_threat_campaign_correlation():
    """A full multi-stage sequence (DGA -> Tunnel -> Exfil) must produce MULTI_STAGE_ATTACK_CAMPAIGN."""
    engine = CorrelationEngine(window_seconds=60.0)

    a1 = make_dummy_alert("ALT-001", "192.168.1.77", "DGA_DOMAIN", "HIGH", 0.89)
    a2 = make_dummy_alert("ALT-002", "192.168.1.77", "DNS_TUNNELING", "CRITICAL", 0.84)
    a3 = make_dummy_alert("ALT-003", "192.168.1.77", "EXFILTRATION", "CRITICAL", 0.95)

    engine.process_alert(a1)
    engine.process_alert(a2)
    inc3, ctx3 = engine.process_alert(a3)

    assert inc3.correlation_label == "MULTI_STAGE_ATTACK_CAMPAIGN"
    assert inc3.severity == "CRITICAL"
    assert inc3.correlation_score >= 0.80
    assert len(inc3.threat_classes) == 3

def test_correlation_does_not_modify_base_threat_class():
    """Correlation layer must never mutate or overwrite individual alert base threat classes."""
    engine = CorrelationEngine(window_seconds=60.0)

    a1 = make_dummy_alert("ALT-001", "172.16.0.50", "PORT_SCAN")
    a2 = make_dummy_alert("ALT-002", "172.16.0.50", "C2_BEACONING")

    _, ctx1 = engine.process_alert(a1)
    _, ctx2 = engine.process_alert(a2)

    assert a1.threat_class == "PORT_SCAN"
    assert a2.threat_class == "C2_BEACONING"
    assert ctx2["correlation_label"] == "RECON_TO_C2_ACTIVITY"

def test_evidence_chain_and_attribution_retention():
    """Every generated alert must contain evidence chain, detector attribution, and valid confidence."""
    pipeline = FeaturePipeline()
    correlation_engine = CorrelationEngine()
    risk_engine = RiskEngine(correlation_engine=correlation_engine)

    # Generate a C2 flow
    pkt0 = PacketMetadata(timestamp=0.0, length=100, src_ip="10.0.0.10", dst_ip="198.51.100.4", src_port=52000, dst_port=443, protocol="TCP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)
    for step in range(1, 10):
        flow.add_packet(PacketMetadata(timestamp=step * 10.0, length=100, src_ip="10.0.0.10", dst_ip="198.51.100.4", src_port=52000, dst_port=443, protocol="TCP"))

    feats = pipeline.extract_features(flow)
    alert = risk_engine.analyze(flow, feats)

    assert alert is not None
    assert 0.0 <= alert.confidence <= 1.0
    assert "evidence_chain" in alert.model_dump()
    assert alert.evidence_chain["flow_summary"]["flow_id"] == flow.flow_id
    assert "detector_attribution" in alert.evidence_chain
    assert alert.correlation is not None
    assert alert.correlation["correlation_label"] == "ISOLATED_C2_BEACONING"

def test_host_risk_dossier_compilation():
    """Host risk dossier must compile multi-incident host threat statistics."""
    engine = CorrelationEngine(window_seconds=60.0)

    a1 = make_dummy_alert("ALT-001", "10.10.10.5", "PORT_SCAN", "MEDIUM", dst_ip="192.168.1.10")
    a2 = make_dummy_alert("ALT-002", "10.10.10.5", "C2_BEACONING", "HIGH", dst_ip="198.51.100.99")

    engine.process_alert(a1)
    engine.process_alert(a2)

    dossier = engine.get_host_dossier("10.10.10.5")
    assert dossier is not None
    assert dossier["host_ip"] == "10.10.10.5"
    assert dossier["total_alerts"] == 2
    assert "192.168.1.10" in dossier["affected_destinations"]
    assert "198.51.100.99" in dossier["affected_destinations"]
    assert dossier["threat_distribution"]["PORT_SCAN"] == 1
    assert dossier["threat_distribution"]["C2_BEACONING"] == 1
    assert dossier["active_incident"]["correlation_label"] == "RECON_TO_C2_ACTIVITY"

def test_passive_boundary_correlation_integrity():
    """Correlation layer must never attempt network I/O, socket opens, or mitigation commands."""
    import socket
    engine = CorrelationEngine(window_seconds=60.0)

    # Process 50 alerts across 10 hosts
    for h in range(10):
        for t in ["PORT_SCAN", "C2_BEACONING", "EXFILTRATION"]:
            alert = make_dummy_alert(f"ALT-{h}-{t}", f"10.0.1.{h}", t)
            engine.process_alert(alert)

    # Verify no sockets were bound or opened by engine
    incidents = engine.get_all_incidents()
    assert len(incidents) == 10
    for inc in incidents:
        assert inc["correlation_label"] in ["MULTI_STAGE_ATTACK_CAMPAIGN", "RECON_TO_C2_ACTIVITY"]
        assert inc["correlation_score"] >= 0.50
