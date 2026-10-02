import pytest
import os
from flows.flow_key import CanonicalFlowKey, Flow
from ingest.models import PacketMetadata
from features.feature_pipeline import FeaturePipeline
from features.baseline_profiler import HostBaselineProfiler
from detection.ddos_detector import DDoSDetector
from detection.scanning_detector import ScanningDetector
from detection.beacon_detector import BeaconDetector
from detection.dga_detector import DGADetector
from detection.dns_tunnel_detector import DNSTunnelDetector
from detection.exfiltration_detector import ExfiltrationDetector
from detection.encrypted_session_detector import EncryptedSessionDetector
from detection.ml_detector import MLDetector
from detection.anomaly_detector import AnomalyDetector
from detection.ensemble import RiskEngine

# --- Regression Tests for UDP Amplification Bug Fix ---

def test_single_udp_dns_query_no_udp_amplification():
    """Test A: 1 UDP DNS packet must NOT trigger UDP Amplification."""
    pipeline = FeaturePipeline()
    detector = DDoSDetector()

    pkt = PacketMetadata(timestamp=100.0, length=110, src_ip="192.168.1.15", dst_ip="8.8.8.8", src_port=54000, dst_port=53, protocol="UDP", dns_query="example.com")
    flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
    feats = pipeline.extract_features(flow)

    res = detector.analyze_flow(feats)
    assert res is None, "Single UDP packet falsely triggered DDoSDetector!"

def test_small_udp_flow_no_udp_amplification():
    """Test B: Small UDP flow (< 5 packets) must NOT trigger UDP Amplification."""
    pipeline = FeaturePipeline()
    detector = DDoSDetector()

    pkt0 = PacketMetadata(timestamp=100.0, length=200, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=5000, dst_port=53, protocol="UDP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)

    for i in range(1, 4):  # Total 4 packets (< 5)
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.01, length=200, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=5000, dst_port=53, protocol="UDP"))

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)
    assert res is None, "Small UDP flow (<5 pkts) falsely triggered DDoSDetector!"

def test_genuine_udp_amplification_triggers_alert():
    """Test C: Genuine UDP Amplification (>= 5 packets, high rate, asymmetric volume) MUST trigger alert."""
    pipeline = FeaturePipeline()
    detector = DDoSDetector()

    pkt0 = PacketMetadata(timestamp=100.0, length=1420, src_ip="198.51.100.77", dst_ip="192.168.1.10", src_port=123, dst_port=55100, protocol="UDP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)

    for i in range(1, 30):  # 30 packets (>= 5)
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.005, length=1420, src_ip="198.51.100.77", dst_ip="192.168.1.10", src_port=123, dst_port=55100, protocol="UDP"))

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class in ["UDP_FLOOD", "UDP_AMPLIFICATION"]
    assert res.severity == "CRITICAL"

# --- Test D: Existing Threat Regression Tests ---

def test_syn_flood_detection():
    pipeline = FeaturePipeline()
    detector = DDoSDetector()

    pkt_syn = PacketMetadata(timestamp=100.0, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02)
    flow = Flow(CanonicalFlowKey.from_packet(pkt_syn), pkt_syn)

    for i in range(1, 100):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.01, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02))

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class == "SYN_FLOOD"
    assert res.severity == "CRITICAL"

def test_beacon_c2_detection():
    pipeline = FeaturePipeline()
    detector = BeaconDetector()

    pkt0 = PacketMetadata(timestamp=0.0, length=100, src_ip="10.0.0.10", dst_ip="198.51.100.4", src_port=52000, dst_port=443, protocol="TCP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)

    for step in range(1, 10):
        flow.add_packet(PacketMetadata(timestamp=step * 10.0, length=100, src_ip="10.0.0.10", dst_ip="198.51.100.4", src_port=52000, dst_port=443, protocol="TCP"))

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class == "C2_BEACONING"

def test_dga_detection():
    pipeline = FeaturePipeline()
    detector = DGADetector()

    pkt = PacketMetadata(timestamp=100.0, length=110, src_ip="192.168.1.15", dst_ip="8.8.8.8", src_port=54000, dst_port=53, protocol="UDP", dns_query="x7z9qkw912mzbv0q81l.biz")
    flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class == "DGA_DOMAIN"

def test_dns_tunnel_detection():
    pipeline = FeaturePipeline()
    detector = DNSTunnelDetector()

    pkt = PacketMetadata(timestamp=100.0, length=180, src_ip="192.168.1.15", dst_ip="8.8.8.8", src_port=54001, dst_port=53, protocol="UDP", dns_query="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.covert-tunnel.org")
    flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class == "DNS_TUNNELING"

def test_encrypted_session_detection():
    pipeline = FeaturePipeline()
    detector = EncryptedSessionDetector()

    pkt0 = PacketMetadata(timestamp=100.0, length=1200, src_ip="192.168.1.15", dst_ip="198.51.100.222", src_port=51100, dst_port=443, protocol="TCP", tls_sni="xzk9012-encrypted-c2-channel.net", tls_version="TLS 1.3")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)

    for i in range(1, 10):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.2, length=1200, src_ip="192.168.1.15", dst_ip="198.51.100.222", src_port=51100, dst_port=443, protocol="TCP", tls_sni="xzk9012-encrypted-c2-channel.net"))

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class == "SUSPICIOUS_ENCRYPTED_SESSION"

def test_port_scan_detection():
    detector = ScanningDetector()

    for p in range(1, 20):
        pkt = PacketMetadata(timestamp=100.0 + p*0.05, length=64, src_ip="172.16.0.44", dst_ip="192.168.1.10", src_port=55000, dst_port=80+p, protocol="TCP", tcp_flags=0x02)
        flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
        feats = FeaturePipeline().extract_features(flow)
        res = detector.analyze_flow(feats)
        if res:
            assert res.threat_class == "PORT_SCAN"
            return

    pytest.fail("Port scan detector did not trigger")

def test_host_scan_detection():
    detector = ScanningDetector()

    for h in range(1, 20):
        pkt = PacketMetadata(timestamp=100.0 + h*0.05, length=64, src_ip="172.16.0.44", dst_ip=f"192.168.1.{10+h}", src_port=55000, dst_port=445, protocol="TCP", tcp_flags=0x02)
        flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
        feats = FeaturePipeline().extract_features(flow)
        res = detector.analyze_flow(feats)
        if res:
            assert res.threat_class == "HOST_SCAN"
            return

    pytest.fail("Host scan detector did not trigger")

def test_exfiltration_detection():
    pipeline = FeaturePipeline()
    detector = ExfiltrationDetector()

    pkt0 = PacketMetadata(timestamp=100.0, length=1460, src_ip="192.168.1.10", dst_ip="203.0.113.88", src_port=49500, dst_port=443, protocol="TCP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)

    for i in range(1, 100):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.01, length=1460, src_ip="192.168.1.10", dst_ip="203.0.113.88", src_port=49500, dst_port=443, protocol="TCP"))

    feats = pipeline.extract_features(flow)
    res = detector.analyze_flow(feats)

    assert res is not None
    assert res.threat_class == "EXFILTRATION"

def test_baseline_profiler():
    profiler = HostBaselineProfiler(min_history_flows=3)

    flow1 = Flow(CanonicalFlowKey.from_packet(PacketMetadata(timestamp=1.0, length=100, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=5000, dst_port=80, protocol="TCP")), PacketMetadata(timestamp=1.0, length=100, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=5000, dst_port=80, protocol="TCP"))
    res1 = profiler.get_baseline_features("10.0.0.5", flow1.fwd_bytes, flow1.fwd_packets)
    assert res1["byte_zscore"] == 0.0

    for i in range(2, 5):
        profiler.get_baseline_features("10.0.0.5", 100, 1)

    res_extreme = profiler.get_baseline_features("10.0.0.5", 500000, 500)
    assert res_extreme["byte_zscore"] > 2.0

def test_ml_detector_loading():
    detector = MLDetector()
    assert detector.name == "MLDetector"
    assert detector.version == "rf-v1.0"

def test_isolation_forest_loading():
    detector = AnomalyDetector()
    assert detector.name == "AnomalyDetector"

def test_end_to_end_pipeline():
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    pkt = PacketMetadata(timestamp=100.0, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02)
    flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
    for i in range(1, 100):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.01, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02))

    feats = pipeline.extract_features(flow)
    alert = engine.analyze(flow, feats)

    assert alert is not None
    assert alert.flow_id == flow.flow_id
    assert alert.severity in ["CRITICAL", "HIGH", "MEDIUM"]
    assert alert.confidence >= 0.65

# --- P1.7 Specificity & Cross-Trigger Regression Tests ---

def test_udp_detector_requires_udp_protocol():
    """DDoSDetector and MLDetector must reject UDP_AMPLIFICATION for non-UDP traffic."""
    pipeline = FeaturePipeline()
    ddos_detector = DDoSDetector()
    ml_detector = MLDetector()

    # Create high-rate TCP flow
    pkt0 = PacketMetadata(timestamp=100.0, length=1420, src_ip="198.51.100.77", dst_ip="192.168.1.10", src_port=123, dst_port=55100, protocol="TCP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)
    for i in range(1, 30):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.005, length=1420, src_ip="198.51.100.77", dst_ip="192.168.1.10", src_port=123, dst_port=55100, protocol="TCP"))

    feats = pipeline.extract_features(flow)
    res_ddos = ddos_detector.analyze_flow(feats)
    res_ml = ml_detector.analyze_flow(feats)

    assert res_ddos is None or res_ddos.threat_class != "UDP_AMPLIFICATION"
    if res_ml is not None:
        assert res_ml.threat_class != "UDP_AMPLIFICATION"

def test_syn_detector_requires_tcp():
    """DDoSDetector and MLDetector must reject SYN_FLOOD for non-TCP traffic."""
    pipeline = FeaturePipeline()
    ddos_detector = DDoSDetector()
    ml_detector = MLDetector()

    # Create high-rate UDP flow with fwd_syn feature spoofed
    pkt0 = PacketMetadata(timestamp=100.0, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=5000, dst_port=80, protocol="UDP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)
    for i in range(1, 100):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.01, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=5000, dst_port=80, protocol="UDP"))

    feats = pipeline.extract_features(flow)
    feats["fwd_syn"] = 100
    feats["syn_ack_ratio"] = 0.0

    res_ddos = ddos_detector.analyze_flow(feats)
    res_ml = ml_detector.analyze_flow(feats)

    assert res_ddos is None or res_ddos.threat_class != "SYN_FLOOD"
    if res_ml is not None:
        assert res_ml.threat_class != "SYN_FLOOD"

def test_syn_flood_does_not_trigger_udp_amplification():
    """SYN flood traffic must NEVER trigger UDP_AMPLIFICATION."""
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    pkt_syn = PacketMetadata(timestamp=100.0, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02)
    flow = Flow(CanonicalFlowKey.from_packet(pkt_syn), pkt_syn)
    for i in range(1, 100):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.01, length=64, src_ip="10.20.4.15", dst_ip="192.168.1.10", src_port=49152, dst_port=80, protocol="TCP", tcp_flags=0x02))

    feats = pipeline.extract_features(flow)
    for det in engine.detectors:
        res = det.analyze_flow(feats)
        if res and res.detected:
            assert res.threat_class != "UDP_AMPLIFICATION", f"Detector {det.name} falsely fired UDP_AMPLIFICATION on SYN flood!"

def test_port_scan_does_not_trigger_udp_amplification():
    """Vertical port scan probe traffic must NEVER trigger UDP_AMPLIFICATION."""
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    for p in range(1, 25):
        pkt = PacketMetadata(timestamp=100.0 + p*0.05, length=64, src_ip="172.16.0.44", dst_ip="192.168.1.10", src_port=55000, dst_port=80+p, protocol="TCP", tcp_flags=0x02)
        flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
        feats = pipeline.extract_features(flow)
        for det in engine.detectors:
            res = det.analyze_flow(feats)
            if res and res.detected:
                assert res.threat_class != "UDP_AMPLIFICATION", f"Detector {det.name} falsely fired UDP_AMPLIFICATION on Port Scan!"

def test_host_scan_does_not_trigger_udp_amplification():
    """Horizontal host scan probe traffic must NEVER trigger UDP_AMPLIFICATION."""
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    for h in range(1, 25):
        pkt = PacketMetadata(timestamp=100.0 + h*0.05, length=64, src_ip="172.16.0.45", dst_ip=f"192.168.1.{10+h}", src_port=55000, dst_port=445, protocol="TCP", tcp_flags=0x02)
        flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
        feats = pipeline.extract_features(flow)
        for det in engine.detectors:
            res = det.analyze_flow(feats)
            if res and res.detected:
                assert res.threat_class != "UDP_AMPLIFICATION", f"Detector {det.name} falsely fired UDP_AMPLIFICATION on Host Scan!"

def test_benign_dns_does_not_trigger_udp_amplification():
    """Single benign DNS query must NOT trigger UDP_AMPLIFICATION."""
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    pkt = PacketMetadata(timestamp=100.0, length=110, src_ip="192.168.1.15", dst_ip="8.8.8.8", src_port=54000, dst_port=53, protocol="UDP", dns_query="google.com")
    flow = Flow(CanonicalFlowKey.from_packet(pkt), pkt)
    feats = pipeline.extract_features(flow)

    for det in engine.detectors:
        res = det.analyze_flow(feats)
        if res and res.detected:
            assert res.threat_class != "UDP_AMPLIFICATION", f"Detector {det.name} falsely fired UDP_AMPLIFICATION on benign DNS!"

def test_normal_udp_does_not_trigger_udp_amplification():
    """Normal multi-packet UDP flow with moderate rate & symmetric volume must NOT trigger UDP_AMPLIFICATION."""
    pipeline = FeaturePipeline()
    engine = RiskEngine()

    pkt0 = PacketMetadata(timestamp=100.0, length=200, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=6000, dst_port=6000, protocol="UDP")
    flow = Flow(CanonicalFlowKey.from_packet(pkt0), pkt0)
    for i in range(1, 10):
        flow.add_packet(PacketMetadata(timestamp=100.0 + i*0.5, length=200, src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=6000, dst_port=6000, protocol="UDP"))

    feats = pipeline.extract_features(flow)
    for det in engine.detectors:
        res = det.analyze_flow(feats)
        if res and res.detected:
            assert res.threat_class != "UDP_AMPLIFICATION", f"Detector {det.name} falsely fired UDP_AMPLIFICATION on normal UDP!"

