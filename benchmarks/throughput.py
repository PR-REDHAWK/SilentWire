import time
import os
import sys
import psutil
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from simulator.traffic_generator import TrafficGenerator
from flows.flow_manager import FlowManager
from features.feature_pipeline import FeaturePipeline
from detection.ensemble import RiskEngine
from detection.correlation_engine import CorrelationEngine
from flows.flow_key import CanonicalFlowKey, Flow

def run_core_detection_microbenchmark(iterations: int = 1000):
    print("\n==================================================================")
    print("      OracleShield Core Detection Engine Microbenchmark")
    print("  (Evaluates Feature Extraction + ML/Rule Detection + Correlation)")
    print("==================================================================")
    
    generator = TrafficGenerator()
    pipeline = FeaturePipeline()
    correlation_engine = CorrelationEngine(window_seconds=60.0)
    risk_engine = RiskEngine(correlation_engine=correlation_engine)
    process = psutil.Process(os.getpid())

    # Pre-generate diverse flow objects
    sample_flows = []
    # SYN flood flow
    syn_pkts = generator.generate_syn_flood(100.0, 1.0, 50.0)
    f_syn = Flow(CanonicalFlowKey.from_packet(syn_pkts[0]), syn_pkts[0])
    for p in syn_pkts[1:]: f_syn.add_packet(p)
    sample_flows.append(f_syn)

    # UDP Amp flow
    udp_pkts = generator.generate_udp_amplification(100.0)
    f_udp = Flow(CanonicalFlowKey.from_packet(udp_pkts[0]), udp_pkts[0])
    for p in udp_pkts[1:]: f_udp.add_packet(p)
    sample_flows.append(f_udp)

    # C2 Beacon flow
    c2_pkts = generator.generate_c2_beacon(100.0)
    f_c2 = Flow(CanonicalFlowKey.from_packet(c2_pkts[0]), c2_pkts[0])
    for p in c2_pkts[1:]: f_c2.add_packet(p)
    sample_flows.append(f_c2)

    # Benign flow
    benign_pkts = generator.generate_benign_flow(100.0)
    f_benign = Flow(CanonicalFlowKey.from_packet(benign_pkts[0]), benign_pkts[0])
    for p in benign_pkts[1:]: f_benign.add_packet(p)
    sample_flows.append(f_benign)

    feat_latencies = []
    det_latencies = []
    total_latencies = []
    alerts_generated = 0

    t_start = time.perf_counter()
    for i in range(iterations):
        flow = sample_flows[i % len(sample_flows)]
        
        t0 = time.perf_counter()
        feats = pipeline.extract_features(flow)
        t1 = time.perf_counter()
        alert = risk_engine.analyze(flow, feats)
        t2 = time.perf_counter()

        feat_latencies.append((t1 - t0) * 1000.0)
        det_latencies.append((t2 - t1) * 1000.0)
        total_latencies.append((t2 - t0) * 1000.0)
        if alert:
            alerts_generated += 1

    t_total = time.perf_counter() - t_start
    throughput = iterations / t_total
    mem_mb = process.memory_info().rss / (1024 * 1024)
    cpu = process.cpu_percent(interval=0.1)

    print(f"Iterations:             {iterations} flows evaluated")
    print(f"Core Engine Throughput: {throughput:,.1f} flows/sec")
    print(f"Feature Extraction Lat: Mean: {np.mean(feat_latencies):.4f} ms | P50: {np.percentile(feat_latencies, 50):.4f} ms | P99: {np.percentile(feat_latencies, 99):.4f} ms")
    print(f"Detection + Corr Lat:   Mean: {np.mean(det_latencies):.4f} ms | P50: {np.percentile(det_latencies, 50):.4f} ms | P99: {np.percentile(det_latencies, 99):.4f} ms")
    print(f"Total Engine Latency:   Mean: {np.mean(total_latencies):.4f} ms | P50: {np.percentile(total_latencies, 50):.4f} ms | P99: {np.percentile(total_latencies, 99):.4f} ms")
    print(f"Resource Consumption:   CPU: {cpu:.1f}% | Memory RSS: {mem_mb:.1f} MB | Alerts: {alerts_generated}")
    print("------------------------------------------------------------------")


def run_end_to_end_benchmark(flow_counts: list = [500, 1000, 2000]):
    print("\n==================================================================")
    print("      OracleShield End-to-End Streaming Pipeline Benchmark")
    print("  (Ingestion -> Flow State -> Features -> Detectors -> Correlation)")
    print("==================================================================")

    generator = TrafficGenerator()
    pipeline = FeaturePipeline()
    process = psutil.Process(os.getpid())

    for target_count in flow_counts:
        flow_manager = FlowManager(window_seconds=1.0)
        correlation_engine = CorrelationEngine(window_seconds=60.0)
        risk_engine = RiskEngine(correlation_engine=correlation_engine)

        latencies = []
        alerts_raised = 0
        total_packets = 0

        # Generate combined synthetic stream
        packets = []
        for i in range(target_count):
            if i % 6 == 0:
                packets.extend(generator.generate_syn_flood(timestamp=time.time(), duration_seconds=0.1, rate=200))
            elif i % 8 == 0:
                packets.extend(generator.generate_c2_beacon(timestamp=time.time(), count=4, interval=0.1))
            else:
                packets.extend(generator.generate_benign_flow(timestamp=time.time()))

        t_start = time.perf_counter()
        for pkt in packets:
            t0 = time.perf_counter()
            emitted_flows = flow_manager.process_packet(pkt)
            total_packets += 1

            for flow in emitted_flows:
                feats = pipeline.extract_features(flow)
                alert = risk_engine.analyze(flow, feats)
                if alert:
                    alerts_raised += 1

            t_end = time.perf_counter()
            latencies.append((t_end - t0) * 1000.0)

        t_total = max(time.perf_counter() - t_start, 0.001)

        input_rate = len(packets) / t_total
        p50 = np.percentile(latencies, 50)
        p95 = np.percentile(latencies, 95)
        p99 = np.percentile(latencies, 99)

        cpu_usage = process.cpu_percent(interval=0.1)
        mem_mb = process.memory_info().rss / (1024 * 1024)

        print(f"Target Flows: {target_count:4d} | Stream Ingestion: {input_rate:7.1f} pkts/s (Total Pkts: {total_packets})")
        print(f"  Per-Packet Latency:  Mean: {np.mean(latencies):.4f} ms | P50: {p50:.4f} ms | P95: {p95:.4f} ms | P99: {p99:.4f} ms")
        print(f"  System Resources:    CPU: {cpu_usage:.1f}% | Memory: {mem_mb:.1f} MB | Correlated Incidents: {len(correlation_engine.get_all_incidents())}")
        print("------------------------------------------------------------------")

if __name__ == "__main__":
    run_core_detection_microbenchmark(iterations=1000)
    run_end_to_end_benchmark(flow_counts=[500, 1000])

