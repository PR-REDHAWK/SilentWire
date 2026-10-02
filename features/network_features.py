import numpy as np
from typing import Dict, Any
from flows.flow_key import Flow

def extract_network_features(flow: Flow) -> Dict[str, Any]:
    """Extract general flow, volume, direction, and packet size features."""
    duration = max(flow.duration, 0.001)  # Avoid div by zero
    total_pkts = flow.total_packets
    total_bytes = flow.total_bytes

    sizes = np.array(flow.packet_sizes) if flow.packet_sizes else np.array([0])

    if total_pkts <= 1:
        pkts_per_sec = float(total_pkts)
        bytes_per_sec = float(total_bytes)
    else:
        pkts_per_sec = total_pkts / duration
        bytes_per_sec = total_bytes / duration

    mean_pkt_size = float(np.mean(sizes))
    std_pkt_size = float(np.std(sizes))
    min_pkt_size = int(np.min(sizes))
    max_pkt_size = int(np.max(sizes))

    # Direction ratios
    fwd_bytes = flow.fwd_bytes
    rev_bytes = flow.rev_bytes
    bytes_ratio = fwd_bytes / (rev_bytes + 1.0)
    outbound_asymmetry = (fwd_bytes - rev_bytes) / (total_bytes + 1.0)

    fwd_pkts = flow.fwd_packets
    rev_pkts = flow.rev_packets
    pkts_ratio = fwd_pkts / (rev_pkts + 1.0)

    # TCP Flag ratios
    syn_ack_ratio = (flow.fwd_syn_ack + flow.rev_syn_ack) / (flow.fwd_syn + flow.rev_syn + 1.0)

    return {
        "duration": duration,
        "total_packets": total_pkts,
        "total_bytes": total_bytes,
        "fwd_packets": fwd_pkts,
        "rev_packets": rev_pkts,
        "fwd_bytes": fwd_bytes,
        "rev_bytes": rev_bytes,
        "packets_per_sec": pkts_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "mean_pkt_size": mean_pkt_size,
        "std_pkt_size": std_pkt_size,
        "min_pkt_size": min_pkt_size,
        "max_pkt_size": max_pkt_size,
        "bytes_ratio": bytes_ratio,
        "outbound_asymmetry": outbound_asymmetry,
        "pkts_ratio": pkts_ratio,
        "syn_ack_ratio": syn_ack_ratio,
        "fwd_syn": flow.fwd_syn,
        "rev_syn": flow.rev_syn,
        "fwd_syn_ack": flow.fwd_syn_ack,
        "rev_syn_ack": flow.rev_syn_ack
    }
