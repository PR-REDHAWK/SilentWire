import time
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
from alerts.schema import Alert

SEVERITY_WEIGHTS = {
    "CRITICAL": 0.40,
    "HIGH": 0.30,
    "MEDIUM": 0.20,
    "LOW": 0.10,
    "INFO": 0.05
}

class CorrelatedIncident:
    """
    Represents a correlated security incident tracking multiple temporal alerts
    associated with a specific host/session entity over a sliding time window.
    """

    def __init__(self, incident_id: str, host_ip: str, initial_alert: Alert, window_seconds: float = 60.0):
        self.incident_id = incident_id
        self.host_ip = host_ip
        self.window_seconds = window_seconds
        self.first_seen = initial_alert.timestamp
        self.last_seen = initial_alert.timestamp
        self.first_seen_epoch = time.time()
        self.last_seen_epoch = self.first_seen_epoch

        self.alerts: List[Alert] = [initial_alert]
        self.alert_ids: List[str] = [initial_alert.alert_id]
        self.threat_classes: List[str] = [initial_alert.threat_class]
        self.affected_destinations: Set[str] = {initial_alert.dst_ip}
        self.protocols: Set[str] = {initial_alert.protocol}

        self.correlation_label = "SINGLE_EVENT_OBSERVED"
        self.severity = initial_alert.severity
        self.correlation_score = 0.50
        self.score_breakdown: Dict[str, float] = {}
        self.explanation = ""
        self.recompute()

    def add_alert(self, alert: Alert):
        """Appends a new related alert and updates correlation analytics."""
        self.alerts.append(alert)
        self.alert_ids.append(alert.alert_id)
        self.threat_classes.append(alert.threat_class)
        self.affected_destinations.add(alert.dst_ip)
        self.protocols.add(alert.protocol)
        self.last_seen = alert.timestamp
        self.last_seen_epoch = time.time()
        self.recompute()

    def is_active(self, current_time: float) -> bool:
        """Returns True if the incident has received activity within the correlation window."""
        return (current_time - self.last_seen_epoch) <= self.window_seconds

    def recompute(self):
        """
        Recomputes correlation label, explainable score, and narrative explanation
        using transparent observable criteria.
        """
        distinct_threats = list(dict.fromkeys(self.threat_classes))  # preserved order
        alert_count = len(self.alerts)
        timespan = max(0.1, self.last_seen_epoch - self.first_seen_epoch)

        # Determine highest severity among constituent alerts
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_sev = max(self.alerts, key=lambda a: sev_rank.get(a.severity, 0)).severity
        self.severity = max_sev

        # 1. Pattern & Sequence Classification (Multi-Stage Temporal Sequences)
        has_port_scan = "PORT_SCAN" in distinct_threats
        has_host_scan = "HOST_SCAN" in distinct_threats
        has_recon = has_port_scan or has_host_scan
        has_c2 = "C2_BEACONING" in distinct_threats
        has_dga = "DGA_DOMAIN" in distinct_threats
        has_dns_tunnel = "DNS_TUNNELING" in distinct_threats
        has_exfil = "EXFILTRATION" in distinct_threats
        has_tls_anomaly = "SUSPICIOUS_ENCRYPTED_SESSION" in distinct_threats
        has_syn_flood = "SYN_FLOOD" in distinct_threats
        has_udp_amp = "UDP_AMPLIFICATION" in distinct_threats

        if len(distinct_threats) >= 3 and has_exfil:
            self.correlation_label = "MULTI_STAGE_ATTACK_CAMPAIGN"
            self.explanation = (
                f"Multi-stage attack sequence observed from {self.host_ip} spanning "
                f"{len(distinct_threats)} distinct threat categories culminating in data exfiltration."
            )
        elif has_recon and has_c2:
            self.correlation_label = "RECON_TO_C2_ACTIVITY"
            self.explanation = (
                f"Reconnaissance scanning activity immediately followed by persistent "
                f"C2 beaconing connections from host {self.host_ip}."
            )
        elif has_recon and (has_tls_anomaly or has_exfil):
            self.correlation_label = "RECON_TO_EXFILTRATION"
            self.explanation = (
                f"Reconnaissance scanning followed by outbound encrypted session and data exfiltration transfer."
            )
        elif (has_c2 or has_tls_anomaly) and has_exfil:
            self.correlation_label = "C2_TO_EXFILTRATION"
            self.explanation = (
                f"Command & Control or suspicious encrypted channel followed by high-volume outbound data exfiltration."
            )
        elif has_dga and has_dns_tunnel:
            self.correlation_label = "DGA_AND_DNS_TUNNELING"
            self.explanation = (
                f"Suspicious DNS weaponization: algorithmic domain generation (DGA) coupled with covert DNS tunneling transfer."
            )
        elif has_port_scan and has_host_scan:
            self.correlation_label = "RECON_CAMPAIGN"
            self.explanation = (
                f"Comprehensive reconnaissance campaign combining vertical port scanning and horizontal host subnet enumeration."
            )
        elif has_syn_flood or has_udp_amp:
            self.correlation_label = "VOLUMETRIC_DDOS_EVENT"
            self.explanation = (
                f"High-volume volumetric denial-of-service traffic stream originating from or targeting {self.host_ip}."
            )
        elif alert_count > 1 and len(distinct_threats) == 1:
            self.correlation_label = f"REPEATED_{distinct_threats[0]}_BURST"
            self.explanation = (
                f"Repeated bursts of {distinct_threats[0]} activity ({alert_count} occurrences) within correlation window."
            )
        else:
            self.correlation_label = f"ISOLATED_{distinct_threats[0]}"
            self.explanation = f"Isolated single threat alert ({distinct_threats[0]}) observed for host {self.host_ip}."

        # 2. Transparent & Explainable Correlation Scoring Formula
        # Formula:
        # Score = Base Severity Weight (0.10 - 0.40)
        #       + Threat Diversity Weight (0.00 - 0.25)
        #       + Repetition Factor (0.00 - 0.15)
        #       + Temporal Proximity Factor (0.00 - 0.10)
        #       + Target Focus Factor (0.00 - 0.10)
        base_sev_weight = SEVERITY_WEIGHTS.get(max_sev, 0.20)
        diversity_weight = min(0.25, (len(distinct_threats) - 1) * 0.10) if len(distinct_threats) > 1 else 0.0
        repetition_weight = min(0.15, (alert_count - 1) * 0.03) if alert_count > 1 else 0.0
        
        # Temporal proximity: tighter clustering inside window yields higher correlation confidence
        if alert_count > 1:
            temporal_proximity = 0.10 if timespan <= 15.0 else (0.05 if timespan <= 45.0 else 0.02)
        else:
            temporal_proximity = 0.0

        # Destination focus: concentrated targeting of few critical targets
        target_focus = 0.10 if len(self.affected_destinations) <= 2 else 0.05

        raw_score = base_sev_weight + diversity_weight + repetition_weight + temporal_proximity + target_focus
        self.correlation_score = round(min(0.99, max(0.40, raw_score)), 2)

        self.score_breakdown = {
            "base_severity_weight": round(base_sev_weight, 2),
            "threat_diversity_weight": round(diversity_weight, 2),
            "repetition_weight": round(repetition_weight, 2),
            "temporal_proximity_weight": round(temporal_proximity, 2),
            "target_focus_weight": round(target_focus, 2),
            "final_score": self.correlation_score
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serializes correlated incident for API & WebSocket delivery."""
        return {
            "incident_id": self.incident_id,
            "host_ip": self.host_ip,
            "correlation_label": self.correlation_label,
            "severity": self.severity,
            "correlation_score": self.correlation_score,
            "score_breakdown": self.score_breakdown,
            "explanation": self.explanation,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": round(max(0.1, self.last_seen_epoch - self.first_seen_epoch), 2),
            "alert_count": len(self.alerts),
            "distinct_threat_count": len(set(self.threat_classes)),
            "threat_classes": list(dict.fromkeys(self.threat_classes)),
            "alert_ids": self.alert_ids,
            "affected_destinations": list(self.affected_destinations),
            "protocols": list(self.protocols),
            "timeline": [
                {
                    "alert_id": a.alert_id,
                    "timestamp": a.timestamp,
                    "threat_class": a.threat_class,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "dst_ip": a.dst_ip,
                    "dst_port": a.dst_port,
                    "protocol": a.protocol,
                    "evidence_summary": list(a.evidence.keys())[:4]
                }
                for a in self.alerts
            ]
        }


class CorrelationEngine:
    """
    Lightweight, strictly passive multi-event correlation engine.
    Groups individual flow alerts by host entity and sliding temporal window,
    identifying multi-stage threat campaigns without performing any active network actions.
    """

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.active_incidents: Dict[str, CorrelatedIncident] = {}  # host_ip -> CorrelatedIncident
        self.closed_incidents: List[CorrelatedIncident] = []
        self.incident_counter = 0

    def reset(self):
        """Clears all correlation state."""
        self.active_incidents.clear()
        self.closed_incidents.clear()
        self.incident_counter = 0

    def process_alert(self, alert: Alert) -> Tuple[CorrelatedIncident, Dict[str, Any]]:
        """
        Processes an incoming alert, associating it with an active host incident
        or creating a new correlated incident entity.
        Returns the incident and the enriched correlation context dict to attach to the alert.
        """
        now = time.time()
        host_ip = alert.src_ip

        # Prune expired incidents
        self._prune_expired_incidents(now)

        if host_ip in self.active_incidents:
            incident = self.active_incidents[host_ip]
            if incident.is_active(now):
                incident.add_alert(alert)
            else:
                # Close expired incident and start new one
                self.closed_incidents.append(incident)
                self.incident_counter += 1
                incident = CorrelatedIncident(
                    incident_id=f"INC-2026-{self.incident_counter:04d}",
                    host_ip=host_ip,
                    initial_alert=alert,
                    window_seconds=self.window_seconds
                )
                self.active_incidents[host_ip] = incident
        else:
            self.incident_counter += 1
            incident = CorrelatedIncident(
                incident_id=f"INC-2026-{self.incident_counter:04d}",
                host_ip=host_ip,
                initial_alert=alert,
                window_seconds=self.window_seconds
            )
            self.active_incidents[host_ip] = incident

        # Build correlation context for the alert
        correlation_context = {
            "incident_id": incident.incident_id,
            "correlation_label": incident.correlation_label,
            "correlation_score": incident.correlation_score,
            "related_alert_count": len(incident.alerts),
            "related_alerts": [a_id for a_id in incident.alert_ids if a_id != alert.alert_id],
            "related_threats": list(set(incident.threat_classes)),
            "host_risk_severity": incident.severity,
            "correlation_window_seconds": self.window_seconds
        }

        return incident, correlation_context

    def _prune_expired_incidents(self, current_time: float):
        """Closes incidents that have exceeded the correlation window."""
        expired_hosts = []
        for host, inc in self.active_incidents.items():
            if not inc.is_active(current_time):
                expired_hosts.append(host)
                self.closed_incidents.append(inc)

        for host in expired_hosts:
            del self.active_incidents[host]

        # Keep closed incidents buffer capped
        if len(self.closed_incidents) > 200:
            self.closed_incidents = self.closed_incidents[-200:]

    def get_active_incidents(self) -> List[Dict[str, Any]]:
        """Returns all currently active correlated incidents."""
        self._prune_expired_incidents(time.time())
        return [inc.to_dict() for inc in self.active_incidents.values()]

    def get_all_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent active and closed incidents."""
        self._prune_expired_incidents(time.time())
        all_inc = list(self.active_incidents.values()) + list(reversed(self.closed_incidents))
        return [inc.to_dict() for inc in all_inc[:limit]]

    def get_host_dossier(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Compiles a complete risk dossier for a specific host."""
        matching = [inc for inc in list(self.active_incidents.values()) + self.closed_incidents if inc.host_ip == host_ip]
        if not matching:
            return None

        all_alerts: List[Alert] = []
        all_dests = set()
        for inc in matching:
            all_alerts.extend(inc.alerts)
            all_dests.update(inc.affected_destinations)

        threat_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in all_alerts:
            threat_counts[a.threat_class] = threat_counts.get(a.threat_class, 0) + 1
            if a.severity in sev_counts:
                sev_counts[a.severity] += 1

        active_inc = self.active_incidents.get(host_ip)

        return {
            "host_ip": host_ip,
            "total_alerts": len(all_alerts),
            "threat_distribution": threat_counts,
            "severity_counts": sev_counts,
            "affected_destinations": list(all_dests),
            "first_seen": matching[0].first_seen,
            "last_seen": matching[-1].last_seen,
            "active_incident": active_inc.to_dict() if active_inc else None,
            "incident_count": len(matching),
            "recent_incidents": [inc.to_dict() for inc in matching[-5:]]
        }

# Global singleton correlation engine instance
global_correlation_engine = CorrelationEngine(window_seconds=60.0)
