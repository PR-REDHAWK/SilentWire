export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Alert {
  alert_id: string;
  timestamp: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  threat_class: string;
  severity: Severity;
  confidence: number;
  evidence: Record<string, any>;
  contributing_features?: Record<string, number>;
  model_version: string;
  correlated_alerts_count?: number;
  detector_attribution?: Record<string, any>;
  evidence_chain?: Record<string, any>;
  correlation?: {
    incident_id: string;
    correlation_label: string;
    correlation_score: number;
    related_alert_count: number;
    related_alerts: string[];
    related_threats: string[];
    host_risk_severity: Severity;
    correlation_window_seconds: number;
  };
}

export interface CorrelatedIncident {
  incident_id: string;
  host_ip: string;
  correlation_label: string;
  severity: Severity;
  correlation_score: number;
  score_breakdown: Record<string, number>;
  explanation: string;
  first_seen: string;
  last_seen: string;
  duration_seconds: number;
  alert_count: number;
  distinct_threat_count: number;
  threat_classes: string[];
  alert_ids: string[];
  affected_destinations: string[];
  protocols: string[];
  timeline: {
    alert_id: string;
    timestamp: string;
    threat_class: string;
    severity: Severity;
    confidence: number;
    dst_ip: string;
    dst_port: number;
    protocol: string;
    evidence_summary: string[];
  }[];
}

export interface HostRiskDossier {
  host_ip: string;
  total_alerts: number;
  threat_distribution: Record<string, number>;
  severity_counts: Record<Severity, number>;
  affected_destinations: string[];
  first_seen: string;
  last_seen: string;
  active_incident?: CorrelatedIncident | null;
  incident_count: number;
  recent_incidents: CorrelatedIncident[];
}

export interface Statistics {
  status: string;
  ingest_mode: string;
  active_response: boolean;
  uptime_seconds: number;
  flows_per_sec: number;
  packets_per_sec: number;
  total_flows: number;
  total_packets: number;
  total_alerts: number;
  avg_latency_ms: number;
  severity_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  threat_distribution: Record<string, number>;
}
