from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from detection.correlation_engine import global_correlation_engine
from backend.api.alerts import in_memory_alerts

router = APIRouter(tags=["Correlation & Host Risk"])

@router.get("/api/correlations")
async def get_correlated_incidents(limit: int = Query(50, ge=1, le=200)):
    """Retrieve multi-event correlated incidents across monitored hosts."""
    return global_correlation_engine.get_all_incidents(limit=limit)

@router.get("/api/correlations/{incident_id}")
async def get_incident_by_id(incident_id: str):
    """Retrieve detailed correlation incident by ID."""
    incidents = global_correlation_engine.get_all_incidents(limit=200)
    for inc in incidents:
        if inc.get("incident_id") == incident_id:
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

@router.get("/api/hosts/{host_ip}/risk")
async def get_host_risk_dossier(host_ip: str):
    """Retrieve comprehensive risk profile and correlated timeline for a specific host."""
    dossier = global_correlation_engine.get_host_dossier(host_ip)
    if dossier:
        return dossier

    # Fallback to in-memory alerts matching host_ip
    matching = [a for a in in_memory_alerts if a.get("src_ip") == host_ip]
    if not matching:
        raise HTTPException(status_code=404, detail=f"Host {host_ip} has no recorded threat activity")

    threat_counts = {}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    dests = set()
    for a in matching:
        t = a.get("threat_class", "UNKNOWN")
        s = a.get("severity", "LOW")
        threat_counts[t] = threat_counts.get(t, 0) + 1
        if s in sev_counts:
            sev_counts[s] += 1
        dests.add(a.get("dst_ip"))

    return {
        "host_ip": host_ip,
        "total_alerts": len(matching),
        "threat_distribution": threat_counts,
        "severity_counts": sev_counts,
        "affected_destinations": list(dests),
        "first_seen": matching[-1].get("timestamp"),
        "last_seen": matching[0].get("timestamp"),
        "active_incident": None,
        "incident_count": 0,
        "recent_incidents": []
    }

@router.get("/api/timeline")
async def get_alert_timeline(limit: int = Query(100, ge=1, le=500)):
    """Retrieve a unified chronological timeline of alerts and correlation milestones."""
    events = []
    for a in in_memory_alerts[:limit]:
        events.append({
            "event_type": "ALERT",
            "id": a.get("alert_id"),
            "timestamp": a.get("timestamp"),
            "src_ip": a.get("src_ip"),
            "dst_ip": a.get("dst_ip"),
            "threat_class": a.get("threat_class"),
            "severity": a.get("severity"),
            "confidence": a.get("confidence"),
            "correlation_label": a.get("correlation", {}).get("correlation_label") if a.get("correlation") else None,
            "incident_id": a.get("correlation", {}).get("incident_id") if a.get("correlation") else None,
            "evidence": a.get("evidence", {})
        })
    return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
