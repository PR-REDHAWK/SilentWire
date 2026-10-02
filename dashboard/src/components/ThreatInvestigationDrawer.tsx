import React from 'react';
import { Alert } from '../types';
import { X, ShieldAlert, Cpu, Terminal, Layers, ArrowRight, CheckCircle2 } from 'lucide-react';

interface ThreatInvestigationDrawerProps {
  alert: Alert | null;
  onClose: () => void;
}

export const ThreatInvestigationDrawer: React.FC<ThreatInvestigationDrawerProps> = ({ alert, onClose }) => {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-2xl bg-gray-900 border-l border-gray-800 h-full flex flex-col shadow-2xl overflow-y-auto">
        {/* Drawer Header */}
        <div className="px-6 py-5 border-b border-gray-800 flex items-center justify-between bg-gray-950/80 sticky top-0 z-10 backdrop-blur-md">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-red-500/10 border border-red-500/30 rounded-lg">
              <ShieldAlert className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-wide">{alert.threat_class}</h2>
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                  {alert.severity}
                </span>
              </div>
              <p className="text-xs text-gray-400 font-mono">Alert ID: {alert.alert_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white bg-gray-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6 flex-1">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Confidence Score</span>
              <span className="text-lg font-bold text-cyan-400">{Math.round(alert.confidence * 100)}%</span>
            </div>
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Detector Model</span>
              <span className="text-sm font-semibold text-purple-400 truncate block">{alert.model_version}</span>
            </div>
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Flow ID</span>
              <span className="text-sm font-semibold text-gray-200">{alert.flow_id}</span>
            </div>
            <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-500 block">Timestamp</span>
              <span className="text-xs font-semibold text-gray-300">
                {new Date(alert.timestamp).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {/* 5-Tuple Network Flow Details */}
          <div className="bg-gray-950 border border-gray-800 rounded-xl p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-cyan-400" /> Flow 5-Tuple Identifier
            </h3>
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-800 font-mono text-xs gap-3">
              <div>
                <span className="text-gray-500 text-[10px] block">SOURCE ENDPOINT (INITIATOR)</span>
                <span className="text-cyan-400 font-bold text-sm">{alert.src_ip}:{alert.src_port}</span>
              </div>
              <ArrowRight className="w-5 h-5 text-gray-600 hidden md:block" />
              <div>
                <span className="text-gray-500 text-[10px] block">DESTINATION ENDPOINT</span>
                <span className="text-purple-400 font-bold text-sm">{alert.dst_ip}:{alert.dst_port}</span>
              </div>
              <div className="text-right">
                <span className="text-gray-500 text-[10px] block">PROTOCOL</span>
                <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-200 font-bold text-xs">
                  {alert.protocol}
                </span>
              </div>
            </div>
          </div>

          {/* Detector Attribution Breakdown */}
          {alert.detector_attribution && Object.keys(alert.detector_attribution).length > 0 && (
            <div className="bg-gray-950 border border-gray-800 rounded-xl p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-cyan-400" /> Ensemble Detector Attribution
              </h3>
              <div className="space-y-2 font-mono text-xs">
                {Object.entries(alert.detector_attribution).map(([det, val]) => (
                  <div key={det} className="p-2.5 bg-gray-900 rounded border border-gray-800 flex justify-between items-center">
                    <span className="text-gray-400 capitalize">{det.replace(/_/g, ' ')}:</span>
                    <span className="text-cyan-400 font-semibold">{String(val)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Multi-Event Correlation Context */}
          {alert.correlation && (
            <div className="bg-purple-950/20 border border-purple-500/30 rounded-xl p-4 font-mono text-xs">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-purple-400 mb-3 flex items-center gap-1.5">
                <Layers className="w-4 h-4" /> Multi-Event Correlation Context
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3">
                <div className="p-2 bg-gray-900 rounded border border-gray-800">
                  <span className="text-gray-500 text-[10px] block">CORRELATED INCIDENT</span>
                  <span className="text-white font-bold">{alert.correlation.incident_id}</span>
                </div>
                <div className="p-2 bg-gray-900 rounded border border-gray-800">
                  <span className="text-gray-500 text-[10px] block">CORRELATION LABEL</span>
                  <span className="text-purple-400 font-bold">{alert.correlation.correlation_label}</span>
                </div>
              </div>
              {alert.correlation.related_threats && alert.correlation.related_threats.length > 0 && (
                <div>
                  <span className="text-gray-500 text-[10px] block mb-1">CORRELATED THREAT SEQUENCE:</span>
                  <div className="flex flex-wrap gap-1">
                    {alert.correlation.related_threats.map((th) => (
                      <span key={th} className="px-2 py-0.5 bg-gray-900 border border-gray-800 text-gray-200 rounded text-[11px]">
                        {th}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Supporting Evidence Breakdown */}
          <div className="bg-gray-950 border border-gray-800 rounded-xl p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-emerald-400" /> Empirical Feature Evidence
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 font-mono text-xs">
              {Object.entries(alert.evidence).map(([key, val]) => (
                <div key={key} className="p-2.5 bg-gray-900 rounded border border-gray-800 flex justify-between items-center">
                  <span className="text-gray-400 capitalize">{key.replace(/_/g, ' ')}:</span>
                  <span className="text-emerald-400 font-bold">{String(val)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Model Feature Attributions */}
          {alert.contributing_features && Object.keys(alert.contributing_features).length > 0 && (
            <div className="bg-gray-950 border border-gray-800 rounded-xl p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-purple-400" /> Model Feature Importance
              </h3>
              <div className="space-y-2 font-mono text-xs">
                {Object.entries(alert.contributing_features).map(([feat, importance]) => (
                  <div key={feat}>
                    <div className="flex justify-between text-[11px] mb-1 text-gray-300">
                      <span>{feat}</span>
                      <span className="text-purple-400 font-bold">{Math.round(importance * 100)}%</span>
                    </div>
                    <div className="w-full bg-gray-900 rounded-full h-1.5 overflow-hidden">
                      <div
                        className="bg-purple-500 h-full rounded-full"
                        style={{ width: `${Math.round(importance * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Passive Architecture Note */}
          <div className="p-4 bg-blue-950/30 border border-blue-500/20 rounded-xl text-xs text-blue-300 flex items-start gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold block">Passive Enclave Intelligence</span>
              Suspicious encrypted-session detection using observable TLS/QUIC metadata and flow behavior without decrypting application payloads. Zero return packets transmitted to monitored network.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
