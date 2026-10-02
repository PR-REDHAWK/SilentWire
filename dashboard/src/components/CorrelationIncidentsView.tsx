import React from 'react';
import { CorrelatedIncident, Severity } from '../types';
import { Network, ShieldAlert, AlertTriangle, ArrowRight, Clock, Target, Activity } from 'lucide-react';

interface CorrelationIncidentsViewProps {
  incidents: CorrelatedIncident[];
  onSelectHost: (hostIp: string) => void;
}

export const CorrelationIncidentsView: React.FC<CorrelationIncidentsViewProps> = ({ incidents, onSelectHost }) => {
  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40">LOW</span>;
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex flex-col space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-gray-200 tracking-wide uppercase flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            Multi-Event Host Correlation & Attack Campaigns
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-purple-950 text-purple-400 border border-purple-800">
              {incidents.length} Active Incidents
            </span>
          </h2>
          <p className="text-xs text-gray-400">
            Temporal multi-event sequences correlated passively by host entity and sliding window
          </p>
        </div>
      </div>

      {incidents.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-gray-500 bg-gray-950/50 rounded-lg border border-gray-800/60">
          No multi-event correlation campaigns detected. Passive link monitoring...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {incidents.map((inc) => (
            <div
              key={inc.incident_id}
              className="bg-gray-950 border border-gray-800 rounded-xl p-4 flex flex-col justify-between space-y-3 hover:border-cyan-500/50 transition-colors"
            >
              {/* Header */}
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white font-mono">{inc.correlation_label}</span>
                    {getSeverityBadge(inc.severity)}
                  </div>
                  <div className="flex items-center gap-2 mt-1 text-xs text-gray-400">
                    <span className="text-gray-500">Host:</span>
                    <button
                      onClick={() => onSelectHost(inc.host_ip)}
                      className="font-mono text-cyan-400 font-bold hover:underline"
                    >
                      {inc.host_ip}
                    </button>
                    <span className="text-gray-600">•</span>
                    <span className="font-mono text-gray-400">{inc.incident_id}</span>
                  </div>
                </div>
                <div className="text-right font-mono">
                  <span className="text-[10px] text-gray-500 block">CORRELATION SCORE</span>
                  <span className="text-base font-bold text-purple-400">
                    {Math.round(inc.correlation_score * 100)}%
                  </span>
                </div>
              </div>

              {/* Explanation Narrative */}
              <p className="text-xs text-gray-300 bg-gray-900/80 p-2.5 rounded-lg border border-gray-800/80 font-sans leading-relaxed">
                {inc.explanation}
              </p>

              {/* Attack Sequence Flow Visualizer */}
              <div>
                <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider block mb-1.5 flex items-center gap-1">
                  <Activity className="w-3 h-3 text-cyan-400" /> Correlated Threat Timeline
                </span>
                <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                  {inc.threat_classes.map((t, idx) => (
                    <React.Fragment key={idx}>
                      <span className="px-2 py-0.5 bg-gray-800 text-gray-200 rounded border border-gray-700 font-semibold">
                        {t}
                      </span>
                      {idx < inc.threat_classes.length - 1 && (
                        <ArrowRight className="w-3 h-3 text-gray-500 shrink-0" />
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              {/* Footer Meta */}
              <div className="pt-2 border-t border-gray-800/60 flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span className="flex items-center gap-1">
                  <Target className="w-3 h-3 text-gray-500" />
                  {inc.affected_destinations.length} Target(s) Contacted
                </span>
                <span className="flex items-center gap-1 text-gray-500">
                  <Clock className="w-3 h-3" />
                  Span: {inc.duration_seconds}s ({inc.alert_count} events)
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
