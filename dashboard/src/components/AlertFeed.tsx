import React from 'react';
import { Alert, Severity } from '../types';
import { ShieldAlert, AlertTriangle, Info, Search, ArrowRight } from 'lucide-react';

interface AlertFeedProps {
  alerts: Alert[];
  onSelectAlert: (alert: Alert) => void;
  onSelectHost?: (hostIp: string) => void;
}

export const AlertFeed: React.FC<AlertFeedProps> = ({ alerts, onSelectAlert, onSelectHost }) => {
  const [viewMode, setViewMode] = React.useState<'TABLE' | 'TIMELINE'>('TABLE');

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500/20 text-red-400 border border-red-500/40 flex items-center gap-1 w-max">
            <ShieldAlert className="w-3 h-3" /> CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/40 flex items-center gap-1 w-max">
            <AlertTriangle className="w-3 h-3" /> HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center gap-1 w-max">
            <AlertTriangle className="w-3 h-3" /> MEDIUM
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40 flex items-center gap-1 w-max">
            <Info className="w-3 h-3" /> LOW
          </span>
        );
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-200 tracking-wide uppercase flex items-center gap-2">
            Live Threat Stream & Timeline
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              {alerts.length} Events
            </span>
          </h2>
          <p className="text-xs text-gray-400">Click any threat to launch the Threat Investigation Drawer or click host to inspect dossier</p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setViewMode('TABLE')}
            className={`px-3 py-1 rounded-lg border transition-colors ${
              viewMode === 'TABLE'
                ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40 font-bold'
                : 'bg-gray-950 text-gray-400 border-gray-800 hover:text-white'
            }`}
          >
            Table View
          </button>
          <button
            onClick={() => setViewMode('TIMELINE')}
            className={`px-3 py-1 rounded-lg border transition-colors ${
              viewMode === 'TIMELINE'
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/40 font-bold'
                : 'bg-gray-950 text-gray-400 border-gray-800 hover:text-white'
            }`}
          >
            Chronological Timeline
          </button>
        </div>
      </div>

      {viewMode === 'TABLE' ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-950 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Threat Class</th>
                <th className="py-3 px-4">Flow Connection</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Correlation Label</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-gray-500">
                    No active threat detections observed. Passive link monitoring...
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    onClick={() => onSelectAlert(alert)}
                    className="hover:bg-gray-800/60 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4">{getSeverityBadge(alert.severity)}</td>
                    <td className="py-3 px-4 font-bold text-gray-200">{alert.threat_class}</td>
                    <td className="py-3 px-4 text-gray-300">
                      <span
                        onClick={(e) => {
                          e.stopPropagation();
                          if (onSelectHost) onSelectHost(alert.src_ip);
                        }}
                        className="text-cyan-400 font-semibold hover:underline"
                      >
                        {alert.src_ip}:{alert.src_port}
                      </span>
                      <ArrowRight className="w-3 h-3 inline mx-1.5 text-gray-500" />
                      <span className="text-purple-400">{alert.dst_ip}:{alert.dst_port}</span>
                    </td>
                    <td className="py-3 px-4 text-gray-400">{alert.protocol}</td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="bg-cyan-400 h-full rounded-full"
                            style={{ width: `${Math.round(alert.confidence * 100)}%` }}
                          />
                        </div>
                        <span className="text-gray-300 font-semibold">{Math.round(alert.confidence * 100)}%</span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      {alert.correlation ? (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-300 border border-purple-800 font-bold">
                          {alert.correlation.correlation_label}
                        </span>
                      ) : (
                        <span className="text-gray-500 text-[11px]">STANDALONE</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-gray-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button className="px-2.5 py-1 rounded bg-gray-800 group-hover:bg-cyan-500 text-gray-300 group-hover:text-black transition-colors text-[11px]">
                        <Search className="w-3 h-3 inline mr-1" /> View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      ) : (
        /* Chronological Timeline View */
        <div className="space-y-3 font-mono text-xs">
          {alerts.map((alert, idx) => (
            <div
              key={alert.alert_id}
              onClick={() => onSelectAlert(alert)}
              className="p-3.5 bg-gray-950 border border-gray-800 rounded-xl hover:border-cyan-500/50 cursor-pointer transition-colors flex items-center justify-between"
            >
              <div className="flex items-center gap-4">
                <span className="text-gray-500 font-bold w-20">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </span>
                <div className="h-6 w-0.5 bg-gray-800" />
                {getSeverityBadge(alert.severity)}
                <span className="font-bold text-gray-100 text-sm">{alert.threat_class}</span>
                <span className="text-gray-400 hidden md:inline">
                  from <span className="text-cyan-400 font-semibold">{alert.src_ip}</span> to <span className="text-purple-400 font-semibold">{alert.dst_ip}:{alert.dst_port}</span>
                </span>
              </div>
              <div className="flex items-center gap-3">
                {alert.correlation && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-300 border border-purple-800 font-bold">
                    {alert.correlation.correlation_label}
                  </span>
                )}
                <span className="text-cyan-400 font-semibold">{Math.round(alert.confidence * 100)}%</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
