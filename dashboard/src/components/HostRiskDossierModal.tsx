import React, { useEffect, useState } from 'react';
import { HostRiskDossier } from '../types';
import { X, Server, ShieldAlert, AlertTriangle, Target, Activity, Clock, CheckCircle2 } from 'lucide-react';

interface HostRiskDossierModalProps {
  hostIp: string | null;
  onClose: () => void;
}

export const HostRiskDossierModal: React.FC<HostRiskDossierModalProps> = ({ hostIp, onClose }) => {
  const [dossier, setDossier] = useState<HostRiskDossier | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    if (!hostIp) {
      setDossier(null);
      return;
    }

    const fetchDossier = async () => {
      setLoading(true);
      try {
        const res = await fetch(`/api/hosts/${hostIp}/risk`);
        if (res.ok) {
          const data = await res.json();
          setDossier(data);
        }
      } catch (err) {
        console.error("Failed to load host dossier:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchDossier();
  }, [hostIp]);

  if (!hostIp) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-3xl bg-gray-900 border border-gray-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 flex items-center justify-between bg-gray-950">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-xl">
              <Server className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white font-mono">{hostIp}</h2>
                <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-950 text-purple-400 border border-purple-800">
                  Host Risk Dossier
                </span>
              </div>
              <p className="text-xs text-gray-400">Aggregated multi-event threat profile & correlation history</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white bg-gray-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 font-mono">
          {loading ? (
            <div className="py-12 text-center text-gray-400 text-xs">Compiling host intelligence dossier...</div>
          ) : !dossier ? (
            <div className="py-12 text-center text-gray-400 text-xs">No threat activity recorded for host {hostIp}.</div>
          ) : (
            <>
              {/* Summary Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                  <span className="text-gray-500 block text-[10px]">TOTAL ALERTS</span>
                  <span className="text-xl font-bold text-white">{dossier.total_alerts}</span>
                </div>
                <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                  <span className="text-gray-500 block text-[10px]">CRITICAL SEVERITY</span>
                  <span className="text-xl font-bold text-red-400">{dossier.severity_counts.CRITICAL || 0}</span>
                </div>
                <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                  <span className="text-gray-500 block text-[10px]">AFFECTED TARGETS</span>
                  <span className="text-xl font-bold text-cyan-400">{dossier.affected_destinations.length}</span>
                </div>
                <div className="bg-gray-950 p-3 rounded-lg border border-gray-800">
                  <span className="text-gray-500 block text-[10px]">CORRELATED CAMPAIGNS</span>
                  <span className="text-xl font-bold text-purple-400">{dossier.incident_count}</span>
                </div>
              </div>

              {/* Active Incident Banner */}
              {dossier.active_incident && (
                <div className="bg-purple-950/30 border border-purple-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-purple-400 flex items-center gap-1.5">
                      <Activity className="w-4 h-4" /> Active Attack Campaign: {dossier.active_incident.correlation_label}
                    </span>
                    <span className="text-xs font-bold text-cyan-400">
                      Score: {Math.round(dossier.active_incident.correlation_score * 100)}%
                    </span>
                  </div>
                  <p className="text-xs text-gray-300 font-sans leading-relaxed">
                    {dossier.active_incident.explanation}
                  </p>
                </div>
              )}

              {/* Threat Distribution */}
              <div className="bg-gray-950 border border-gray-800 rounded-xl p-4">
                <h3 className="text-xs font-semibold uppercase text-gray-400 mb-3 flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-orange-400" /> Threat Class Distribution
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                  {Object.entries(dossier.threat_distribution).map(([threat, count]) => (
                    <div key={threat} className="p-2.5 bg-gray-900 rounded border border-gray-800 flex justify-between items-center">
                      <span className="text-gray-300 font-semibold">{threat}</span>
                      <span className="px-2 py-0.5 rounded bg-gray-800 text-cyan-400 font-bold">{count}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Affected Destinations */}
              <div className="bg-gray-950 border border-gray-800 rounded-xl p-4">
                <h3 className="text-xs font-semibold uppercase text-gray-400 mb-3 flex items-center gap-1.5">
                  <Target className="w-4 h-4 text-cyan-400" /> Targeted / Contacted Destinations
                </h3>
                <div className="flex flex-wrap gap-2 text-xs">
                  {dossier.affected_destinations.map((dst) => (
                    <span key={dst} className="px-2.5 py-1 rounded bg-gray-900 border border-gray-800 text-purple-400 font-bold">
                      {dst}
                    </span>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
