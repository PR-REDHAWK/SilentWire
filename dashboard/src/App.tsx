import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { KPICards } from './components/KPICards';
import { ThreatCharts } from './components/ThreatCharts';
import { AlertFeed } from './components/AlertFeed';
import { CorrelationIncidentsView } from './components/CorrelationIncidentsView';
import { ThreatInvestigationDrawer } from './components/ThreatInvestigationDrawer';
import { HostRiskDossierModal } from './components/HostRiskDossierModal';
import { Alert, Statistics, CorrelatedIncident } from './types';

export const App: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Statistics | null>(null);
  const [incidents, setIncidents] = useState<CorrelatedIncident[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedHostIp, setSelectedHostIp] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  // Poll REST statistics, alerts & correlation incidents
  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsRes = await fetch('/api/statistics');
        if (statsRes.ok) {
          const statsData = await statsRes.json();
          setStats(statsData);
        }

        const alertsRes = await fetch('/api/alerts?limit=50');
        if (alertsRes.ok) {
          const alertsData = await alertsRes.json();
          setAlerts(alertsData);
        }

        const corrRes = await fetch('/api/correlations?limit=20');
        if (corrRes.ok) {
          const corrData = await corrRes.json();
          setIncidents(corrData);
        }
      } catch (err) {
        console.error("Error fetching telemetry:", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket Live Alert Stream
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
    
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setIsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'NEW_ALERT' && payload.data) {
              const newAlert: Alert = payload.data;
              setAlerts((prev) => [newAlert, ...prev.slice(0, 49)]);
            }
          } catch (e) {
            console.error("Failed to parse WS message:", e);
          }
        };

        ws.onclose = () => {
          setIsConnected(false);
          reconnectTimeout = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          setIsConnected(false);
        };
      } catch (e) {
        setIsConnected(false);
      }
    };

    connect();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col font-sans">
      <Header isConnected={isConnected} />

      <main className="flex-1 p-6 space-y-6 max-w-7xl mx-auto w-full">
        {/* KPI Performance & Threat Summary Cards */}
        <KPICards stats={stats} />

        {/* Multi-Event Correlation & Attack Campaign Visualizer */}
        <CorrelationIncidentsView
          incidents={incidents}
          onSelectHost={(ip) => setSelectedHostIp(ip)}
        />

        {/* Real-time Threat Activity Charts */}
        <ThreatCharts alerts={alerts} stats={stats} />

        {/* Live Alert Feed Stream & Timeline */}
        <AlertFeed
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
          onSelectHost={(ip) => setSelectedHostIp(ip)}
        />
      </main>

      {/* Threat Investigation Drawer Modal */}
      <ThreatInvestigationDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />

      {/* Host Risk Dossier Modal */}
      <HostRiskDossierModal hostIp={selectedHostIp} onClose={() => setSelectedHostIp(null)} />
    </div>
  );
};
export default App;
