import { useState } from 'react';
import { Play, RefreshCw } from 'lucide-react';
import Sidebar from './components/Sidebar';
import MetricCards from './components/MetricCards';
import TrafficChart from './components/TrafficChart';
import AttackDistribution from './components/AttackDistribution';
import AnomalyGauge from './components/AnomalyGauge';
import AlertsFeed from './components/AlertsFeed';
import AIModels from './components/AIModels';
import ThreatMonitor from './components/ThreatMonitor';
import DataProcessing from './components/DataProcessing';
import Reports from './components/Reports';
import { useThreatData } from './hooks/useThreatData';
import type { DataProfile } from './types';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const {
    events, alerts, models, stats, loading, simulating,
    simulateAndStore, fetchEvents, fetchAlerts, dataProfile, setDataProfile,
  } = useThreatData();
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([fetchEvents(), fetchAlerts()]);
    setRefreshing(false);
  };

  const handleProfileLoaded = (profile: DataProfile) => setDataProfile(profile);

  const viewTitle: Record<string, string> = {
    dashboard: 'Threat Detection Dashboard',
    data: 'Data Processing',
    models: 'AI Detection Models',
    monitor: 'Live Threat Monitor',
    alerts: 'Alert Center',
    reports: 'Threat Reports',
  };

  const viewSubtitle: Record<string, string> = {
    dashboard: 'Real-time AI-powered cyber threat monitoring and analysis',
    data: 'Upload, clean, and analyze network traffic datasets',
    models: 'Machine learning model performance and configuration',
    monitor: 'Live network traffic surveillance and threat detection',
    alerts: 'Manage and investigate detected security threats',
    reports: 'Generate and download threat analysis reports',
  };

  return (
    <div className="min-h-screen bg-gray-950">
      <Sidebar
        currentView={currentView}
        onNavigate={setCurrentView}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activeAlerts={stats.activeAlerts}
      />

      <div
        className="transition-all duration-300"
        style={{ marginLeft: sidebarCollapsed ? 68 : 220 }}
      >
        {/* Top Bar */}
        <header className="sticky top-0 z-40 bg-gray-950/80 backdrop-blur-md border-b border-slate-800/40">
          <div className="flex items-center justify-between px-6 py-3">
            <div>
              <h2 className="text-white text-lg font-bold tracking-tight">{viewTitle[currentView]}</h2>
              <p className="text-slate-500 text-xs mt-0.5">{viewSubtitle[currentView]}</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/50 border border-slate-700/50 rounded-lg text-slate-400 text-xs hover:bg-slate-700/50 transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button
                onClick={() => simulateAndStore(50)}
                disabled={simulating}
                className="flex items-center gap-2 px-4 py-1.5 bg-gradient-to-r from-cyan-600 to-teal-600 rounded-lg text-white text-xs font-medium hover:from-cyan-500 hover:to-teal-500 transition-all disabled:opacity-50 shadow-lg shadow-cyan-500/15"
              >
                <Play className="w-3.5 h-3.5" />
                {simulating ? 'Simulating...' : 'Simulate Traffic'}
              </button>
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="px-6 py-6">
          {currentView === 'dashboard' && (
            <div className="space-y-6 animate-fade-in">
              <MetricCards stats={stats} loading={loading} />

              {stats.activeAlerts > 0 && stats.criticalAlerts > 0 && (
                <div className="alert-critical rounded-xl p-4 neon-border-red">
                  <div className="flex items-center gap-3">
                    <div className="bg-red-500 p-2 rounded-lg">
                      <span className="text-white font-bold text-xs mono">{stats.criticalAlerts}</span>
                    </div>
                    <div>
                      <h4 className="text-red-300 font-bold text-sm">CRITICAL ALERTS ACTIVE</h4>
                      <p className="text-red-400/80 text-xs">Immediate investigation required - {stats.criticalAlerts} critical threat{stats.criticalAlerts !== 1 ? 's' : ''} detected</p>
                    </div>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <TrafficChart events={events} loading={loading} />
                </div>
                <AnomalyGauge events={events} loading={loading} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <AttackDistribution events={events} loading={loading} />
                <AlertsFeed alerts={alerts} loading={loading} showBanners={false} limit={8} />
              </div>
            </div>
          )}

          {currentView === 'data' && (
            <div className="animate-fade-in">
              <DataProcessing dataProfile={dataProfile} loading={loading} onProfileLoaded={handleProfileLoaded} />
            </div>
          )}

          {currentView === 'models' && (
            <div className="animate-fade-in">
              <AIModels models={models} loading={loading} />
            </div>
          )}

          {currentView === 'monitor' && (
            <div className="animate-fade-in">
              <ThreatMonitor events={events} loading={loading} />
            </div>
          )}

          {currentView === 'alerts' && (
            <div className="animate-fade-in space-y-6">
              <MetricCards stats={stats} loading={loading} />
              <AlertsFeed alerts={alerts} loading={loading} showBanners />
            </div>
          )}

          {currentView === 'reports' && (
            <div className="animate-fade-in">
              <Reports events={events} alerts={alerts} loading={loading} />
            </div>
          )}
        </main>

        <footer className="border-t border-slate-800/40 mt-8">
          <div className="px-6 py-3 flex items-center justify-between text-[10px] text-slate-600">
            <span>CyberShield AI Threat Detection System v2.0</span>
            <div className="flex items-center gap-4">
              <span>Edge Functions: Active</span>
              <span>Database: Connected</span>
              <span>Events: {events.length}</span>
              <span>Alerts: {alerts.length}</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default App;
