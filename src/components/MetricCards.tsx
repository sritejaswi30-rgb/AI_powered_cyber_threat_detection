import { ShieldAlert, Activity, AlertTriangle, CheckCircle, TrendingUp, Zap } from 'lucide-react';
import type { DashboardStats } from '../types';

interface MetricCardsProps {
  stats: DashboardStats;
  loading: boolean;
}

export default function MetricCards({ stats, loading }: MetricCardsProps) {
  const cards = [
    { label: 'Total Events', value: stats.totalEvents.toLocaleString(), icon: Activity, accent: 'cyan', glow: 'neon-glow-cyan' },
    { label: 'Threats Detected', value: stats.threatsDetected.toLocaleString(), icon: ShieldAlert, accent: 'red', glow: 'neon-glow-red' },
    { label: 'Active Alerts', value: stats.activeAlerts.toLocaleString(), icon: AlertTriangle, accent: 'amber', glow: 'neon-glow-amber' },
    { label: 'Critical', value: stats.criticalAlerts.toLocaleString(), icon: Zap, accent: 'red', glow: 'neon-glow-red' },
    { label: 'Threat Rate', value: `${(stats.threatRate * 100).toFixed(1)}%`, icon: TrendingUp, accent: 'amber', glow: 'neon-glow-amber' },
    { label: 'Resolved', value: stats.resolvedAlerts.toLocaleString(), icon: CheckCircle, accent: 'emerald', glow: 'neon-glow-emerald' },
  ];

  const accentColors: Record<string, { text: string; bg: string; border: string }> = {
    cyan: { text: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/20' },
    red: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
    amber: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
    emerald: { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
  };

  if (loading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="metric-card animate-pulse">
            <div className="h-3 bg-slate-800 rounded w-2/3 mb-3" />
            <div className="h-7 bg-slate-800 rounded w-1/2" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {cards.map(({ label, value, icon: Icon, accent, glow }) => {
        const c = accentColors[accent];
        return (
          <div key={label} className={`metric-card ${glow} hover:scale-[1.02] transition-transform duration-200`}>
            <div className="flex items-center justify-between mb-3">
              <span className={`text-[11px] font-medium ${c.text} uppercase tracking-wider`}>{label}</span>
              <div className={`p-1.5 rounded-md ${c.bg}`}>
                <Icon className={`w-3.5 h-3.5 ${c.text}`} />
              </div>
            </div>
            <p className={`text-2xl font-bold ${c.text} mono`}>{value}</p>
          </div>
        );
      })}
    </div>
  );
}
