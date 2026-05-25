import { useMemo } from 'react';
import { Radio, Clock, ArrowRight } from 'lucide-react';
import type { NetworkEvent } from '../types';

interface ThreatMonitorProps {
  events: NetworkEvent[];
  loading: boolean;
}

const severityColors = {
  critical: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', dot: 'bg-red-400' },
  high: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', dot: 'bg-orange-400' },
  medium: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', dot: 'bg-amber-400' },
  low: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', dot: 'bg-emerald-400' },
};

function getSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score > 0.8) return 'critical';
  if (score > 0.6) return 'high';
  if (score > 0.4) return 'medium';
  return 'low';
}

export default function ThreatMonitor({ events, loading }: ThreatMonitorProps) {
  const recentEvents = useMemo(
    () => [...events].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()).slice(0, 25),
    [events]
  );

  const liveStats = useMemo(() => {
    const last5min = events.filter((e) => Date.now() - new Date(e.created_at).getTime() < 300000);
    return {
      eventsPerMin: last5min.length > 0 ? (last5min.length / 5).toFixed(1) : '0',
      threatsLast5Min: last5min.filter((e) => e.is_threat).length,
      topSourceIP: getMostFrequent(events.map((e) => e.source_ip)),
      topDestPort: getMostFrequent(events.map((e) => String(e.destination_port))),
    };
  }, [events]);

  function getMostFrequent(arr: string[]): string {
    const counts: Record<string, number> = {};
    arr.forEach((v) => (counts[v] = (counts[v] || 0) + 1));
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || '-';
  }

  if (loading) {
    return (
      <div className="space-y-6">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="cyber-card p-5 animate-pulse">
            <div className="h-4 bg-slate-800 rounded w-1/4 mb-4" />
            <div className="space-y-3">{Array.from({ length: 4 }).map((_, j) => (<div key={j} className="h-12 bg-slate-800/50 rounded" />))}</div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Live Stats Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Events/min', value: liveStats.eventsPerMin, color: 'cyan' },
          { label: 'Threats (5min)', value: String(liveStats.threatsLast5Min), color: 'red' },
          { label: 'Top Source', value: liveStats.topSourceIP, color: 'amber' },
          { label: 'Top Dst Port', value: liveStats.topDestPort, color: 'cyan' },
        ].map((s) => (
          <div key={s.label} className="metric-card">
            <span className={`text-[10px] font-medium uppercase tracking-wider text-${s.color}-400`}>{s.label}</span>
            <p className={`text-sm font-bold text-${s.color}-400 mono mt-1 truncate`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Live Monitor Panel */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold text-sm flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            Live Network Monitor
          </h3>
          <span className="flex items-center gap-1.5 text-xs text-emerald-400">
            <span className="w-2 h-2 bg-emerald-400 rounded-full" style={{ animation: 'pulse-dot 1.5s ease-in-out infinite' }} />
            Receiving
          </span>
        </div>

        {/* Header */}
        <div className="grid grid-cols-8 gap-2 text-[10px] text-slate-600 uppercase tracking-wider font-medium pb-2 border-b border-slate-800 mb-2">
          <span>Source IP</span>
          <span>Dest IP</span>
          <span>Port</span>
          <span>Protocol</span>
          <span>Size</span>
          <span>Threat Level</span>
          <span>Attack</span>
          <span>Time</span>
        </div>

        {/* Events */}
        <div className="space-y-1 max-h-[480px] overflow-y-auto">
          {recentEvents.map((e) => {
            const sev = e.is_threat ? getSeverity(e.anomaly_score) : 'low';
            const cfg = severityColors[sev];
            return (
              <div
                key={e.id}
                className={`grid grid-cols-8 gap-2 items-center py-2 px-1 rounded-lg text-xs transition-all duration-200 hover:bg-slate-800/30 ${e.is_threat ? cfg.bg : ''}`}
              >
                <span className="mono text-slate-300 truncate">{e.source_ip}</span>
                <span className="flex items-center gap-1 mono text-slate-300 truncate">
                  <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
                  {e.destination_ip}
                </span>
                <span className="mono text-slate-400">{e.destination_port}</span>
                <span className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-300 text-[10px] inline-block w-fit">{e.protocol}</span>
                <span className="mono text-slate-400">{e.packet_size}B</span>
                <span className="flex items-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} style={e.is_threat ? { animation: 'pulse-dot 1.5s ease-in-out infinite' } : {}} />
                  <span className={`${cfg.text} font-bold uppercase text-[10px]`}>{sev}</span>
                </span>
                <span className="text-slate-400 text-[10px] truncate capitalize">{e.is_threat ? e.threat_type.replace('_', ' ') : '-'}</span>
                <span className="text-slate-500 text-[10px] flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(e.created_at).toLocaleTimeString()}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
