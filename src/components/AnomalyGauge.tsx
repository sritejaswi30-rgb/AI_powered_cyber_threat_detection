import { useMemo } from 'react';
import type { NetworkEvent } from '../types';

interface AnomalyGaugeProps {
  events: NetworkEvent[];
  loading: boolean;
}

export default function AnomalyGauge({ events, loading }: AnomalyGaugeProps) {
  const avgScore = useMemo(() => {
    if (events.length === 0) return 0;
    return events.reduce((s, e) => s + e.anomaly_score, 0) / events.length;
  }, [events]);

  const pct = avgScore * 100;
  const color = pct > 75 ? '#ef4444' : pct > 50 ? '#f59e0b' : pct > 25 ? '#06b6d4' : '#10b981';
  const label = pct > 75 ? 'CRITICAL' : pct > 50 ? 'WARNING' : pct > 25 ? 'ELEVATED' : 'NORMAL';

  if (loading) {
    return (
      <div className="cyber-card p-5">
        <div className="h-4 bg-slate-800 rounded w-1/3 mb-4" />
        <div className="h-48 bg-slate-800/50 rounded animate-pulse" />
      </div>
    );
  }

  return (
    <div className="cyber-card p-5">
      <h3 className="text-white font-semibold text-sm mb-4">Anomaly Score Gauge</h3>
      <div className="flex flex-col items-center py-2">
        {/* Gauge arc */}
        <div className="relative w-48 h-48">
          <svg viewBox="0 0 200 200" className="w-full h-full -rotate-90">
            {/* Background arc */}
            <circle
              cx="100" cy="100" r="85"
              fill="none"
              stroke="#1e293b"
              strokeWidth="12"
              strokeDasharray="400 534"
              strokeLinecap="round"
            />
            {/* Filled arc */}
            <circle
              cx="100" cy="100" r="85"
              fill="none"
              stroke={color}
              strokeWidth="12"
              strokeDasharray={`${(pct / 100) * 400} 534`}
              strokeLinecap="round"
              style={{
                filter: `drop-shadow(0 0 8px ${color}40)`,
                transition: 'stroke-dasharray 1s ease, stroke 0.5s ease',
              }}
            />
          </svg>
          {/* Center text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-bold mono" style={{ color }}>{pct.toFixed(1)}%</span>
            <span className="text-xs font-bold mt-1 tracking-widest" style={{ color }}>{label}</span>
          </div>
        </div>

        {/* Score breakdown */}
        <div className="w-full mt-4 grid grid-cols-3 gap-2 text-center">
          {[
            { range: '0-25%', label: 'Normal', c: '#10b981' },
            { range: '25-50%', label: 'Elevated', c: '#06b6d4' },
            { range: '50-75%', label: 'Warning', c: '#f59e0b' },
          ].map(({ range, label: lbl, c }) => (
            <div key={range} className="bg-slate-900/50 rounded-lg py-2 px-1">
              <span className="text-[10px] block" style={{ color: c }}>{range}</span>
              <span className="text-[11px] text-slate-400">{lbl}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
