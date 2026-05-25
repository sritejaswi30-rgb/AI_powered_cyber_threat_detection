import { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import type { NetworkEvent } from '../types';

interface AttackDistributionProps {
  events: NetworkEvent[];
  loading: boolean;
}

const COLORS: Record<string, string> = {
  normal: '#06b6d4',
  ddos: '#ef4444',
  intrusion: '#f97316',
  port_scan: '#f59e0b',
  brute_force: '#a855f7',
  data_exfiltration: '#ec4899',
  anomaly: '#64748b',
  malware_c2: '#dc2626',
};

export default function AttackDistribution({ events, loading }: AttackDistributionProps) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {};
    events.forEach((e) => {
      const type = e.is_threat ? e.threat_type || 'anomaly' : 'normal';
      counts[type] = (counts[type] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name: name.replace('_', ' '), value, color: COLORS[name] || '#64748b' }))
      .sort((a, b) => b.value - a.value);
  }, [events]);

  if (loading) {
    return (
      <div className="cyber-card p-5">
        <div className="h-4 bg-slate-800 rounded w-1/3 mb-4" />
        <div className="h-56 bg-slate-800/50 rounded animate-pulse" />
      </div>
    );
  }

  return (
    <div className="cyber-card p-5">
      <h3 className="text-white font-semibold text-sm mb-4">Attack Type Distribution</h3>
      <div className="flex items-center gap-4">
        <div className="w-1/2 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={2}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#94a3b8' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="w-1/2 space-y-2">
          {data.map(({ name, value, color }) => (
            <div key={name} className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: color }} />
              <span className="text-xs text-slate-400 capitalize flex-1 truncate">{name}</span>
              <span className="text-xs text-slate-300 mono font-medium">{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
