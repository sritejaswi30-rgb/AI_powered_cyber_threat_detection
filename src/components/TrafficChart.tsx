import { useMemo } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import type { NetworkEvent } from '../types';

interface TrafficChartProps {
  events: NetworkEvent[];
  loading: boolean;
}

export default function TrafficChart({ events, loading }: TrafficChartProps) {
  const data = useMemo(() => {
    const buckets: Record<string, { time: string; normal: number; threats: number }> = {};
    const sorted = [...events].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    sorted.forEach((e) => {
      const t = new Date(e.created_at);
      const key = `${t.getHours().toString().padStart(2, '0')}:${Math.floor(t.getMinutes() / 5) * 5}`;
      if (!buckets[key]) buckets[key] = { time: key, normal: 0, threats: 0 };
      if (e.is_threat) buckets[key].threats++;
      else buckets[key].normal++;
    });
    return Object.values(buckets).slice(-24);
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
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold text-sm">Network Traffic</h3>
        <div className="flex items-center gap-4 text-xs">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span className="text-slate-400">Normal</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
            <span className="text-slate-400">Threats</span>
          </span>
        </div>
      </div>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 5, bottom: 5, left: 0 }}>
            <defs>
              <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={{ stroke: '#1e293b' }} tickLine={false} />
            <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#94a3b8' }}
            />
            <Area type="monotone" dataKey="normal" stroke="#06b6d4" fill="url(#normalGrad)" strokeWidth={2} />
            <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
