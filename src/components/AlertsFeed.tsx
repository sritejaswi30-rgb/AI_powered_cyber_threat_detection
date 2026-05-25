import { AlertTriangle, ShieldAlert, Zap, Info, Clock } from 'lucide-react';
import type { ThreatAlert } from '../types';

interface AlertsFeedProps {
  alerts: ThreatAlert[];
  loading: boolean;
  showBanners?: boolean;
  limit?: number;
}

const severityConfig = {
  critical: { icon: Zap, cls: 'alert-critical', text: 'text-red-400', badge: 'bg-red-500', label: 'CRITICAL' },
  high: { icon: ShieldAlert, cls: 'alert-high', text: 'text-orange-400', badge: 'bg-orange-500', label: 'HIGH' },
  medium: { icon: AlertTriangle, cls: 'alert-medium', text: 'text-amber-400', badge: 'bg-amber-500', label: 'MEDIUM' },
  low: { icon: Info, cls: 'alert-low', text: 'text-emerald-400', badge: 'bg-emerald-500', label: 'LOW' },
};

function timeAgo(date: string): string {
  const diff = Date.now() - new Date(date).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function AlertsFeed({ alerts, loading, showBanners = true, limit }: AlertsFeedProps) {
  const display = limit ? alerts.slice(0, limit) : alerts;

  const criticals = alerts.filter((a) => a.severity === 'critical' && !a.resolved);
  const highs = alerts.filter((a) => a.severity === 'high' && !a.resolved);

  if (loading) {
    return (
      <div className="cyber-card p-5">
        <div className="h-4 bg-slate-800 rounded w-1/4 mb-4" />
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-16 bg-slate-800/50 rounded-lg mb-2 animate-pulse" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Critical/High warning banners */}
      {showBanners && criticals.length > 0 && (
        <div className="alert-critical rounded-xl p-4 neon-border-red animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="bg-red-500 p-2 rounded-lg">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <div>
              <h4 className="text-red-300 font-bold text-sm">CRITICAL THREAT DETECTED</h4>
              <p className="text-red-400/80 text-xs">{criticals.length} critical alert{criticals.length !== 1 ? 's' : ''} require immediate attention</p>
            </div>
            <span className="ml-auto mono text-red-400 text-sm font-bold">{criticals.length}</span>
          </div>
        </div>
      )}

      {showBanners && highs.length > 0 && (
        <div className="alert-high rounded-xl p-4 neon-border-amber animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="bg-orange-500 p-2 rounded-lg">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <h4 className="text-orange-300 font-bold text-sm">HIGH SEVERITY ALERTS</h4>
              <p className="text-orange-400/80 text-xs">{highs.length} high-severity threat{highs.length !== 1 ? 's' : ''} active</p>
            </div>
            <span className="ml-auto mono text-orange-400 text-sm font-bold">{highs.length}</span>
          </div>
        </div>
      )}

      {/* Safe status if no threats */}
      {showBanners && criticals.length === 0 && highs.length === 0 && alerts.length > 0 && (
        <div className="alert-low rounded-xl p-4 neon-border-emerald animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500 p-2 rounded-lg">
              <Info className="w-5 h-5 text-white" />
            </div>
            <div>
              <h4 className="text-emerald-300 font-bold text-sm">SYSTEM SECURE</h4>
              <p className="text-emerald-400/80 text-xs">No critical or high-severity threats detected</p>
            </div>
          </div>
        </div>
      )}

      {/* Alert list */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold text-sm">Alert History</h3>
          <span className="text-xs text-slate-500 mono">{display.length} alerts</span>
        </div>
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {display.length === 0 ? (
            <div className="text-center py-8 text-slate-500 text-sm">No alerts detected</div>
          ) : (
            display.map((alert) => {
              const config = severityConfig[alert.severity] || severityConfig.low;
              const Icon = config.icon;
              return (
                <div key={alert.id} className={`${config.cls} rounded-lg p-3 transition-all duration-200 hover:scale-[1.005]`}>
                  <div className="flex items-start gap-3">
                    <div className={`${config.badge} p-1.5 rounded-md mt-0.5`}>
                      <Icon className="w-3.5 h-3.5 text-white" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`${config.text} text-xs font-bold`}>{config.label}</span>
                        <span className="text-slate-600 text-xs">|</span>
                        <span className="text-slate-300 text-xs font-medium capitalize">{alert.threat_category.replace('_', ' ')}</span>
                      </div>
                      <p className="text-slate-300 text-xs leading-relaxed truncate">{alert.description}</p>
                      <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500">
                        <span className="mono">{alert.source_ip}</span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {timeAgo(alert.created_at)}
                        </span>
                        <span>Confidence: {(alert.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                    {alert.resolved && (
                      <span className="text-[10px] text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded-full">Resolved</span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
