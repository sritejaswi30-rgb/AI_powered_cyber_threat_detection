import { useMemo } from 'react';
import { Download, FileText, BarChart3 } from 'lucide-react';
import type { NetworkEvent, ThreatAlert } from '../types';

interface ReportsProps {
  events: NetworkEvent[];
  alerts: ThreatAlert[];
  loading: boolean;
}

function toCSV(headers: string[], rows: string[][]): string {
  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
}

function downloadCSV(filename: string, csv: string) {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Reports({ events, alerts, loading }: ReportsProps) {
  const reportStats = useMemo(() => {
    const threats = events.filter((e) => e.is_threat);
    const byType: Record<string, number> = {};
    threats.forEach((e) => {
      const t = e.threat_type || 'unknown';
      byType[t] = (byType[t] || 0) + 1;
    });
    const bySeverity: Record<string, number> = {};
    alerts.forEach((a) => {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
    });
    const byProtocol: Record<string, number> = {};
    events.forEach((e) => {
      byProtocol[e.protocol] = (byProtocol[e.protocol] || 0) + 1;
    });
    const avgAnomaly = events.length > 0 ? events.reduce((s, e) => s + e.anomaly_score, 0) / events.length : 0;
    const topSourceIPs: Record<string, number> = {};
    threats.forEach((e) => {
      topSourceIPs[e.source_ip] = (topSourceIPs[e.source_ip] || 0) + 1;
    });
    return { byType, bySeverity, byProtocol, avgAnomaly, topSourceIPs, totalThreats: threats.length };
  }, [events, alerts]);

  const downloadEventsReport = () => {
    const headers = ['timestamp', 'source_ip', 'destination_ip', 'protocol', 'port', 'packet_size', 'is_threat', 'threat_type', 'anomaly_score'];
    const rows = events.map((e) => [
      new Date(e.created_at).toISOString(),
      e.source_ip,
      e.destination_ip,
      e.protocol,
      String(e.destination_port),
      String(e.packet_size),
      String(e.is_threat),
      e.threat_type,
      e.anomaly_score.toFixed(4),
    ]);
    downloadCSV(`threat_events_${new Date().toISOString().slice(0, 10)}.csv`, toCSV(headers, rows));
  };

  const downloadAlertsReport = () => {
    const headers = ['timestamp', 'severity', 'category', 'source_ip', 'confidence', 'resolved', 'description'];
    const rows = alerts.map((a) => [
      new Date(a.created_at).toISOString(),
      a.severity,
      a.threat_category,
      a.source_ip,
      a.confidence.toFixed(4),
      String(a.resolved),
      `"${a.description.replace(/"/g, '""')}"`,
    ]);
    downloadCSV(`threat_alerts_${new Date().toISOString().slice(0, 10)}.csv`, toCSV(headers, rows));
  };

  const downloadFullReport = () => {
    const lines: string[] = [
      'CyberShield AI Threat Detection Report',
      `Generated: ${new Date().toISOString()}`,
      '',
      '--- SUMMARY ---',
      `Total Events Analyzed: ${events.length}`,
      `Threats Detected: ${reportStats.totalThreats}`,
      `Threat Rate: ${events.length > 0 ? ((reportStats.totalThreats / events.length) * 100).toFixed(1) : 0}%`,
      `Average Anomaly Score: ${(reportStats.avgAnomaly * 100).toFixed(1)}%`,
      '',
      '--- THREAT TYPES ---',
      ...Object.entries(reportStats.byType).map(([t, c]) => `${t}: ${c}`),
      '',
      '--- SEVERITY DISTRIBUTION ---',
      ...Object.entries(reportStats.bySeverity).map(([s, c]) => `${s}: ${c}`),
      '',
      '--- TOP MALICIOUS SOURCE IPs ---',
      ...Object.entries(reportStats.topSourceIPs).slice(0, 10).map(([ip, c]) => `${ip}: ${c} threats`),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `full_report_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="cyber-card p-8 animate-pulse">
        <div className="h-6 bg-slate-800 rounded w-1/3 mb-6" />
        <div className="space-y-4">{Array.from({ length: 4 }).map((_, i) => (<div key={i} className="h-20 bg-slate-800/50 rounded" />))}</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Download cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={downloadEventsReport}
          className="cyber-card p-6 text-left hover:scale-[1.02] transition-transform group"
          disabled={events.length === 0}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 bg-cyan-500/10 rounded-lg flex items-center justify-center group-hover:bg-cyan-500/20 transition-colors">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h4 className="text-white text-sm font-semibold">Events Report</h4>
              <p className="text-[11px] text-slate-500">Network event data with anomaly scores</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-medium">
            <Download className="w-3.5 h-3.5" />
            Download CSV ({events.length} rows)
          </div>
        </button>

        <button
          onClick={downloadAlertsReport}
          className="cyber-card p-6 text-left hover:scale-[1.02] transition-transform group"
          disabled={alerts.length === 0}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 bg-red-500/10 rounded-lg flex items-center justify-center group-hover:bg-red-500/20 transition-colors">
              <FileText className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h4 className="text-white text-sm font-semibold">Alerts Report</h4>
              <p className="text-[11px] text-slate-500">Threat alerts with severity and confidence</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-red-400 text-xs font-medium">
            <Download className="w-3.5 h-3.5" />
            Download CSV ({alerts.length} rows)
          </div>
        </button>

        <button
          onClick={downloadFullReport}
          className="cyber-card p-6 text-left hover:scale-[1.02] transition-transform group"
          disabled={events.length === 0}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 bg-amber-500/10 rounded-lg flex items-center justify-center group-hover:bg-amber-500/20 transition-colors">
              <BarChart3 className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h4 className="text-white text-sm font-semibold">Full Analysis Report</h4>
              <p className="text-[11px] text-slate-500">Complete threat analysis summary</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-amber-400 text-xs font-medium">
            <Download className="w-3.5 h-3.5" />
            Download TXT
          </div>
        </button>
      </div>

      {/* Summary Statistics */}
      <div className="cyber-card p-5">
        <h3 className="text-white font-semibold text-sm mb-4">Report Summary</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Events', value: events.length, color: 'cyan' },
            { label: 'Threats Detected', value: reportStats.totalThreats, color: 'red' },
            { label: 'Threat Rate', value: `${events.length > 0 ? ((reportStats.totalThreats / events.length) * 100).toFixed(1) : 0}%`, color: 'amber' },
            { label: 'Avg Anomaly', value: `${(reportStats.avgAnomaly * 100).toFixed(1)}%`, color: 'amber' },
          ].map((s) => (
            <div key={s.label} className="bg-slate-900/50 rounded-lg p-3">
              <span className={`text-[10px] font-medium uppercase tracking-wider text-${s.color}-400`}>{s.label}</span>
              <p className={`text-lg font-bold text-${s.color}-400 mono mt-1`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Threat type breakdown */}
        {Object.keys(reportStats.byType).length > 0 && (
          <div className="mt-6">
            <h4 className="text-xs text-slate-400 uppercase tracking-wider font-medium mb-3">Threat Type Breakdown</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {Object.entries(reportStats.byType)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => (
                  <div key={type} className="bg-slate-900/30 rounded-lg p-3 flex items-center justify-between">
                    <span className="text-xs text-slate-300 capitalize">{type.replace('_', ' ')}</span>
                    <span className="text-xs text-red-400 mono font-bold">{count}</span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Top malicious IPs */}
        {Object.keys(reportStats.topSourceIPs).length > 0 && (
          <div className="mt-6">
            <h4 className="text-xs text-slate-400 uppercase tracking-wider font-medium mb-3">Top Malicious Source IPs</h4>
            <div className="space-y-1.5">
              {Object.entries(reportStats.topSourceIPs)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([ip, count]) => (
                  <div key={ip} className="flex items-center justify-between bg-slate-900/30 rounded-lg px-3 py-2">
                    <span className="mono text-xs text-slate-300">{ip}</span>
                    <span className="mono text-xs text-red-400">{count} threats</span>
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
