import { useState, useCallback } from 'react';
import { Upload, FileText, BarChart3, CheckCircle } from 'lucide-react';
import type { DataProfile, ColumnProfile } from '../types';

interface DataProcessingProps {
  dataProfile: DataProfile | null;
  loading: boolean;
  onProfileLoaded: (profile: DataProfile) => void;
}

export default function DataProcessing({ dataProfile, loading, onProfileLoaded }: DataProcessingProps) {
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [step, setStep] = useState<'upload' | 'cleaning' | 'encoding' | 'done'>('upload');

  const processCSV = useCallback(async (text: string, name: string) => {
    setUploading(true);
    setFileName(name);
    setStep('cleaning');

    const lines = text.trim().split('\n');
    const headers = lines[0].split(',').map((h) => h.trim());
    const rows = lines.slice(1).map((l) => l.split(',').map((c) => c.trim()));

    await new Promise((r) => setTimeout(r, 800));
    setStep('encoding');

    const columns: ColumnProfile[] = headers.map((h, idx) => {
      const values = rows.map((r) => r[idx]).filter(Boolean);
      const missing = rows.filter((r) => !r[idx] || r[idx] === '').length;
      const unique = new Set(values).size;
      const numeric = values.every((v) => !isNaN(Number(v)));
      const type = numeric ? 'numeric' : unique < 20 ? 'categorical' : 'string';
      return { name: h, type, missing, unique, sample: values[0] || '' };
    });

    const threatDist: Record<string, number> = {};
    const protocolDist: Record<string, number> = {};
    const threatCol = headers.findIndex((h) => h.toLowerCase().includes('threat') || h.toLowerCase().includes('label') || h.toLowerCase().includes('attack'));
    const protoCol = headers.findIndex((h) => h.toLowerCase().includes('proto'));

    if (threatCol >= 0) {
      rows.forEach((r) => {
        const v = r[threatCol] || 'unknown';
        threatDist[v] = (threatDist[v] || 0) + 1;
      });
    }
    if (protoCol >= 0) {
      rows.forEach((r) => {
        const v = r[protoCol] || 'unknown';
        protocolDist[v] = (protocolDist[v] || 0) + 1;
      });
    }

    await new Promise((r) => setTimeout(r, 600));
    setStep('done');

    onProfileLoaded({
      rowCount: rows.length,
      colCount: headers.length,
      columns,
      missingValues: columns.reduce((s, c) => s + c.missing, 0),
      threatDistribution: threatDist,
      protocolDistribution: protocolDist,
    });
    setUploading(false);
  }, [onProfileLoaded]);

  const handleFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      processCSV(text, file.name);
    };
    reader.readAsText(file);
  }, [processCSV]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.csv')) handleFile(file);
  }, [handleFile]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="cyber-card p-8 animate-pulse">
          <div className="h-6 bg-slate-800 rounded w-1/4 mb-6" />
          <div className="h-48 bg-slate-800/50 rounded" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Upload Section */}
      <div className="cyber-card p-6">
        <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
          <Upload className="w-4 h-4 text-cyan-400" />
          Dataset Upload & Processing
        </h3>

        <div
          className={`cyber-upload p-8 text-center ${dragOver ? 'dragover' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
        >
          {step === 'done' ? (
            <div className="flex flex-col items-center gap-3">
              <CheckCircle className="w-12 h-12 text-emerald-400" />
              <p className="text-emerald-400 text-sm font-medium">Dataset processed successfully</p>
              <p className="text-slate-500 text-xs mono">{fileName}</p>
              <button
                onClick={() => { setStep('upload'); setFileName(null); }}
                className="mt-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                Upload another dataset
              </button>
            </div>
          ) : uploading ? (
            <div className="flex flex-col items-center gap-3">
              <div className="cyber-spinner" />
              <p className="text-cyan-400 text-sm font-medium">
                {step === 'cleaning' && 'Cleaning missing values...'}
                {step === 'encoding' && 'Encoding categorical features...'}
              </p>
              <div className="w-48 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-teal-400 rounded-full transition-all duration-700"
                  style={{ width: step === 'cleaning' ? '50%' : '85%' }}
                />
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <FileText className="w-10 h-10 text-cyan-400/60" />
              <p className="text-slate-300 text-sm">Drop a CSV file here or click to upload</p>
              <p className="text-slate-500 text-xs">Supports UNSW-NB15, CICIDS2017, or custom network traffic CSVs</p>
              <label className="mt-2 cursor-pointer">
                <span className="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400 text-xs font-medium hover:bg-cyan-500/20 transition-colors inline-block">
                  Browse Files
                </span>
                <input type="file" accept=".csv" className="hidden" onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])} />
              </label>
            </div>
          )}
        </div>
      </div>

      {/* Data Profile */}
      {dataProfile && (
        <>
          {/* Stats row */}
          <div className="grid grid-cols-3 gap-4">
            <div className="metric-card">
              <span className="text-[11px] text-cyan-400 uppercase tracking-wider font-medium">Rows</span>
              <p className="text-xl font-bold text-cyan-400 mono mt-1">{dataProfile.rowCount.toLocaleString()}</p>
            </div>
            <div className="metric-card">
              <span className="text-[11px] text-amber-400 uppercase tracking-wider font-medium">Columns</span>
              <p className="text-xl font-bold text-amber-400 mono mt-1">{dataProfile.colCount}</p>
            </div>
            <div className="metric-card">
              <span className="text-[11px] text-red-400 uppercase tracking-wider font-medium">Missing Values</span>
              <p className="text-xl font-bold text-red-400 mono mt-1">{dataProfile.missingValues.toLocaleString()}</p>
            </div>
          </div>

          {/* Column Details Table */}
          <div className="cyber-card p-5">
            <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              Column Profile
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-slate-500 border-b border-slate-800">
                    <th className="text-left py-2 px-3 font-medium">Column</th>
                    <th className="text-left py-2 px-3 font-medium">Type</th>
                    <th className="text-left py-2 px-3 font-medium">Missing</th>
                    <th className="text-left py-2 px-3 font-medium">Unique</th>
                    <th className="text-left py-2 px-3 font-medium">Sample</th>
                  </tr>
                </thead>
                <tbody>
                  {dataProfile.columns.map((col) => (
                    <tr key={col.name} className="border-b border-slate-800/40 hover:bg-slate-800/20">
                      <td className="py-2 px-3 text-slate-300 mono">{col.name}</td>
                      <td className="py-2 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                          col.type === 'numeric' ? 'bg-cyan-500/10 text-cyan-400' :
                          col.type === 'categorical' ? 'bg-amber-500/10 text-amber-400' :
                          col.type === 'binary' ? 'bg-emerald-500/10 text-emerald-400' :
                          'bg-slate-500/10 text-slate-400'
                        }`}>{col.type}</span>
                      </td>
                      <td className="py-2 px-3 mono text-slate-400">{col.missing}</td>
                      <td className="py-2 px-3 mono text-slate-400">{col.unique.toLocaleString()}</td>
                      <td className="py-2 px-3 mono text-slate-500 truncate max-w-[120px]">{col.sample}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Distributions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.keys(dataProfile.threatDistribution).length > 0 && (
              <div className="cyber-card p-5">
                <h3 className="text-white font-semibold text-sm mb-3">Threat Distribution</h3>
                <div className="space-y-2">
                  {Object.entries(dataProfile.threatDistribution)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => {
                      const max = Math.max(...Object.values(dataProfile.threatDistribution));
                      const isNormal = type.toLowerCase() === 'normal' || type === '0';
                      return (
                        <div key={type}>
                          <div className="flex items-center justify-between text-xs mb-1">
                            <span className={`capitalize ${isNormal ? 'text-emerald-400' : 'text-red-400'}`}>{type.replace('_', ' ')}</span>
                            <span className="mono text-slate-400">{count.toLocaleString()}</span>
                          </div>
                          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${isNormal ? 'bg-emerald-400' : 'bg-red-400'}`}
                              style={{ width: `${(count / max) * 100}%`, transition: 'width 0.5s ease' }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}
            {Object.keys(dataProfile.protocolDistribution).length > 0 && (
              <div className="cyber-card p-5">
                <h3 className="text-white font-semibold text-sm mb-3">Protocol Distribution</h3>
                <div className="space-y-2">
                  {Object.entries(dataProfile.protocolDistribution)
                    .sort((a, b) => b[1] - a[1])
                    .map(([proto, count]) => {
                      const max = Math.max(...Object.values(dataProfile.protocolDistribution));
                      return (
                        <div key={proto}>
                          <div className="flex items-center justify-between text-xs mb-1">
                            <span className="text-cyan-400">{proto}</span>
                            <span className="mono text-slate-400">{count.toLocaleString()}</span>
                          </div>
                          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${(count / max) * 100}%`, transition: 'width 0.5s ease' }} />
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Use sample dataset button */}
      {!dataProfile && (
        <div className="cyber-card p-5 text-center">
          <p className="text-slate-400 text-sm mb-3">Or use the built-in UNSW-NB15 style sample dataset</p>
          <button
            onClick={() => {
              onProfileLoaded({
                rowCount: 10000,
                colCount: 14,
                columns: [
                  { name: 'source_ip', type: 'categorical', missing: 0, unique: 842, sample: '192.168.1.45' },
                  { name: 'destination_ip', type: 'categorical', missing: 0, unique: 756, sample: '10.0.0.23' },
                  { name: 'source_port', type: 'numeric', missing: 0, unique: 4921, sample: '44125' },
                  { name: 'destination_port', type: 'numeric', missing: 0, unique: 210, sample: '443' },
                  { name: 'protocol', type: 'categorical', missing: 0, unique: 5, sample: 'TCP' },
                  { name: 'packet_size', type: 'numeric', missing: 12, unique: 8420, sample: '748' },
                  { name: 'duration', type: 'numeric', missing: 0, unique: 9100, sample: '2.34' },
                  { name: 'bytes_sent', type: 'numeric', missing: 45, unique: 7200, sample: '15230' },
                  { name: 'bytes_received', type: 'numeric', missing: 38, unique: 6800, sample: '42100' },
                  { name: 'failed_logins', type: 'numeric', missing: 0, unique: 21, sample: '0' },
                  { name: 'service', type: 'categorical', missing: 0, unique: 7, sample: 'https' },
                  { name: 'state', type: 'categorical', missing: 142, unique: 5, sample: 'ESTABLISHED' },
                  { name: 'is_threat', type: 'binary', missing: 0, unique: 2, sample: 'false' },
                  { name: 'threat_type', type: 'categorical', missing: 0, unique: 7, sample: 'normal' },
                ],
                missingValues: 237,
                threatDistribution: { normal: 8500, ddos: 320, intrusion: 280, port_scan: 410, brute_force: 290, data_exfiltration: 120, anomaly: 80 },
                protocolDistribution: { TCP: 5800, UDP: 2100, ICMP: 480, HTTP: 920, HTTPS: 700 },
              });
            }}
            className="px-5 py-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400 text-sm font-medium hover:bg-cyan-500/20 transition-colors"
          >
            Load Sample Dataset
          </button>
        </div>
      )}
    </div>
  );
}
