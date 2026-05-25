import {
  LayoutDashboard,
  Shield,
  AlertTriangle,
  Brain,
  Radio,
  FileWarning,
  Download,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';

interface SidebarProps {
  currentView: string;
  onNavigate: (view: string) => void;
  collapsed: boolean;
  onToggle: () => void;
  activeAlerts: number;
}

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'data', label: 'Data Processing', icon: ShieldCheck },
  { id: 'models', label: 'AI Models', icon: Brain },
  { id: 'monitor', label: 'Threat Monitor', icon: Radio },
  { id: 'alerts', label: 'Alerts', icon: FileWarning, badge: true },
  { id: 'reports', label: 'Reports', icon: Download },
];

export default function Sidebar({ currentView, onNavigate, collapsed, onToggle, activeAlerts }: SidebarProps) {
  return (
    <aside
      className={`fixed left-0 top-0 h-full bg-gray-950 border-r border-slate-800/60 z-50 transition-all duration-300 ${
        collapsed ? 'w-[68px]' : 'w-[220px]'
      }`}
    >
      <div className="flex flex-col h-full">
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 h-16 border-b border-slate-800/60">
          <div className="w-9 h-9 bg-gradient-to-br from-cyan-400 to-teal-500 rounded-lg flex items-center justify-center flex-shrink-0 neon-glow-cyan">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <h1 className="text-white font-bold text-base leading-tight tracking-tight">CyberShield</h1>
              <p className="text-cyan-500/70 text-[10px] font-medium">AI THREAT DETECTION</p>
            </div>
          )}
        </div>

        {/* Nav items */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map(({ id, label, icon: Icon, badge }) => (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={`sidebar-item w-full ${currentView === id ? 'active' : ''} ${
                collapsed ? 'justify-center px-2' : ''
              }`}
              title={collapsed ? label : undefined}
            >
              <Icon className="w-[18px] h-[18px] flex-shrink-0" />
              {!collapsed && <span>{label}</span>}
              {!collapsed && badge && activeAlerts > 0 && (
                <span className="ml-auto bg-red-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
                  {activeAlerts}
                </span>
              )}
              {collapsed && badge && activeAlerts > 0 && (
                <span className="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full" />
              )}
            </button>
          ))}
        </nav>

        {/* System status */}
        {!collapsed && (
          <div className="px-4 pb-4 space-y-3">
            <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-800/40">
              <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                <AlertTriangle className="w-3.5 h-3.5 text-cyan-400" />
                System Status
              </div>
              <div className="space-y-1.5">
                {[
                  { label: 'Detection Engine', status: 'Active', color: 'bg-emerald-400' },
                  { label: 'Autoencoder', status: 'Running', color: 'bg-emerald-400' },
                  { label: 'Database', status: 'Connected', color: 'bg-emerald-400' },
                ].map((s) => (
                  <div key={s.label} className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-500">{s.label}</span>
                    <span className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 ${s.color} rounded-full`} style={{ animation: 'pulse-dot 2s ease-in-out infinite' }} />
                      <span className="text-slate-400">{s.status}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Toggle */}
        <button
          onClick={onToggle}
          className="flex items-center justify-center h-12 border-t border-slate-800/60 text-slate-500 hover:text-slate-300 transition-colors"
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>
    </aside>
  );
}
