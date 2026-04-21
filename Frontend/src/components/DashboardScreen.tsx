import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Clock, Activity, Home, ExternalLink, Zap } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { getDashboardStats, startDashboard, type DashboardStatsResponse } from '@/lib/api';

type Screen = 'home' | 'simulation' | 'data' | 'training' | 'dashboard' | 'post-simulation';

interface Props {
  onNavigate: (screen: Screen) => void;
}

const DashboardScreen = ({ onNavigate }: Props) => {
  const [stats, setStats] = useState<DashboardStatsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const palette = ['#22c55e', '#06b6d4', '#f59e0b', '#ef4444', '#a78bfa', '#f97316'];

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const response = await getDashboardStats();
        if (!active) return;
        setStats(response);
        setErrorMessage(null);
      } catch {
        if (!active) return;
        setErrorMessage('Unable to load live dashboard metrics.');
      } finally {
        if (active) setIsLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 8000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  const statCards = useMemo(() => {
    const totalAttacks = stats?.totalAttacks ?? 0;
    const detectionRate = stats?.detectionRate ?? 0;
    const avgResponseTime = stats?.avgResponseTime ?? 0;
    const activeThreats = stats?.activeThreats ?? 0;
    return [
      {
        label: 'Total Attacks',
        value: totalAttacks.toLocaleString(),
        icon: <Shield className="w-5 h-5" />,
        color: 'text-primary',
        glow: 'shadow-[0_0_16px_-4px_hsl(120_100%_50%/0.5)]',
        border: 'border-green-800',
        bg: 'bg-green-950/50',
      },
      {
        label: 'Detection Rate',
        value: `${detectionRate}%`,
        icon: <Activity className="w-5 h-5" />,
        color: 'text-cyan-400',
        glow: 'shadow-[0_0_16px_-4px_hsl(185_100%_50%/0.5)]',
        border: 'border-cyan-800',
        bg: 'bg-cyan-950/50',
      },
      {
        label: 'Avg Response',
        value: `${avgResponseTime}s`,
        icon: <Clock className="w-5 h-5" />,
        color: 'text-yellow-400',
        glow: 'shadow-[0_0_16px_-4px_hsl(45_100%_55%/0.5)]',
        border: 'border-yellow-800',
        bg: 'bg-yellow-950/50',
      },
      {
        label: 'Active Threats',
        value: String(activeThreats),
        icon: <AlertTriangle className="w-5 h-5" />,
        color: 'text-red-400',
        glow: 'shadow-[0_0_16px_-4px_hsl(0_90%_60%/0.5)]',
        border: 'border-red-900',
        bg: 'bg-red-950/50',
      },
    ];
  }, [stats]);

  const attackDistribution = useMemo(() => {
    const base = stats?.attackDistribution ?? [];
    return base.map((entry, idx) => ({ ...entry, color: palette[idx % palette.length] }));
  }, [stats]);

  const topAttackers = stats?.topAttackerIPs ?? [];
  const recentSessions = stats?.recentSessions ?? [];

  const openLiveDashboard = async () => {
    try {
      const launch = await startDashboard();
      window.open(launch.url, '_blank', 'noopener,noreferrer');
    } catch {
      setErrorMessage('Failed to launch Streamlit dashboard process.');
    }
  };

  const severityCell = (sev: string) => {
    if (sev === 'critical') return 'text-red-400 font-bold text-glow-red';
    if (sev === 'high') return 'text-red-400';
    if (sev === 'medium') return 'text-yellow-400';
    return 'text-green-400';
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex-1 flex flex-col p-5 gap-5 overflow-auto cyber-grid">
      {/* Top bar */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => onNavigate('home')}
          className="cyber-btn rounded-sm p-2 transition-colors"
        >
          <Home className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-primary animate-pulse-glow" />
          <h2 className="text-xl font-bold font-display tracking-widest uppercase text-primary text-glow-primary">
            Security Dashboard
          </h2>
        </div>
        <button
          onClick={openLiveDashboard}
          className="cyber-btn rounded-sm px-3 py-2 ml-auto flex items-center gap-2 text-xs font-mono"
        >
          <ExternalLink className="w-3.5 h-3.5" />
          Open Streamlit
        </button>
      </div>

      {errorMessage && (
        <div className="cyber-card rounded-sm p-3 text-sm text-red-400 border-red-900 font-mono">
          <span className="text-red-500 mr-2">[ERR]</span>{errorMessage}
        </div>
      )}
      {isLoading && !errorMessage && (
        <div className="cyber-card rounded-sm p-3 text-sm text-muted-foreground font-mono">
          <span className="text-primary animate-pulse">▶</span> Loading live dashboard metrics...
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: i * 0.08 }}
            className={`cyber-card rounded-lg p-5 relative overflow-hidden border ${s.border} ${s.glow}`}
          >
            {/* Top line glow */}
            <span className="absolute top-0 left-0 right-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${palette[i]}, transparent)` }} />
            <div className={`w-9 h-9 rounded-sm cyber-icon flex items-center justify-center ${s.color} mb-3`}>
              {s.icon}
            </div>
            <p className={`text-3xl font-bold font-mono ${s.color}`}>{s.value}</p>
            <p className="text-xs text-muted-foreground font-mono mt-1 tracking-wider uppercase">{s.label}</p>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Pie chart */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} className="cyber-card rounded-lg p-5">
          <h3 className="font-bold font-display tracking-widest uppercase text-sm text-primary mb-4">
            Attack Distribution
          </h3>
          <div className="h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {attackDistribution.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: 'hsl(220, 25%, 6%)',
                    border: '1px solid hsl(120, 40%, 20%)',
                    borderRadius: '2px',
                    color: '#a0f4a0',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap gap-3 mt-2">
            {attackDistribution.map(d => (
              <span key={d.name} className="text-xs text-muted-foreground flex items-center gap-1.5 font-mono">
                <span className="w-2 h-2 rounded-full" style={{ background: d.color, boxShadow: `0 0 6px ${d.color}` }} />
                {d.name}
              </span>
            ))}
          </div>
        </motion.div>

        {/* Top attackers */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }} className="cyber-card rounded-lg p-5">
          <h3 className="font-bold font-display tracking-widest uppercase text-sm text-red-400 mb-4">
            Top Attacker IPs
          </h3>
          <div className="space-y-3">
            {topAttackers.map((ip, i) => (
              <div key={ip.ip} className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground font-mono w-5 text-right">{i + 1}</span>
                <div className="flex-1">
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-mono text-sm text-red-300">{ip.ip}</span>
                    <span className="text-xs text-muted-foreground font-mono">{ip.count} hits</span>
                  </div>
                  <div className="cyber-track h-2 rounded-none overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${topAttackers.length ? (ip.count / topAttackers[0].count) * 100 : 0}%` }}
                      transition={{ delay: 0.5 + i * 0.1, duration: 0.6 }}
                      className="h-full bg-gradient-to-r from-red-700 to-red-500"
                      style={{ boxShadow: '0 0 8px hsl(0 90% 50% / 0.5)' }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Recent activity */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }} className="cyber-card rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-border/40">
          <h3 className="font-bold font-display tracking-widest uppercase text-sm text-cyan-400">Recent Activity</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/20">
                {['ID', 'Time', 'Source IP', 'Attack Type', 'Severity'].map(h => (
                  <th key={h} className="px-5 py-2.5 text-left text-[10px] font-mono text-muted-foreground tracking-[0.15em] uppercase">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recentSessions.map((s, i) => (
                <motion.tr
                  key={s.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.55 + i * 0.04 }}
                  className="border-b border-border/10 hover:bg-green-950/10 transition-colors group"
                >
                  <td className="px-5 py-3 font-mono text-primary text-xs">{s.id}</td>
                  <td className="px-5 py-3 text-muted-foreground font-mono text-xs">{new Date(s.timestamp).toLocaleString()}</td>
                  <td className="px-5 py-3 font-mono text-xs text-green-300">{s.srcIp}</td>
                  <td className="px-5 py-3 font-mono text-xs text-cyan-300">{s.attackType}</td>
                  <td className={`px-5 py-3 font-mono uppercase text-xs tracking-widest ${severityCell(s.severity)}`}>
                    {s.severity}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default DashboardScreen;
