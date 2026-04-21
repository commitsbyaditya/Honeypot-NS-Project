import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Filter, Download, Home, ArrowLeft, Brain, ChevronDown, ChevronUp, Eye, EyeOff, Database } from 'lucide-react';
import { getDataSessions, type AttackSessionRow } from '@/lib/api';

type Screen = 'home' | 'simulation' | 'data' | 'training' | 'dashboard' | 'post-simulation';

interface Props {
  onNavigate: (screen: Screen) => void;
  previousScreen?: Screen;
}

type SortKey = 'id' | 'timestamp' | 'srcIp' | 'attackType' | 'duration' | 'packetsCount' | 'severity' | 'detected';

const severityColor: Record<string, string> = {
  low: 'text-green-400',
  medium: 'text-yellow-400',
  high: 'text-red-400',
  critical: 'text-red-300 font-bold',
};

const allColumns: { key: SortKey; label: string }[] = [
  { key: 'id', label: 'Session ID' },
  { key: 'timestamp', label: 'Time' },
  { key: 'srcIp', label: 'Source IP' },
  { key: 'attackType', label: 'Attack Type' },
  { key: 'duration', label: 'Duration (s)' },
  { key: 'packetsCount', label: 'Packets' },
  { key: 'severity', label: 'Severity' },
  { key: 'detected', label: 'Detected' },
];

const attackTypeOptions = [
  { value: 'all', label: 'All Types' },
  { value: 'ssh', label: 'SSH' },
  { value: 'portscan', label: 'Port Scan' },
  { value: 'dns', label: 'DNS' },
  { value: 'arp', label: 'ARP' },
  { value: 'icmp', label: 'ICMP' },
];

const DataExplorerScreen = ({ onNavigate, previousScreen = 'home' }: Props) => {
  const [rows, setRows] = useState<AttackSessionRow[]>([]);
  const [totalRows, setTotalRows] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [sortKey, setSortKey] = useState<SortKey>('timestamp');
  const [sortAsc, setSortAsc] = useState(false);
  const [visibleCols, setVisibleCols] = useState<Set<SortKey>>(new Set(allColumns.map(c => c.key)));
  const [showColMenu, setShowColMenu] = useState(false);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setIsLoading(true);
      setErrorMessage(null);
      try {
        const response = await getDataSessions({ search, attackType: filterType, limit: 1000 });
        if (!active) return;
        setRows(response.sessions);
        setTotalRows(response.total);
      } catch {
        if (!active) return;
        setErrorMessage('Unable to load attack sessions. Start the API bridge and retry.');
      } finally {
        if (active) setIsLoading(false);
      }
    };
    load();
    return () => { active = false; };
  }, [search, filterType]);

  const filtered = useMemo(() => {
    const data = [...rows];
    data.sort((a, b) => {
      const va = a[sortKey]; const vb = b[sortKey];
      if (typeof va === 'string') return sortAsc ? va.localeCompare(vb as string) : (vb as string).localeCompare(va);
      if (typeof va === 'boolean') return sortAsc ? Number(va) - Number(vb as boolean) : Number(vb as boolean) - Number(va);
      return sortAsc ? (va as number) - (vb as number) : (vb as number) - (va as number);
    });
    return data;
  }, [rows, sortKey, sortAsc]);

  const stats = useMemo(() => {
    const types: Record<string, number> = {};
    filtered.forEach(s => { types[s.attackType] = (types[s.attackType] || 0) + 1; });
    return { total: totalRows || filtered.length, types };
  }, [filtered, totalRows]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(false); }
  };

  const toggleCol = (key: SortKey) => {
    const next = new Set(visibleCols);
    next.has(key) ? next.delete(key) : next.add(key);
    setVisibleCols(next);
  };

  const exportCsv = () => {
    const selectedColumns = allColumns.filter(c => visibleCols.has(c.key));
    const header = selectedColumns.map(c => c.label).join(',');
    const body = filtered.map(row =>
      selectedColumns.map(c => `"${String(row[c.key]).replace(/"/g, '""')}"`).join(',')
    );
    const blob = new Blob([[header, ...body].join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `attack_sessions_${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const typeColors: Record<string, string> = {
    ssh: 'text-red-400 border-red-800 bg-red-950/40',
    portscan: 'text-yellow-400 border-yellow-800 bg-yellow-950/40',
    dns: 'text-cyan-400 border-cyan-800 bg-cyan-950/40',
    arp: 'text-purple-400 border-purple-800 bg-purple-950/40',
    icmp: 'text-blue-400 border-blue-800 bg-blue-950/40',
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex-1 flex flex-col p-5 gap-4 overflow-hidden cyber-grid">
      {/* Top bar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <button onClick={() => onNavigate(previousScreen)} className="cyber-btn rounded-sm p-2">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <button onClick={() => onNavigate('home')} className="cyber-btn rounded-sm p-2">
            <Home className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 ml-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xl font-bold font-display tracking-widest uppercase text-cyan-400">
              Data Explorer
            </h2>
          </div>
        </div>
        <button onClick={() => onNavigate('training')} className="cyber-btn rounded-sm px-3 py-2 flex items-center gap-2 text-xs">
          <Brain className="w-3.5 h-3.5 text-yellow-400" />
          <span className="tracking-widest">TRAIN ON CURRENT DATASET</span>
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        <div className="cyber-card rounded-sm p-3 border-cyan-800 col-span-2 md:col-span-1">
          <p className="text-[9px] font-mono text-muted-foreground tracking-widest uppercase mb-1">Total Sessions</p>
          <p className="text-2xl font-bold font-mono text-cyan-400" style={{ textShadow: '0 0 10px hsl(185 100% 50% / 0.5)' }}>
            {stats.total}
          </p>
        </div>
        {Object.entries(stats.types).slice(0, 4).map(([type, count]) => (
          <div key={type} className={`cyber-card rounded-sm p-3 border ${typeColors[type] || 'text-primary border-green-800'}`}>
            <p className="text-[9px] font-mono tracking-widest uppercase mb-1 opacity-70">{type.toUpperCase()}</p>
            <p className="text-2xl font-bold font-mono">{count}</p>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="cyber-input rounded-sm px-3 py-2 flex items-center gap-2 flex-1 min-w-[180px] max-w-sm border">
          <Search className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search sessions..."
            className="bg-transparent outline-none text-sm flex-1 text-green-200 placeholder:text-muted-foreground font-mono"
          />
        </div>
        <div className="cyber-btn rounded-sm px-3 py-2 flex items-center gap-2">
          <Filter className="w-3.5 h-3.5" />
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            className="bg-transparent outline-none text-xs font-mono cursor-pointer text-green-200"
          >
            {attackTypeOptions.map(a => (
              <option key={a.value} value={a.value} className="bg-[#0a100a] text-green-200">{a.label}</option>
            ))}
          </select>
        </div>
        <div className="relative">
          <button onClick={() => setShowColMenu(!showColMenu)} className="cyber-btn rounded-sm px-3 py-2 flex items-center gap-2 text-xs">
            {showColMenu ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            <span className="tracking-widest">COLUMNS</span>
          </button>
          {showColMenu && (
            <div className="absolute top-full mt-1 right-0 cyber-card rounded-sm p-2 z-10 min-w-[160px]">
              {allColumns.map(c => (
                <label key={c.key} className="flex items-center gap-2 px-2 py-1.5 text-xs text-green-200 font-mono cursor-pointer hover:bg-green-950/30 rounded-sm">
                  <input type="checkbox" checked={visibleCols.has(c.key)} onChange={() => toggleCol(c.key)} className="accent-green-500" />
                  {c.label}
                </label>
              ))}
            </div>
          )}
        </div>
        <button onClick={exportCsv} className="cyber-btn rounded-sm px-3 py-2 flex items-center gap-2 text-xs">
          <Download className="w-3.5 h-3.5" />
          <span className="tracking-widest">EXPORT CSV</span>
        </button>
      </div>

      {errorMessage && (
        <div className="cyber-card rounded-sm p-3 text-xs text-red-400 border-red-900 font-mono">
          <span className="text-red-500 mr-2">[ERR]</span>{errorMessage}
        </div>
      )}
      {isLoading && !errorMessage && (
        <div className="cyber-card rounded-sm p-3 text-xs text-muted-foreground font-mono">
          <span className="text-primary animate-pulse mr-2">▶</span>Loading sessions...
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto rounded-sm cyber-card">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-green-900/50">
              {allColumns.filter(c => visibleCols.has(c.key)).map(c => (
                <th
                  key={c.key}
                  onClick={() => toggleSort(c.key)}
                  className="px-4 py-3 text-left font-mono text-muted-foreground cursor-pointer hover:text-green-300 transition-colors select-none tracking-[0.12em] uppercase text-[9px]"
                >
                  <span className="inline-flex items-center gap-1">
                    {c.label}
                    {sortKey === c.key && (sortAsc ? <ChevronUp className="w-3 h-3 text-primary" /> : <ChevronDown className="w-3 h-3 text-primary" />)}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map((row, i) => (
              <motion.tr
                key={row.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.008 }}
                className="border-b border-green-900/10 hover:bg-green-950/20 transition-colors group"
              >
                {visibleCols.has('id') && <td className="px-4 py-2.5 font-mono text-primary">{row.id}</td>}
                {visibleCols.has('timestamp') && <td className="px-4 py-2.5 text-muted-foreground font-mono">{new Date(row.timestamp).toLocaleString()}</td>}
                {visibleCols.has('srcIp') && <td className="px-4 py-2.5 font-mono text-green-300">{row.srcIp}</td>}
                {visibleCols.has('attackType') && (
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded-sm border font-mono text-[9px] tracking-wider uppercase ${typeColors[row.attackType] || 'text-primary border-green-800 bg-green-950/40'}`}>
                      {row.attackType}
                    </span>
                  </td>
                )}
                {visibleCols.has('duration') && <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.duration}s</td>}
                {visibleCols.has('packetsCount') && <td className="px-4 py-2.5 font-mono text-muted-foreground">{row.packetsCount}</td>}
                {visibleCols.has('severity') && (
                  <td className={`px-4 py-2.5 font-mono uppercase tracking-widest text-[9px] ${severityColor[row.severity] || 'text-green-400'}`}>
                    {row.severity}
                  </td>
                )}
                {visibleCols.has('detected') && (
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded-sm text-[9px] font-mono tracking-wider uppercase border ${row.detected ? 'pill-green' : 'pill-red'}`}>
                      {row.detected ? 'YES' : 'NO'}
                    </span>
                  </td>
                )}
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
};

export default DataExplorerScreen;
