import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Home, Terminal, Zap } from 'lucide-react';
import { getJobStatus, startSimulation, stopAllSimulations, type SimulationAttackType } from '@/lib/api';

interface Props {
  onComplete: () => void;
  onHomeClick: () => void;
  attackType: SimulationAttackType;
}

interface ParsedSimulationState {
  currentIdx: number;
  progress: number;
}

const SIMULATION_PHASES = [
  { id: 'ssh', name: 'SSH Brute Force', icon: '🔐', color: 'text-red-400', bar: 'from-red-700 to-red-500' },
  { id: 'portscan', name: 'Port Scan', icon: '🔍', color: 'text-yellow-400', bar: 'from-yellow-700 to-yellow-400' },
  { id: 'dns', name: 'DNS Attack', icon: '🌐', color: 'text-cyan-400', bar: 'from-cyan-700 to-cyan-400' },
  { id: 'icmp', name: 'ICMP Flood', icon: '🌊', color: 'text-blue-400', bar: 'from-blue-700 to-blue-400' },
  { id: 'arp', name: 'ARP Spoof', icon: '🕸️', color: 'text-purple-400', bar: 'from-purple-700 to-purple-400' },
] as const;

const PHASE_SIZE = 100 / SIMULATION_PHASES.length;

const attackIndexMap: Record<Exclude<SimulationAttackType, 'all'>, number> = {
  ssh: 0,
  portscan: 1,
  dns: 2,
  icmp: 3,
  arp: 4,
};

const SimulationScreen = ({ onComplete, onHomeClick, attackType }: Props) => {
  const initialAttackIdx = attackType === 'all' ? 0 : attackIndexMap[attackType];
  const [jobId, setJobId] = useState<string | null>(null);
  const [currentAttackIdx, setCurrentAttackIdx] = useState(initialAttackIdx);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [isComplete, setIsComplete] = useState(false);
  const [isAborting, setIsAborting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const latestJobIdRef = useRef<string | null>(null);
  const latestCompleteRef = useRef(false);

  const currentAttack = SIMULATION_PHASES[Math.min(currentAttackIdx, SIMULATION_PHASES.length - 1)];

  useEffect(() => { latestJobIdRef.current = jobId; }, [jobId]);
  useEffect(() => { latestCompleteRef.current = isComplete; }, [isComplete]);

  useEffect(() => {
    return () => {
      if (latestJobIdRef.current && !latestCompleteRef.current) {
        void stopAllSimulations().catch(() => {});
      }
    };
  }, []);

  const detectAttackIndex = (line: string): number => {
    const n = line.toLowerCase();
    if (n.includes('ssh brute force') || n.includes('ssh honeypot') || n.includes('running: ssh')) return 0;
    if (n.includes('port scanning') || n.includes('port scan') || n.includes('portscan')) return 1;
    if (n.includes('dns attacks') || n.includes('dns attack') || n.includes('dnssimulator')) return 2;
    if (n.includes('icmp flood') || n.includes('ping of death') || n.includes('icmpsimulator') || n.includes('running: icmp')) return 3;
    if (n.includes('arp spoofing') || n.includes('arp spoof') || n.includes('running: arp')) return 4;
    return -1;
  };

  const parseSimulationState = (nextLogs: string[], status: 'running' | 'completed' | 'failed'): ParsedSimulationState => {
    if (status === 'completed' || status === 'failed') return { currentIdx: currentAttackIdx, progress: 100 };
    const completed = new Set<number>();
    let currentIdx = 0;
    let sawRuntimePhase = false;
    for (const line of nextLogs) {
      const normalized = line.toLowerCase();
      const idx = detectAttackIndex(line);
      if (idx >= 0 && (normalized.includes('running:') || normalized.includes('attack simulator') || normalized.includes('simulator]'))) {
        currentIdx = idx; sawRuntimePhase = true;
      }
      if (normalized.includes('[skip]') || normalized.includes('completed successfully') || normalized.includes('failed with exit code') || normalized.includes('timed out')) {
        const doneIdx = idx >= 0 ? idx : currentIdx;
        if (doneIdx >= 0) { completed.add(doneIdx); currentIdx = Math.max(currentIdx, doneIdx); sawRuntimePhase = true; }
      }
      if ((normalized.startsWith('[ok]') || normalized.startsWith('[fail]') || normalized.startsWith('[-]')) && normalized.includes(':')) {
        const summaryIdx = detectAttackIndex(line);
        if (summaryIdx >= 0) { completed.add(summaryIdx); currentIdx = Math.max(currentIdx, summaryIdx); sawRuntimePhase = true; }
      }
    }
    const completedProgress = completed.size * PHASE_SIZE;
    const inFlightBonus = sawRuntimePhase && !completed.has(currentIdx) ? PHASE_SIZE * 0.55 : 0;
    const startupBonus = nextLogs.length > 0 ? 2 : 0;
    return { currentIdx, progress: Math.min(95, completedProgress + inFlightBonus + startupBonus) };
  };

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      try {
        const start = await startSimulation('quick', attackType);
        if (!mounted) return;
        setJobId(start.jobId);
        const modeLabel = attackType === 'all' ? 'all vectors' : `${attackType} only`;
        setLogs(prev => [...prev, `[SYSTEM] Simulation job started (${modeLabel})`]);
      } catch (err) {
        if (!mounted) return;
        setErrorMessage('Failed to start simulation runner. Ensure API bridge is running.');
        setLogs(prev => [...prev, `[ERR] ${err instanceof Error ? err.message : 'Unable to start simulation'}`]);
      }
    };
    run();
    return () => { mounted = false; };
  }, [attackType]);

  useEffect(() => {
    if (!jobId || isComplete) return;
    let mounted = true;
    const interval = setInterval(async () => {
      try {
        const job = await getJobStatus(jobId);
        if (!mounted) return;
        const nextLogs = job.logs || [];
        setLogs(nextLogs);
        const parsed = parseSimulationState(nextLogs, job.status);
        setCurrentAttackIdx(parsed.currentIdx);
        setProgress(prev => Math.max(prev, Math.round(parsed.progress)));
        if (job.status === 'completed') {
          setIsComplete(true); setProgress(100);
          clearInterval(interval);
          setTimeout(onComplete, 1400);
        }
        if (job.status === 'failed') {
          setProgress(100);
          setErrorMessage('Simulation runner failed. Check terminal output and retry.');
          clearInterval(interval);
        }
      } catch {
        if (!mounted) return;
        setErrorMessage('Lost connection to simulation job status API.');
        clearInterval(interval);
      }
    }, 900);
    return () => { mounted = false; clearInterval(interval); };
  }, [jobId, isComplete, onComplete]);

  const handleAbort = async () => {
    if (isAborting) return;
    setIsAborting(true);
    try {
      if (jobId && !isComplete) await stopAllSimulations();
    } catch { /* ignore */ }
    finally { onHomeClick(); setIsAborting(false); }
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const logColor = (log: string) => {
    if (log.includes('[ERR]') || log.includes('FAIL') || log.includes('ERROR')) return 'text-red-400';
    if (log.includes('ALERT') || log.includes('CRITICAL')) return 'text-red-300 font-bold';
    if (log.includes('BLOCK') || log.includes('SCAN') || log.includes('WARN')) return 'text-yellow-400';
    if (log.includes('[OK]') || log.includes('SUCCESS') || log.includes('DONE')) return 'text-green-400';
    if (log.includes('[SYSTEM]')) return 'text-cyan-400';
    return 'text-green-300/80';
  };

  const getVisualization = () => {
    const id = currentAttack.id;
    if (id === 'ssh') {
      return (
        <div className="grid grid-cols-8 gap-1 w-full">
          {Array.from({ length: 32 }).map((_, i) => (
            <motion.div
              key={i}
              animate={{ opacity: [0.15, 1, 0.15], background: ['#7f1d1d', '#ef4444', '#7f1d1d'] }}
              transition={{ duration: 0.4, delay: i * 0.025, repeat: Infinity }}
              className="h-1.5 rounded-none"
            />
          ))}
        </div>
      );
    }
    if (id === 'portscan') {
      return (
        <div className="flex gap-0.5 items-end h-14 w-full">
          {Array.from({ length: 32 }).map((_, i) => (
            <motion.div
              key={i}
              animate={{ height: ['10%', `${30 + Math.random() * 70}%`, '10%'] }}
              transition={{ duration: 0.5 + Math.random() * 0.5, delay: i * 0.04, repeat: Infinity }}
              className="flex-1 bg-gradient-to-t from-yellow-700 to-yellow-400"
              style={{ boxShadow: '0 0 4px hsl(45 100% 50% / 0.4)' }}
            />
          ))}
        </div>
      );
    }
    if (id === 'dns') {
      return (
        <div className="flex gap-3 justify-center items-center h-12">
          {Array.from({ length: 10 }).map((_, i) => (
            <motion.div
              key={i}
              animate={{ scale: [0.3, 1.8, 0.3], opacity: [0.2, 1, 0.2] }}
              transition={{ duration: 0.9, delay: i * 0.09, repeat: Infinity }}
              className="w-3 h-3 rounded-full bg-cyan-400"
              style={{ boxShadow: '0 0 8px hsl(185 100% 50% / 0.7)' }}
            />
          ))}
        </div>
      );
    }
    if (id === 'arp') {
      return (
        <div className="flex items-center justify-center gap-6 h-12">
          <motion.div animate={{ x: [-12, 12, -12] }} transition={{ duration: 1.2, repeat: Infinity }} className="w-10 h-10 bg-purple-950 border border-purple-500 rounded-sm flex items-center justify-center">
            <span className="text-purple-400 text-[10px] font-mono">HOST</span>
          </motion.div>
          <motion.div animate={{ scaleX: [0.4, 1.6, 0.4], opacity: [0.3, 1, 0.3] }} transition={{ duration: 0.7, repeat: Infinity }} className="h-0.5 w-24 bg-gradient-to-r from-purple-600 to-purple-300" style={{ boxShadow: '0 0 6px hsl(270 80% 60% / 0.5)' }} />
          <motion.div animate={{ x: [12, -12, 12] }} transition={{ duration: 1.2, repeat: Infinity }} className="w-10 h-10 bg-purple-950 border border-purple-500 rounded-sm flex items-center justify-center">
            <span className="text-purple-400 text-[10px] font-mono">GW</span>
          </motion.div>
        </div>
      );
    }
    // ICMP
    return (
      <div className="flex items-center justify-center relative h-12">
        {Array.from({ length: 6 }).map((_, i) => (
          <motion.div
            key={i}
            animate={{ scale: [1, 3 + i * 0.5, 1], opacity: [0.9, 0, 0.9] }}
            transition={{ duration: 1.8, delay: i * 0.3, repeat: Infinity }}
            className="absolute w-5 h-5 rounded-full border border-blue-500"
            style={{ boxShadow: '0 0 6px hsl(220 100% 60% / 0.4)' }}
          />
        ))}
        <span className="text-blue-400 text-xs font-mono">ICMP</span>
      </div>
    );
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex-1 flex flex-col p-6 gap-5 cyber-grid">
      {/* Top bar */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleAbort}
          disabled={isAborting}
          className="cyber-btn-danger rounded-sm px-3 py-1.5 flex items-center gap-1.5 text-xs disabled:opacity-50"
        >
          <Home className="w-3.5 h-3.5" />
          {isAborting ? 'STOPPING...' : 'ABORT & RETURN'}
        </button>
        <div className="flex items-center gap-2 ml-2">
          <Terminal className="w-4 h-4 text-primary animate-pulse-glow" />
          <span className="text-xs font-mono text-muted-foreground tracking-widest uppercase">
            Attack Simulation Running
          </span>
        </div>
      </div>

      {/* Attack header */}
      <div className="text-center">
        <AnimatePresence mode="wait">
          <motion.div key={currentAttack.id} initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: -10, opacity: 0 }}>
            <p className="text-[10px] font-mono text-muted-foreground tracking-[0.3em] uppercase mb-2">
              ◈ Simulating Attack Vector ◈
            </p>
            <h2 className={`text-2xl font-bold font-display tracking-widest uppercase ${currentAttack.color}`}>
              {currentAttack.icon} {currentAttack.name}
            </h2>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Progress */}
      <div className="max-w-2xl mx-auto w-full">
        <div className="flex justify-between text-xs text-muted-foreground font-mono mb-2 tracking-wider">
          <span>PROGRESS</span>
          <span className="text-primary font-bold">{Math.round(progress)}%</span>
        </div>
        <div className="cyber-track h-3 rounded-none overflow-hidden">
          <motion.div
            className="h-full bg-gradient-to-r from-green-700 via-green-400 to-cyan-400"
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3 }}
            style={{ boxShadow: '0 0 10px hsl(120 100% 50% / 0.5), 0 0 20px hsl(120 100% 50% / 0.25)' }}
          />
        </div>
        {/* Phase labels */}
        <div className="flex justify-between mt-2">
          {SIMULATION_PHASES.map((a, i) => (
            <span
              key={a.id}
              className={`text-[9px] font-mono tracking-widest uppercase ${
                i <= currentAttackIdx ? a.color : 'text-muted-foreground/30'
              }`}
            >
              {a.name.split(' ')[0]}
            </span>
          ))}
        </div>
      </div>

      {/* Visualization panel */}
      <div className="cyber-card rounded-lg p-5 max-w-2xl mx-auto w-full h-24 flex items-center justify-center relative overflow-hidden">
        <span className="absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 border-primary/60" />
        <span className="absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 border-primary/60" />
        <AnimatePresence mode="wait">
          <motion.div key={currentAttack.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="w-full">
            {getVisualization()}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Terminal */}
      <div className="cyber-terminal flex-1 max-w-3xl mx-auto w-full p-4 overflow-hidden flex flex-col rounded-sm">
        {/* Terminal title bar */}
        <div className="flex items-center gap-2 mb-3 pb-3 border-b border-green-900/50">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500" style={{ boxShadow: '0 0 4px hsl(0 90% 50%)' }} />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" style={{ boxShadow: '0 0 4px hsl(45 100% 50%)' }} />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500" style={{ boxShadow: '0 0 4px hsl(120 100% 50%)' }} />
          <span className="text-[10px] text-muted-foreground font-mono ml-2 tracking-widest uppercase">honeypot-sim — live feed</span>
          <span className="ml-auto text-[10px] font-mono text-primary animate-pulse-glow">● REC</span>
        </div>
        <div ref={logRef} className="flex-1 overflow-y-auto space-y-0.5 font-mono text-xs">
          {logs.length === 0 && !errorMessage && (
            <div className="text-muted-foreground">
              <span className="text-primary">$</span> Waiting for simulation output...
            </div>
          )}
          {logs.map((log, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              className={logColor(log)}
            >
              <span className="text-muted-foreground/40 mr-2 select-none">{String(i + 1).padStart(3, '0')}</span>
              {log}
            </motion.div>
          ))}
          {errorMessage && <div className="text-red-400"><span className="mr-2">[ERR]</span>{errorMessage}</div>}
          {!isComplete && !errorMessage && (
            <motion.span animate={{ opacity: [1, 0] }} transition={{ duration: 0.8, repeat: Infinity }} className="text-primary ml-1">█</motion.span>
          )}
        </div>
      </div>

      {isComplete && (
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="text-center">
          <span className="text-green-400 font-mono text-sm tracking-widest text-glow-primary">
            ✓ SIMULATION COMPLETE — All vectors executed successfully
          </span>
        </motion.div>
      )}
    </motion.div>
  );
};

export default SimulationScreen;
