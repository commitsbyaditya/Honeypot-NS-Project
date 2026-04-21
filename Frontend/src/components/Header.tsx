import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Power, Shield, Wifi, WifiOff, Activity } from 'lucide-react';
import { getHealth, stopAllSimulations, type HealthResponse } from '@/lib/api';
import { toast } from '@/components/ui/sonner';

interface HeaderProps {
  onHomeClick: () => void;
}

const StatusPill = ({ label, status }: { label: string; status: 'green' | 'yellow' | 'red' }) => {
  const pillClass =
    status === 'green' ? 'cyber-pill-green' : status === 'yellow' ? 'cyber-pill-yellow' : 'cyber-pill-red';
  const dotColor =
    status === 'green'
      ? 'bg-green-400 shadow-[0_0_6px_hsl(120_100%_50%)]'
      : status === 'yellow'
      ? 'bg-yellow-400 shadow-[0_0_6px_hsl(45_100%_55%)]'
      : 'bg-red-400 shadow-[0_0_6px_hsl(0_90%_60%)]';
  return (
    <span className={`${pillClass} rounded-sm`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor} animate-pulse-glow`} />
      {label}
    </span>
  );
};

const Header = ({ onHomeClick }: HeaderProps) => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isKilling, setIsKilling] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const response = await getHealth();
        if (!active) return;
        setHealth(response);
      } catch {
        if (!active) return;
        setHealth(null);
      }
    };
    load();
    const interval = setInterval(load, 10000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  // Tick for live clock
  useEffect(() => {
    const t = setInterval(() => setTick(n => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const systemReady = health !== null;
  const modelLoaded = Boolean(health?.modelExists);
  const datasetReady = Boolean(health?.dataExists);
  const adminGranted = Boolean(health?.isAdmin);
  const honeypotActive = Boolean(health?.honeypotActive);

  const handleKillSwitch = async () => {
    if (isKilling) return;
    setIsKilling(true);
    try {
      const result = await stopAllSimulations();
      toast.success(`Kill switch complete. Stopped ${result.stoppedJobs} job(s), cleaned ${result.cleaned} process(es).`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Kill switch failed.');
    } finally {
      setIsKilling(false);
    }
  };

  const now = new Date();
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
  const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });

  return (
    <motion.header
      initial={{ y: -30, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
      className="cyber-header px-5 py-3 flex items-center justify-between sticky top-0 z-50 animate-flicker"
    >
      {/* Left: Logo */}
      <button onClick={onHomeClick} className="flex items-center gap-3 group">
        <div className="relative w-10 h-10 rounded-sm cyber-icon flex items-center justify-center text-primary group-hover:text-green-300 transition-all duration-200 animate-neon-breathe">
          <Shield className="w-5 h-5" />
          {/* Corner decorations */}
          <span className="absolute top-0 left-0 w-2 h-2 border-t border-l border-primary/70" />
          <span className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-primary/70" />
        </div>
        <div>
          <h1 className="text-base font-bold tracking-widest uppercase font-display text-primary text-glow-primary leading-tight">
            HoneyPot
          </h1>
          <p className="text-[10px] text-muted-foreground font-mono tracking-[0.2em] uppercase leading-tight">
            ◈ Control Center ◈
          </p>
        </div>
      </button>

      {/* Center: Live time */}
      <div className="hidden md:flex flex-col items-center gap-0.5">
        <span className="font-mono text-lg font-bold text-primary text-glow-primary tracking-widest" key={tick}>
          {timeStr}
        </span>
        <span className="font-mono text-[10px] text-muted-foreground tracking-widest uppercase">{dateStr}</span>
      </div>

      {/* Right: Status pills + Kill button */}
      <div className="flex items-center gap-2 flex-wrap justify-end">
        <div className="hidden lg:flex items-center gap-1.5 flex-wrap justify-end">
          <StatusPill label="API" status={systemReady ? 'green' : 'red'} />
          <StatusPill label="Model" status={modelLoaded ? 'green' : 'yellow'} />
          <StatusPill label="Dataset" status={datasetReady ? 'green' : 'yellow'} />
          <StatusPill label="Honeypot" status={honeypotActive ? 'green' : 'red'} />
          <StatusPill label="Admin" status={adminGranted ? 'green' : 'red'} />
        </div>
        <button
          onClick={handleKillSwitch}
          disabled={isKilling}
          className="cyber-btn-danger rounded-sm px-3 py-1.5 inline-flex items-center gap-1.5 text-xs disabled:opacity-50 ml-2"
          title="Force-stop all running attack simulator processes"
        >
          <Power className="w-3 h-3" />
          {isKilling ? 'KILLING...' : 'KILL SIM'}
        </button>
      </div>
    </motion.header>
  );
};

export default Header;
