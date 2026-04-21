import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Crosshair, Database, Brain, BarChart3, Terminal, Zap } from 'lucide-react';
import type { ReactNode } from 'react';
import { getHealth, type SimulationAttackType } from '@/lib/api';

type Screen = 'home' | 'simulation' | 'data' | 'training' | 'dashboard' | 'post-simulation';

interface Props {
  onNavigate: (screen: Screen) => void;
  onStartSimulation: (attackType: SimulationAttackType) => void;
}

interface ActionCard {
  icon: ReactNode;
  title: string;
  description: string;
  screen: Screen;
  accent: string;
  tag: string;
}

const cards: ActionCard[] = [
  {
    icon: <Crosshair className="w-7 h-7" />,
    title: 'Attack Simulation',
    description: 'Deploy AI-driven attack vectors against honeypot infrastructure. SSH, DNS, ARP, ICMP & Port Scan.',
    screen: 'simulation',
    accent: 'primary',
    tag: 'LAUNCH',
  },
  {
    icon: <Database className="w-7 h-7" />,
    title: 'Data Explorer',
    description: 'Analyze captured sessions, filter by attack type, inspect payloads and export datasets.',
    screen: 'data',
    accent: 'accent',
    tag: 'INSPECT',
  },
  {
    icon: <Brain className="w-7 h-7" />,
    title: 'ML Model Training',
    description: 'Fine-tune RandomForest classifier on latest attack patterns and threat signatures.',
    screen: 'training',
    accent: 'warning',
    tag: 'TRAIN',
  },
  {
    icon: <BarChart3 className="w-7 h-7" />,
    title: 'Security Dashboard',
    description: 'Real-time threat analytics, attacker IPs, detection rates and incident overview.',
    screen: 'dashboard',
    accent: 'destructive',
    tag: 'MONITOR',
  },
];

const accentStyles: Record<string, { text: string; border: string; glow: string; bg: string; tag: string }> = {
  primary: {
    text: 'text-primary',
    border: 'border-green-500/30 hover:border-green-400/60',
    glow: 'hover:shadow-[0_0_30px_-8px_hsl(120_100%_50%/0.4)]',
    bg: 'bg-green-950/30',
    tag: 'text-primary bg-green-950 border-green-800',
  },
  accent: {
    text: 'text-cyan-400',
    border: 'border-cyan-500/30 hover:border-cyan-400/60',
    glow: 'hover:shadow-[0_0_30px_-8px_hsl(185_100%_50%/0.4)]',
    bg: 'bg-cyan-950/30',
    tag: 'text-cyan-400 bg-cyan-950 border-cyan-800',
  },
  warning: {
    text: 'text-yellow-400',
    border: 'border-yellow-500/30 hover:border-yellow-400/60',
    glow: 'hover:shadow-[0_0_30px_-8px_hsl(45_100%_55%/0.4)]',
    bg: 'bg-yellow-950/30',
    tag: 'text-yellow-400 bg-yellow-950 border-yellow-800',
  },
  destructive: {
    text: 'text-red-400',
    border: 'border-red-500/30 hover:border-red-400/60',
    glow: 'hover:shadow-[0_0_30px_-8px_hsl(0_90%_60%/0.4)]',
    bg: 'bg-red-950/30',
    tag: 'text-red-400 bg-red-950 border-red-800',
  },
};

const simulationChoices: Array<{ key: SimulationAttackType; label: string; icon: string }> = [
  { key: 'ssh', label: 'SSH Brute Force', icon: '🔐' },
  { key: 'dns', label: 'DNS Attack', icon: '🌐' },
  { key: 'arp', label: 'ARP Spoof', icon: '🕸️' },
  { key: 'portscan', label: 'Port Scan', icon: '🔍' },
  { key: 'icmp', label: 'ICMP Flood', icon: '🌊' },
  { key: 'all', label: 'All Vectors', icon: '⚡' },
];

const HomeScreen = ({ onNavigate, onStartSimulation }: Props) => {
  const [honeypotActive, setHoneypotActive] = useState<boolean>(false);
  const [honeypotHint, setHoneypotHint] = useState<string>('Checking status...');
  const [showSimulationChooser, setShowSimulationChooser] = useState(false);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const health = await getHealth();
        if (!active) return;
        setHoneypotActive(Boolean(health.honeypotActive));
        setHoneypotHint(health.honeypotHint || 'Start honeypot_manager.py first, then retry simulation.');
      } catch {
        if (!active) return;
        setHoneypotActive(false);
        setHoneypotHint('Cannot reach API. Start frontend API bridge and honeypot manager.');
      }
    };
    load();
    const interval = setInterval(load, 10000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="flex-1 flex flex-col items-center justify-center p-8 cyber-grid"
    >
      {/* Hero header */}
      <motion.div
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="text-center mb-10"
      >
        <div className="flex items-center justify-center gap-2 mb-3">
          <span className="h-px w-16 bg-gradient-to-r from-transparent to-primary/60" />
          <Zap className="w-4 h-4 text-primary animate-pulse-glow" />
          <span className="h-px w-16 bg-gradient-to-l from-transparent to-primary/60" />
        </div>
        <h2 className="text-4xl font-bold text-primary text-glow-primary font-display tracking-widest uppercase mb-1">
          CONTROL CENTER
        </h2>
        <p className="text-muted-foreground font-mono text-xs tracking-[0.3em] uppercase">
          Select an operation vector to begin
        </p>
        <div className={`mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-sm font-mono text-xs tracking-wider border ${
          honeypotActive
            ? 'bg-green-950/50 border-green-800 text-green-400 shadow-[0_0_12px_-4px_hsl(120_100%_50%/0.4)]'
            : 'bg-red-950/50 border-red-900 text-red-400'
        }`}>
          <span className={`w-2 h-2 rounded-full ${honeypotActive ? 'bg-green-400 animate-pulse' : 'bg-red-500'} shadow-[0_0_6px_currentColor]`} />
          <span className="uppercase">Honeypot: {honeypotActive ? 'ACTIVE' : 'INACTIVE'}</span>
          <span className="text-muted-foreground">·</span>
          <span className="truncate max-w-xs">{honeypotHint}</span>
        </div>
      </motion.div>

      {/* Action cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-4xl w-full">
        {cards.map((card, i) => {
          const s = accentStyles[card.accent];
          const isLocked = card.screen === 'simulation' && !honeypotActive;
          return (
            <motion.button
              key={card.title}
              initial={{ y: 30, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.15 + i * 0.08 }}
              whileHover={{ y: -5 }}
              whileTap={{ scale: 0.98, y: 0 }}
              onClick={() => {
                if (card.screen === 'simulation') {
                  setShowSimulationChooser(true);
                  return;
                }
                onNavigate(card.screen);
              }}
              className={`group relative cyber-card ${s.border} ${s.glow} rounded-lg p-6 text-left transition-all duration-300 ${isLocked ? 'opacity-75' : ''} overflow-hidden`}
            >
              {/* Corner accents */}
              <span className={`absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 ${s.text.replace('text-', 'border-')} opacity-60 group-hover:opacity-100 transition-opacity`} />
              <span className={`absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 ${s.text.replace('text-', 'border-')} opacity-60 group-hover:opacity-100 transition-opacity`} />

              {/* Tag */}
              <span className={`absolute top-3 right-3 text-[9px] font-mono font-bold px-2 py-0.5 rounded-sm border tracking-widest ${s.tag}`}>
                {card.tag}
              </span>

              {/* Icon */}
              <div className={`w-12 h-12 rounded-sm cyber-icon flex items-center justify-center mb-4 ${s.text} group-hover:scale-110 transition-transform duration-200`}>
                {card.icon}
              </div>

              {/* Text */}
              <h3 className={`text-lg font-bold tracking-wide mb-2 font-display ${s.text} group-hover:text-glow-primary`}>
                {card.title}
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed font-sans">
                {card.description}
              </p>

              {isLocked && (
                <p className="mt-3 text-[10px] font-mono text-yellow-500 border border-yellow-900/50 bg-yellow-950/30 px-2 py-1 rounded-sm">
                  ⚠ HONEYPOT INACTIVE — Start may be rejected by API
                </p>
              )}

              {/* Bottom scan line on hover */}
              <span className={`absolute bottom-0 left-0 right-0 h-0.5 ${s.bg.replace('bg-', 'bg-').replace('/30', '')} opacity-0 group-hover:opacity-100 transition-opacity`}
                style={{ background: `linear-gradient(90deg, transparent, currentColor, transparent)` }} />
            </motion.button>
          );
        })}
      </div>

      {/* Simulation Chooser Modal */}
      <AnimatePresence>
        {showSimulationChooser && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[80] bg-black/80 backdrop-blur-sm flex items-center justify-center p-6"
            onClick={() => setShowSimulationChooser(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 12, scale: 0.97 }}
              className="max-w-2xl w-full cyber-card rounded-lg p-6 relative"
              onClick={e => e.stopPropagation()}
            >
              {/* Corner decorations */}
              <span className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-primary/80" />
              <span className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-primary/80" />

              <div className="flex items-center gap-2 mb-2">
                <Terminal className="w-4 h-4 text-primary" />
                <h3 className="text-lg font-bold font-display tracking-wider text-primary text-glow-primary uppercase">
                  Select Attack Vector
                </h3>
              </div>
              <p className="text-xs font-mono text-muted-foreground mb-5 tracking-wider">
                Choose one vector or execute all attack simulations concurrently
              </p>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {simulationChoices.map(choice => (
                  <button
                    key={choice.key}
                    className={`cyber-btn rounded-sm px-4 py-3 text-sm font-mono flex flex-col items-start gap-1 ${
                      choice.key === 'all' ? 'cyber-btn-primary col-span-full' : ''
                    }`}
                    onClick={() => {
                      setShowSimulationChooser(false);
                      onStartSimulation(choice.key);
                    }}
                  >
                    <span className="text-base">{choice.icon}</span>
                    <span className="tracking-wider">{choice.label}</span>
                  </button>
                ))}
              </div>

              <div className="cyber-divider my-4" />
              <button
                className="text-xs font-mono text-muted-foreground hover:text-foreground transition-colors tracking-widest"
                onClick={() => setShowSimulationChooser(false)}
              >
                [ ESC ] CANCEL
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default HomeScreen;
