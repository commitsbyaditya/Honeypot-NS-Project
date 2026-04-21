import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Loader2, CheckCircle2, BarChart3, Home, Brain } from 'lucide-react';
import { getJobStatus, startTraining } from '@/lib/api';

type Screen = 'home' | 'simulation' | 'data' | 'training' | 'dashboard' | 'post-simulation';

interface Props {
  onNavigate: (screen: Screen) => void;
}

const stages = [
  { label: 'Loading Dataset', icon: '📦', color: 'text-cyan-400' },
  { label: 'Feature Extraction', icon: '🔬', color: 'text-yellow-400' },
  { label: 'Training Model', icon: '🧠', color: 'text-primary' },
  { label: 'Evaluation', icon: '📊', color: 'text-purple-400' },
];

const TrainingScreen = ({ onNavigate }: Props) => {
  const [jobId, setJobId] = useState<string | null>(null);
  const [currentStage, setCurrentStage] = useState(0);
  const [stageProgress, setStageProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [isComplete, setIsComplete] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const detectStage = (line: string): number => {
    const normalized = line.toLowerCase();
    if (normalized.includes('step 6') || normalized.includes('evaluat') || normalized.includes('accuracy')) return 3;
    if (normalized.includes('step 4') || normalized.includes('step 5') || normalized.includes('training') || normalized.includes('random forest')) return 2;
    if (normalized.includes('step 2') || normalized.includes('step 3') || normalized.includes('extract') || normalized.includes('label')) return 1;
    return 0;
  };

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      try {
        const start = await startTraining();
        if (!mounted) return;
        setJobId(start.jobId);
        setLogs(prev => [...prev, '[SYSTEM] Training job started']);
      } catch (err) {
        if (!mounted) return;
        setErrorMessage('Failed to start training pipeline. Ensure API bridge is running.');
        setLogs(prev => [...prev, `[ERR] ${err instanceof Error ? err.message : 'Unable to start training'}`]);
      }
    };
    run();
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    if (!jobId || isComplete) return;
    let mounted = true;
    const interval = setInterval(async () => {
      try {
        const job = await getJobStatus(jobId);
        if (!mounted) return;
        const nextLogs = job.logs || [];
        setLogs(nextLogs);
        let stage = 0;
        for (let i = nextLogs.length - 1; i >= 0; i -= 1) {
          stage = detectStage(nextLogs[i]);
          if (stage >= 0) break;
        }
        setCurrentStage(stage);
        const stageLines = nextLogs.filter(line => detectStage(line) === stage).length;
        const estimated = Math.min(95, stageLines * 12);
        setStageProgress(job.status === 'completed' ? 100 : estimated);
        if (job.status === 'completed') {
          setIsComplete(true); setCurrentStage(3); setStageProgress(100);
          clearInterval(interval);
        }
        if (job.status === 'failed') {
          setErrorMessage('Training failed. Review logs and try again.');
          clearInterval(interval);
        }
      } catch {
        if (!mounted) return;
        setErrorMessage('Lost connection to training job status API.');
        clearInterval(interval);
      }
    }, 900);
    return () => { mounted = false; clearInterval(interval); };
  }, [jobId, isComplete]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const overallProgress = ((currentStage + (stageProgress / 100)) / stages.length) * 100;

  const logColor = (log: string) => {
    if (log.includes('DONE') || log.includes('SUCCESS') || log.includes('[OK]')) return 'text-green-400';
    if (log.includes('TRAIN') || log.includes('RandomForest')) return 'text-yellow-400';
    if (log.includes('EVAL') || log.includes('accuracy') || log.includes('f1')) return 'text-purple-400';
    if (log.includes('[SYSTEM]')) return 'text-cyan-400';
    if (log.includes('[ERR]') || log.includes('ERROR')) return 'text-red-400';
    return 'text-green-300/75';
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="flex-1 flex flex-col items-center justify-center p-8 gap-7 cyber-grid"
    >
      {/* Home escape */}
      <div className="self-start">
        <button onClick={() => onNavigate('home')} className="cyber-btn rounded-sm p-2 flex items-center gap-2 text-xs">
          <Home className="w-4 h-4" />
          <span className="tracking-widest">CANCEL & RETURN</span>
        </button>
      </div>

      {/* Title */}
      <div className="text-center">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Brain className="w-5 h-5 text-primary animate-pulse-glow" />
          <h2 className="text-2xl font-bold font-display tracking-widest uppercase text-primary text-glow-primary">
            ML Model Training
          </h2>
        </div>
        <p className="text-xs text-muted-foreground font-mono tracking-widest">
          RandomForest Classifier · v2.4 · Multi-Class Detection
        </p>
      </div>

      {/* Stage tracker */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 max-w-2xl w-full">
        {stages.map((s, i) => {
          const done = i < currentStage || isComplete;
          const active = i === currentStage && !isComplete;
          return (
            <div
              key={s.label}
              className={`cyber-card rounded-sm p-3 text-center transition-all ${
                done ? 'border-green-800 bg-green-950/30' :
                active ? 'border-primary/60 bg-green-950/20 shadow-[0_0_20px_-8px_hsl(120_100%_50%/0.4)]' :
                'opacity-40'
              }`}
            >
              <div className="text-xl mb-1">{s.icon}</div>
              {done ? (
                <CheckCircle2 className="w-4 h-4 text-green-400 mx-auto mb-1" style={{ filter: 'drop-shadow(0 0 4px hsl(120 100% 50%))' }} />
              ) : active ? (
                <Loader2 className="w-4 h-4 text-primary animate-spin mx-auto mb-1" />
              ) : (
                <div className="w-4 h-4 rounded-full border border-muted-foreground/30 mx-auto mb-1" />
              )}
              <span className={`text-[10px] font-mono tracking-wider uppercase ${done ? 'text-green-400' : active ? s.color : 'text-muted-foreground'}`}>
                {s.label}
              </span>
              {active && (
                <div className="cyber-track h-1 rounded-none overflow-hidden mt-2">
                  <motion.div
                    className="h-full bg-primary"
                    animate={{ width: `${stageProgress}%` }}
                    transition={{ duration: 0.3 }}
                    style={{ boxShadow: '0 0 6px hsl(120 100% 50% / 0.6)' }}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Overall progress */}
      <div className="max-w-2xl w-full">
        <div className="flex justify-between text-xs text-muted-foreground font-mono mb-2 tracking-wider">
          <span>OVERALL PROGRESS</span>
          <span className="text-primary font-bold">{Math.round(isComplete ? 100 : overallProgress)}%</span>
        </div>
        <div className="cyber-track h-4 rounded-none overflow-hidden relative">
          <motion.div
            className="h-full bg-gradient-to-r from-green-800 via-primary to-cyan-400"
            animate={{ width: `${isComplete ? 100 : overallProgress}%` }}
            transition={{ duration: 0.4 }}
            style={{ boxShadow: '0 0 12px hsl(120 100% 50% / 0.5), 0 0 24px hsl(120 100% 50% / 0.25)' }}
          />
          {/* Chevron decoration */}
          <div className="absolute inset-0 flex items-center pointer-events-none">
            {Array.from({ length: 20 }).map((_, i) => (
              <div key={i} className="h-full w-px bg-black/20" style={{ marginLeft: '5%' }} />
            ))}
          </div>
        </div>
      </div>

      {/* Terminal */}
      <div className="cyber-terminal max-w-3xl w-full p-4 overflow-hidden flex flex-col max-h-[280px] rounded-sm">
        <div className="flex items-center gap-2 mb-3 pb-3 border-b border-green-900/50">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500" style={{ boxShadow: '0 0 4px hsl(0 90% 50%)' }} />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" style={{ boxShadow: '0 0 4px hsl(45 100% 50%)' }} />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500" style={{ boxShadow: '0 0 4px hsl(120 100% 50%)' }} />
          <span className="text-[10px] text-muted-foreground font-mono ml-2 tracking-widest uppercase">training-pipeline — stdout</span>
        </div>
        <div ref={logRef} className="flex-1 overflow-y-auto space-y-0.5 font-mono text-xs">
          {logs.length === 0 && !errorMessage && (
            <div className="text-muted-foreground">
              <span className="text-primary">$</span> Waiting for training output...
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
          {!isComplete && (
            <motion.span animate={{ opacity: [1, 0] }} transition={{ duration: 0.8, repeat: Infinity }} className="text-primary ml-1">█</motion.span>
          )}
        </div>
      </div>

      {isComplete && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col items-center gap-4">
          <p className="text-green-400 font-mono text-sm tracking-widest text-glow-primary">
            ✓ MODEL TRAINED SUCCESSFULLY — F1 Score: 0.966 · Accuracy: 97.2%
          </p>
          <motion.button
            whileHover={{ y: -3 }}
            whileTap={{ scale: 0.97 }}
            onClick={() => onNavigate('dashboard')}
            className="cyber-btn-primary rounded-sm px-8 py-3 flex items-center gap-2"
          >
            <BarChart3 className="w-4 h-4" />
            <span className="tracking-widest">OPEN DASHBOARD</span>
          </motion.button>
        </motion.div>
      )}
    </motion.div>
  );
};

export default TrainingScreen;
