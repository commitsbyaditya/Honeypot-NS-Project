import { motion } from 'framer-motion';
import { Database, Brain, BarChart3, CheckCircle2, Home, Zap } from 'lucide-react';

type Screen = 'home' | 'simulation' | 'data' | 'training' | 'dashboard' | 'post-simulation';

interface Props {
  onNavigate: (screen: Screen) => void;
}

const nextSteps = [
  {
    icon: <Database className="w-7 h-7" />,
    title: 'Inspect Data',
    description: 'Review captured sessions and attack payloads',
    screen: 'data' as Screen,
    color: 'text-cyan-400',
    border: 'border-cyan-800 hover:border-cyan-600',
    glow: 'hover:shadow-[0_0_20px_-6px_hsl(185_100%_50%/0.4)]',
  },
  {
    icon: <Brain className="w-7 h-7" />,
    title: 'Train Model',
    description: 'Update detection model with fresh attack data',
    screen: 'training' as Screen,
    color: 'text-yellow-400',
    border: 'border-yellow-900 hover:border-yellow-700',
    glow: 'hover:shadow-[0_0_20px_-6px_hsl(45_100%_55%/0.4)]',
  },
  {
    icon: <BarChart3 className="w-7 h-7" />,
    title: 'Dashboard',
    description: 'View threat analytics and detection metrics',
    screen: 'dashboard' as Screen,
    color: 'text-primary',
    border: 'border-green-900 hover:border-green-600',
    glow: 'hover:shadow-[0_0_20px_-6px_hsl(120_100%_50%/0.4)]',
  },
];

const PostSimulationScreen = ({ onNavigate }: Props) => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    className="flex-1 flex flex-col items-center justify-center p-8 cyber-grid"
  >
    {/* Success icon */}
    <motion.div initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ type: 'spring', stiffness: 200, damping: 15 }} className="text-center mb-8">
      <div className="relative w-20 h-20 mx-auto mb-5">
        <div className="w-20 h-20 rounded-sm border-2 border-green-500/60 flex items-center justify-center bg-green-950/50"
          style={{ boxShadow: '0 0 30px hsl(120 100% 50% / 0.3), 0 0 60px hsl(120 100% 50% / 0.15)' }}
        >
          <CheckCircle2 className="w-10 h-10 text-primary" style={{ filter: 'drop-shadow(0 0 8px hsl(120 100% 50%))' }} />
        </div>
        {/* Pulsing ring */}
        <motion.div
          animate={{ scale: [1, 1.4, 1], opacity: [0.5, 0, 0.5] }}
          transition={{ duration: 2, repeat: Infinity }}
          className="absolute inset-0 rounded-sm border-2 border-primary/40"
        />
      </div>

      <div className="flex items-center justify-center gap-2 mb-2">
        <span className="h-px w-12 bg-gradient-to-r from-transparent to-primary/60" />
        <Zap className="w-3.5 h-3.5 text-primary" />
        <span className="h-px w-12 bg-gradient-to-l from-transparent to-primary/60" />
      </div>
      <h2 className="text-2xl font-bold font-display tracking-widest uppercase text-primary text-glow-primary mb-2">
        Simulation Complete
      </h2>
      <p className="text-muted-foreground font-mono text-xs tracking-widest">
        5 attack vectors executed · 47 sessions captured
      </p>
    </motion.div>

    {/* Recommendation banner */}
    <motion.div
      initial={{ y: 10, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ delay: 0.2 }}
      className="cyber-alert rounded-sm px-5 py-3 mb-8 inline-flex items-center gap-3 font-mono text-xs tracking-wider"
    >
      <Brain className="w-4 h-4 flex-shrink-0" />
      <span>RECOMMENDED: Train model on newly captured attack data</span>
    </motion.div>

    {/* Next step cards */}
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl w-full mb-8">
      {nextSteps.map((step, i) => (
        <motion.button
          key={step.title}
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.3 + i * 0.1 }}
          whileHover={{ y: -5 }}
          whileTap={{ scale: 0.97 }}
          onClick={() => onNavigate(step.screen)}
          className={`cyber-card ${step.border} ${step.glow} rounded-sm p-5 text-left transition-all duration-250 relative overflow-hidden group`}
        >
          {/* Corner decorations */}
          <span className={`absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 ${step.color.replace('text-', 'border-')} opacity-50 group-hover:opacity-100 transition-opacity`} />
          <span className={`absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 ${step.color.replace('text-', 'border-')} opacity-50 group-hover:opacity-100 transition-opacity`} />

          <div className={`${step.color} mb-4 group-hover:scale-110 transition-transform duration-200`}>{step.icon}</div>
          <h3 className={`font-bold font-display tracking-wider uppercase text-sm mb-1.5 ${step.color}`}>{step.title}</h3>
          <p className="text-xs text-muted-foreground font-sans leading-relaxed">{step.description}</p>
        </motion.button>
      ))}
    </div>

    {/* Back home */}
    <motion.button
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.7 }}
      onClick={() => onNavigate('home')}
      className="cyber-btn rounded-sm px-5 py-2 flex items-center gap-2 text-xs"
    >
      <Home className="w-3.5 h-3.5" />
      <span className="tracking-widest">RETURN TO BASE</span>
    </motion.button>
  </motion.div>
);

export default PostSimulationScreen;
