import { useState } from 'react';
import { AnimatePresence } from 'framer-motion';
import Header from '@/components/Header';
import HomeScreen from '@/components/HomeScreen';
import SimulationScreen from '@/components/SimulationScreen';
import PostSimulationScreen from '@/components/PostSimulationScreen';
import DataExplorerScreen from '@/components/DataExplorerScreen';
import TrainingScreen from '@/components/TrainingScreen';
import DashboardScreen from '@/components/DashboardScreen';
import ErrorBoundary from '@/components/ErrorBoundary';
import { stopAllSimulations, type SimulationAttackType } from '@/lib/api';

type Screen = 'home' | 'simulation' | 'data' | 'training' | 'dashboard' | 'post-simulation';

const Index = () => {
  const [screen, setScreen] = useState<Screen>('home');
  const [prevScreen, setPrevScreen] = useState<Screen>('home');
  const [simulationAttackType, setSimulationAttackType] = useState<SimulationAttackType>('all');

  const navigate = (next: Screen) => {
    if (screen === 'simulation' && next !== 'simulation') {
      void stopAllSimulations().catch(() => {
        // keep navigation responsive even if stop call fails
      });
    }
    setPrevScreen(screen);
    setScreen(next);
  };

  const goHome = () => navigate('home');

  const startSimulationForType = (attackType: SimulationAttackType) => {
    setSimulationAttackType(attackType);
    navigate('simulation');
  };

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <Header onHomeClick={goHome} />
      <ErrorBoundary onHomeClick={goHome}>
        <AnimatePresence mode="wait">
          {screen === 'home' && <HomeScreen key="home" onNavigate={navigate} onStartSimulation={startSimulationForType} />}
          {screen === 'simulation' && <SimulationScreen key="sim" onComplete={() => navigate('post-simulation')} onHomeClick={goHome} attackType={simulationAttackType} />}
          {screen === 'post-simulation' && <PostSimulationScreen key="post" onNavigate={navigate} />}
          {screen === 'data' && <DataExplorerScreen key="data" onNavigate={navigate} previousScreen={prevScreen} />}
          {screen === 'training' && <TrainingScreen key="train" onNavigate={navigate} />}
          {screen === 'dashboard' && <DashboardScreen key="dash" onNavigate={navigate} />}
        </AnimatePresence>
      </ErrorBoundary>
    </div>
  );
};

export default Index;
