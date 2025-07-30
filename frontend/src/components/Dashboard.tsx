import React, { useState, useEffect } from 'react';
import { ApiService, WebSocketService } from '../services/api';
import type { AttackSummary, VulnerabilitySummary, GeneticAlgorithmStats, SessionSummary, MutationNode } from '../types/api';
import AttackMonitor from './AttackMonitor';
import VulnerabilityMap from './VulnerabilityMap';
import NetworkGraph from './NetworkGraph';
import FuzzingProgress from './FuzzingProgress';
import SessionManager from './SessionManager';
import GeneticAlgorithmViz from './GeneticAlgorithmViz';
import WebFuzzingViz from './WebFuzzingViz';
import MutationTree from './MutationTree';

const Dashboard: React.FC = () => {
  const [attackSummary, setAttackSummary] = useState<AttackSummary | null>(null);
  const [vulnSummary, setVulnSummary] = useState<VulnerabilitySummary | null>(null);
  const [fuzzingStats, setFuzzingStats] = useState<GeneticAlgorithmStats | null>(null);
  const [sessionSummary, setSessionSummary] = useState<SessionSummary | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Load initial data
    loadData();

    // Set up WebSocket connection
    const ws = new WebSocketService();
    ws.connect(
      (message) => {
        console.log('WebSocket message:', message);
        // Refresh data when we receive updates
        if (message.type.startsWith('attack_') || 
            message.type.startsWith('vulnerability_') || 
            message.type.startsWith('fuzzing_') || 
            message.type.startsWith('session_')) {
          loadData();
        }
      },
      (error) => {
        console.error('WebSocket error:', error);
        setIsConnected(false);
      }
    );

    setIsConnected(true);

    // Set up periodic refresh
    const interval = setInterval(loadData, 30000); // Refresh every 30 seconds

    return () => {
      clearInterval(interval);
      ws.disconnect();
    };
  }, []);

  const loadData = async () => {
    try {
      setError(null);
      const [attacks, vulns, fuzzing, sessions] = await Promise.all([
        ApiService.getAttackSummary(),
        ApiService.getVulnerabilitySummary(),
        ApiService.getFuzzingStats(),
        ApiService.getSessionSummary(),
      ]);

      setAttackSummary(attacks);
      setVulnSummary(vulns);
      setFuzzingStats(fuzzing);
      setSessionSummary(sessions);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
      console.error('Error loading dashboard data:', err);
    }
  };

  if (error) {
    return (
      <div className="min-h-screen bg-dragon-dark flex items-center justify-center">
        <div className="bg-red-600 text-white p-6 rounded-lg">
          <h2 className="text-xl font-bold mb-2">Error Loading Dashboard</h2>
          <p>{error}</p>
          <button 
            onClick={loadData}
            className="mt-4 bg-red-700 hover:bg-red-800 px-4 py-2 rounded"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dragon-dark text-white">
      {/* Header */}
      <header className="bg-gradient-to-r from-dragon-primary to-dragon-secondary p-6">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-4xl font-bold mb-2">🐉 DragonShard Visualization</h1>
          <p className="text-lg opacity-90">Real-time attack monitoring and network analysis</p>
          <div className="flex items-center mt-4">
            <div className={`w-3 h-3 rounded-full mr-2 ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
            <span className="text-sm">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto p-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Attack Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <h3 className="text-dragon-primary font-semibold mb-4">⚔️ Attack Statistics</h3>
            {attackSummary ? (
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-dragon-primary">{attackSummary.total_attacks}</div>
                  <div className="text-sm text-gray-400">Total Attacks</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">{attackSummary.running_attacks}</div>
                  <div className="text-sm text-gray-400">Running</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">{attackSummary.completed_attacks}</div>
                  <div className="text-sm text-gray-400">Completed</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-400">{attackSummary.success_rate.toFixed(1)}%</div>
                  <div className="text-sm text-gray-400">Success Rate</div>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-400">Loading...</div>
            )}
          </div>

          {/* Vulnerability Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <h3 className="text-dragon-primary font-semibold mb-4">🛡️ Vulnerability Summary</h3>
            {vulnSummary ? (
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-400">{vulnSummary.critical_count}</div>
                  <div className="text-sm text-gray-400">Critical</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-400">{vulnSummary.high_count}</div>
                  <div className="text-sm text-gray-400">High</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-400">{vulnSummary.medium_count}</div>
                  <div className="text-sm text-gray-400">Medium</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">{vulnSummary.low_count}</div>
                  <div className="text-sm text-gray-400">Low</div>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-400">Loading...</div>
            )}
          </div>

          {/* Network Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <h3 className="text-dragon-primary font-semibold mb-4">🌐 Network Topology</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-400">1</div>
                <div className="text-sm text-gray-400">Hosts</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-400">2</div>
                <div className="text-sm text-gray-400">Services</div>
              </div>
            </div>
          </div>

          {/* Fuzzing Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <h3 className="text-dragon-primary font-semibold mb-4">🧬 Genetic Algorithm</h3>
            {fuzzingStats ? (
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">{fuzzingStats.active_sessions}</div>
                  <div className="text-sm text-gray-400">Active Sessions</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">{fuzzingStats.best_fitness.toFixed(2)}</div>
                  <div className="text-sm text-gray-400">Best Fitness</div>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-400">Loading...</div>
            )}
          </div>
        </div>

        {/* Components Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <AttackMonitor />
          <VulnerabilityMap />
          <NetworkGraph />
          <FuzzingProgress />
        </div>

        {/* Advanced Visualization Components */}
        <div className="mt-6">
          <GeneticAlgorithmViz />
        </div>
        
        <div className="mt-6">
          <WebFuzzingViz />
        </div>

        <div className="mt-6">
          <MutationTree 
            nodes={{}} 
            onNodeSelect={(node) => console.log('Selected node:', node)}
          />
        </div>

        <div className="mt-6">
          <SessionManager />
        </div>
      </main>
    </div>
  );
};

export default Dashboard; 