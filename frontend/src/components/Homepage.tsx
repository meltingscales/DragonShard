import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ApiService } from '../services/api';
import type { AttackSummary, VulnerabilitySummary, GeneticAlgorithmStats, SessionSummary } from '../types/api';
import { Shield, Zap, BarChart3, Network, Target, AlertTriangle, Activity, Users } from 'lucide-react';

const Homepage: React.FC = () => {
  const [attackSummary, setAttackSummary] = useState<AttackSummary | null>(null);
  const [vulnSummary, setVulnSummary] = useState<VulnerabilitySummary | null>(null);
  const [fuzzingStats, setFuzzingStats] = useState<GeneticAlgorithmStats | null>(null);
  const [sessionSummary, setSessionSummary] = useState<SessionSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
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
      setLoading(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-dragon-dark flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-dragon-primary mx-auto"></div>
          <p className="mt-4 text-gray-400">Loading DragonShard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-dragon-dark flex items-center justify-center">
        <div className="bg-red-600 text-white p-6 rounded-lg max-w-md">
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
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-dragon-primary to-dragon-secondary py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="flex justify-center mb-6">
            <Shield className="h-20 w-20 text-white" />
          </div>
          <h1 className="text-5xl font-bold mb-6">DragonShard</h1>
          <p className="text-xl mb-8 opacity-90 max-w-3xl mx-auto">
            Autonomous offensive security tool designed to discover vulnerabilities, 
            infer API structure, fuzz endpoints, and plan multi-stage exploit chains.
          </p>
          <div className="flex justify-center space-x-4">
            <Link
              to="/visualizations"
              className="bg-white text-dragon-primary px-6 py-3 rounded-lg font-semibold hover:bg-gray-100 transition-colors"
            >
              View Visualizations
            </Link>
            <Link
              to="/attacks"
              className="border border-white text-white px-6 py-3 rounded-lg font-semibold hover:bg-white hover:text-dragon-primary transition-colors"
            >
              Monitor Attacks
            </Link>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h2 className="text-3xl font-bold mb-8 text-center">System Overview</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {/* Attack Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <Zap className="h-8 w-8 text-blue-400" />
              <span className="text-sm text-gray-400">Attacks</span>
            </div>
            {attackSummary ? (
              <div className="space-y-2">
                <div className="text-2xl font-bold text-blue-400">{attackSummary.total_attacks}</div>
                <div className="text-sm text-gray-400">
                  {attackSummary.running_attacks} running • {attackSummary.success_rate.toFixed(1)}% success
                </div>
              </div>
            ) : (
              <div className="text-gray-400">Loading...</div>
            )}
          </div>

          {/* Vulnerability Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <AlertTriangle className="h-8 w-8 text-red-400" />
              <span className="text-sm text-gray-400">Vulnerabilities</span>
            </div>
            {vulnSummary ? (
              <div className="space-y-2">
                <div className="text-2xl font-bold text-red-400">{vulnSummary.total_vulnerabilities}</div>
                <div className="text-sm text-gray-400">
                  {vulnSummary.critical_count} critical • {vulnSummary.high_count} high
                </div>
              </div>
            ) : (
              <div className="text-gray-400">Loading...</div>
            )}
          </div>

          {/* Fuzzing Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <Activity className="h-8 w-8 text-green-400" />
              <span className="text-sm text-gray-400">Fuzzing</span>
            </div>
            {fuzzingStats ? (
              <div className="space-y-2">
                <div className="text-2xl font-bold text-green-400">{fuzzingStats.active_sessions}</div>
                <div className="text-sm text-gray-400">
                  {fuzzingStats.total_generations} generations • {fuzzingStats.best_fitness.toFixed(2)} fitness
                </div>
              </div>
            ) : (
              <div className="text-gray-400">Loading...</div>
            )}
          </div>

          {/* Session Stats */}
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <Users className="h-8 w-8 text-purple-400" />
              <span className="text-sm text-gray-400">Sessions</span>
            </div>
            {sessionSummary ? (
              <div className="space-y-2">
                <div className="text-2xl font-bold text-purple-400">{sessionSummary.total_sessions}</div>
                <div className="text-sm text-gray-400">
                  {sessionSummary.authenticated_sessions} authenticated • {sessionSummary.active_sessions} active
                </div>
              </div>
            ) : (
              <div className="text-gray-400">Loading...</div>
            )}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Link
            to="/visualizations"
            className="bg-dragon-card border border-dragon-border rounded-lg p-6 hover:border-dragon-primary transition-colors group"
          >
            <div className="flex items-center mb-4">
              <BarChart3 className="h-8 w-8 text-blue-400 mr-3" />
              <h3 className="text-xl font-semibold">Visualizations</h3>
            </div>
            <p className="text-gray-400 mb-4">
              Explore real-time network topology, genetic algorithm progress, and mutation trees with interactive visualizations.
            </p>
            <div className="text-dragon-primary group-hover:text-blue-400 transition-colors">
              View Visualizations →
            </div>
          </Link>

          <Link
            to="/attacks"
            className="bg-dragon-card border border-dragon-border rounded-lg p-6 hover:border-dragon-primary transition-colors group"
          >
            <div className="flex items-center mb-4">
              <Target className="h-8 w-8 text-red-400 mr-3" />
              <h3 className="text-xl font-semibold">Attack Monitor</h3>
            </div>
            <p className="text-gray-400 mb-4">
              Monitor active attack chains, track progress, and manage multi-stage exploit execution.
            </p>
            <div className="text-dragon-primary group-hover:text-red-400 transition-colors">
              Monitor Attacks →
            </div>
          </Link>

          <Link
            to="/network"
            className="bg-dragon-card border border-dragon-border rounded-lg p-6 hover:border-dragon-primary transition-colors group"
          >
            <div className="flex items-center mb-4">
              <Network className="h-8 w-8 text-green-400 mr-3" />
              <h3 className="text-xl font-semibold">Network Topology</h3>
            </div>
            <p className="text-gray-400 mb-4">
              Explore discovered hosts, services, and vulnerabilities in an interactive network graph.
            </p>
            <div className="text-dragon-primary group-hover:text-green-400 transition-colors">
              View Network →
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Homepage; 