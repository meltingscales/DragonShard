import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import type { FuzzingSession, GeneticAlgorithmStats } from '../types/api';

const FuzzingProgress: React.FC = () => {
  const [sessions, setSessions] = useState<FuzzingSession[]>([]);
  const [stats, setStats] = useState<GeneticAlgorithmStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadFuzzingData();
    const interval = setInterval(loadFuzzingData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadFuzzingData = async () => {
    try {
      setError(null);
      const [fuzzingSessions, fuzzingStats] = await Promise.all([
        ApiService.getFuzzingSessions(),
        ApiService.getFuzzingStats(),
      ]);
      setSessions(fuzzingSessions);
      setStats(fuzzingStats);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load fuzzing data');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-green-500';
      case 'completed':
        return 'bg-blue-500';
      case 'paused':
        return 'bg-yellow-500';
      case 'idle':
        return 'bg-gray-500';
      default:
        return 'bg-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🧬 Genetic Algorithm</h3>
        <div className="text-center text-gray-400">Loading...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🧬 Genetic Algorithm</h3>
        <div className="text-red-400">{error}</div>
      </div>
    );
  }

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <h3 className="text-dragon-primary font-semibold mb-4">🧬 Genetic Algorithm</h3>
      
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="bg-dragon-dark rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-green-400">{stats.active_sessions}</div>
            <div className="text-xs text-gray-400">Active Sessions</div>
          </div>
          <div className="bg-dragon-dark rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-blue-400">{stats.best_fitness.toFixed(2)}</div>
            <div className="text-xs text-gray-400">Best Fitness</div>
          </div>
        </div>
      )}

      {/* Sessions */}
      {sessions.length === 0 ? (
        <div className="text-center text-gray-400 py-8">
          No fuzzing sessions
        </div>
      ) : (
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {sessions.map((session) => (
            <div key={session.id} className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-semibold text-white">{session.name}</h4>
                <span className={`px-2 py-1 rounded text-xs font-semibold ${getStatusColor(session.status)}`}>
                  {session.status}
                </span>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm mb-3">
                <div>
                  <span className="text-gray-400">Target:</span>
                  <div className="text-white truncate">{session.target}</div>
                </div>
                <div>
                  <span className="text-gray-400">Type:</span>
                  <div className="text-white">{session.payload_type}</div>
                </div>
              </div>
              
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div className="text-center">
                  <div className="text-blue-400 font-semibold">{session.generation}</div>
                  <div className="text-gray-400">Generation</div>
                </div>
                <div className="text-center">
                  <div className="text-green-400 font-semibold">{session.population_size}</div>
                  <div className="text-gray-400">Population</div>
                </div>
                <div className="text-center">
                  <div className="text-yellow-400 font-semibold">{session.mutations_count}</div>
                  <div className="text-gray-400">Mutations</div>
                </div>
              </div>
              
              <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-gray-400">Best Fitness:</span>
                  <div className="text-green-400 font-semibold">{session.best_fitness.toFixed(3)}</div>
                </div>
                <div>
                  <span className="text-gray-400">Avg Fitness:</span>
                  <div className="text-blue-400 font-semibold">{session.average_fitness.toFixed(3)}</div>
                </div>
              </div>
              
              {session.start_time && (
                <div className="mt-2 text-xs text-gray-500">
                  Started: {new Date(session.start_time).toLocaleString()}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default FuzzingProgress; 