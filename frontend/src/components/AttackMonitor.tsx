import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import type { AttackChain } from '../types/api';

const AttackMonitor: React.FC = () => {
  const [attacks, setAttacks] = useState<AttackChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAttacks();
    const interval = setInterval(loadAttacks, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadAttacks = async () => {
    try {
      setError(null);
      const runningAttacks = await ApiService.getRunningAttacks();
      setAttacks(runningAttacks);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load attacks');
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
      case 'failed':
        return 'bg-red-500';
      case 'pending':
        return 'bg-yellow-500';
      default:
        return 'bg-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🔥 Active Attacks</h3>
        <div className="text-center text-gray-400">Loading...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🔥 Active Attacks</h3>
        <div className="text-red-400">{error}</div>
      </div>
    );
  }

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <h3 className="text-dragon-primary font-semibold mb-4">🔥 Active Attacks</h3>
      
      {attacks.length === 0 ? (
        <div className="text-center text-gray-400 py-8">
          No active attacks
        </div>
      ) : (
        <div className="space-y-4 max-h-96 overflow-y-auto">
          {attacks.map((attack) => (
            <div key={attack.id} className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-semibold text-white">{attack.name}</h4>
                <span className={`px-2 py-1 rounded text-xs font-semibold ${getStatusColor(attack.status)}`}>
                  {attack.status}
                </span>
              </div>
              
              <p className="text-gray-400 text-sm mb-3">{attack.description}</p>
              
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">
                  Progress: {attack.completed_steps}/{attack.total_steps}
                </span>
                <span className="text-yellow-400">
                  {attack.success_rate.toFixed(1)}% success
                </span>
              </div>
              
              {/* Progress bar */}
              <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                <div 
                  className="bg-dragon-primary h-2 rounded-full transition-all duration-300"
                  style={{ width: `${(attack.completed_steps / attack.total_steps) * 100}%` }}
                ></div>
              </div>
              
              {/* Steps */}
              <div className="mt-3 space-y-2">
                {attack.steps.map((step) => (
                  <div key={step.id} className="flex items-center text-xs">
                    <span className={`w-2 h-2 rounded-full mr-2 ${getStatusColor(step.status)}`}></span>
                    <span className="text-gray-400">{step.name}</span>
                    {step.duration && (
                      <span className="ml-auto text-gray-500">
                        {step.duration.toFixed(1)}s
                      </span>
                    )}
                  </div>
                ))}
              </div>
              
              {attack.start_time && (
                <div className="mt-2 text-xs text-gray-500">
                  Started: {new Date(attack.start_time).toLocaleString()}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AttackMonitor; 