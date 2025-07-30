import React, { useState, useEffect } from 'react';
import { Zap, Target, AlertTriangle, Play, Square, Plus, Trash2, Eye } from 'lucide-react';
import { ApiService } from '../services/api';
import type { AttackChain, AttackSummary } from '../types/api';

const AttacksPage: React.FC = () => {
  const [attacks, setAttacks] = useState<AttackChain[]>([]);
  const [attackSummary, setAttackSummary] = useState<AttackSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showNewAttackForm, setShowNewAttackForm] = useState(false);
  const [selectedAttack, setSelectedAttack] = useState<AttackChain | null>(null);

  useEffect(() => {
    loadAttacks();
    const interval = setInterval(loadAttacks, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadAttacks = async () => {
    try {
      setError(null);
      const [runningAttacks, summary] = await Promise.all([
        ApiService.getRunningAttacks(),
        ApiService.getAttackSummary(),
      ]);
      setAttacks(runningAttacks);
      setAttackSummary(summary);
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

  const handleStartAttack = async (attackId: string) => {
    try {
      await ApiService.startAttack(attackId);
      loadAttacks(); // Refresh the list
    } catch (err) {
      setError('Failed to start attack');
    }
  };

  const handleStopAttack = async (attackId: string) => {
    try {
      await ApiService.stopAttack(attackId);
      loadAttacks(); // Refresh the list
    } catch (err) {
      setError('Failed to stop attack');
    }
  };

  const handleDeleteAttack = async (attackId: string) => {
    try {
      await ApiService.deleteAttack(attackId);
      loadAttacks(); // Refresh the list
    } catch (err) {
      setError('Failed to delete attack');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-dragon-dark text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-dragon-primary mx-auto"></div>
            <p className="mt-4 text-gray-400">Loading attacks...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dragon-dark text-white">
      {/* Header */}
      <div className="bg-gradient-to-r from-dragon-primary to-dragon-secondary p-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold mb-2">⚡ Attack Management</h1>
              <p className="text-lg opacity-90">Monitor and control attack chains</p>
            </div>
            <button
              onClick={() => setShowNewAttackForm(true)}
              className="bg-dragon-primary hover:bg-dragon-secondary text-white px-6 py-3 rounded-lg font-semibold flex items-center"
            >
              <Plus className="w-5 h-5 mr-2" />
              New Attack
            </button>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="bg-red-600 text-white p-4 rounded-lg">
            <div className="flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" />
              <span>{error}</span>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {attackSummary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <div className="flex items-center">
                <Zap className="h-8 w-8 text-blue-400 mr-3" />
                <div>
                  <div className="text-2xl font-bold text-blue-400">{attackSummary.total_attacks}</div>
                  <div className="text-sm text-gray-400">Total Attacks</div>
                </div>
              </div>
            </div>
            
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <div className="flex items-center">
                <Play className="h-8 w-8 text-green-400 mr-3" />
                <div>
                  <div className="text-2xl font-bold text-green-400">{attackSummary.running_attacks}</div>
                  <div className="text-sm text-gray-400">Running</div>
                </div>
              </div>
            </div>
            
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <div className="flex items-center">
                <Target className="h-8 w-8 text-blue-400 mr-3" />
                <div>
                  <div className="text-2xl font-bold text-blue-400">{attackSummary.completed_attacks}</div>
                  <div className="text-sm text-gray-400">Completed</div>
                </div>
              </div>
            </div>
            
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <div className="flex items-center">
                <AlertTriangle className="h-8 w-8 text-red-400 mr-3" />
                <div>
                  <div className="text-2xl font-bold text-red-400">{attackSummary.failed_attacks}</div>
                  <div className="text-sm text-gray-400">Failed</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Active Attacks */}
        <div className="bg-dragon-card border border-dragon-border rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-dragon-primary">🔥 Active Attacks</h2>
            <button
              onClick={loadAttacks}
              className="text-dragon-primary hover:text-dragon-secondary text-sm"
            >
              Refresh
            </button>
          </div>
          
          {attacks.length === 0 ? (
            <div className="text-center text-gray-400 py-12">
              <Target className="h-16 w-16 mx-auto mb-4 opacity-50" />
              <p className="text-lg mb-2">No active attacks</p>
              <p className="text-sm">Start a new attack to begin monitoring</p>
            </div>
          ) : (
            <div className="space-y-4">
              {attacks.map((attack) => (
                <div key={attack.id} className="bg-dragon-dark border border-dragon-border rounded-lg p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <h3 className="text-lg font-semibold text-white">{attack.name}</h3>
                      <p className="text-gray-400 text-sm">{attack.description}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusColor(attack.status)}`}>
                        {attack.status}
                      </span>
                      <button
                        onClick={() => setSelectedAttack(attack)}
                        className="text-blue-400 hover:text-blue-300 p-1"
                        title="View Details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      {attack.status === 'running' && (
                        <button
                          onClick={() => handleStopAttack(attack.id)}
                          className="text-red-400 hover:text-red-300 p-1"
                          title="Stop Attack"
                        >
                          <Square className="w-4 h-4" />
                        </button>
                      )}
                      {attack.status === 'pending' && (
                        <button
                          onClick={() => handleStartAttack(attack.id)}
                          className="text-green-400 hover:text-green-300 p-1"
                          title="Start Attack"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                      )}
                      <button
                        onClick={() => handleDeleteAttack(attack.id)}
                        className="text-red-400 hover:text-red-300 p-1"
                        title="Delete Attack"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between text-sm mb-3">
                    <span className="text-gray-400">
                      Progress: {attack.completed_steps}/{attack.total_steps}
                    </span>
                    <span className="text-yellow-400">
                      {attack.success_rate.toFixed(1)}% success
                    </span>
                  </div>
                  
                  {/* Progress bar */}
                  <div className="w-full bg-gray-700 rounded-full h-2 mb-4">
                    <div 
                      className="bg-dragon-primary h-2 rounded-full transition-all duration-300"
                      style={{ width: `${(attack.completed_steps / attack.total_steps) * 100}%` }}
                    ></div>
                  </div>
                  
                  {/* Steps */}
                  <div className="space-y-2">
                    {attack.steps.map((step) => (
                      <div key={step.id} className="flex items-center text-sm">
                        <span className={`w-2 h-2 rounded-full mr-3 ${getStatusColor(step.status)}`}></span>
                        <span className="text-gray-300 flex-1">{step.name}</span>
                        {step.duration && (
                          <span className="text-gray-500 text-xs">
                            {step.duration.toFixed(1)}s
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                  
                  {attack.start_time && (
                    <div className="mt-3 text-xs text-gray-500">
                      Started: {new Date(attack.start_time).toLocaleString()}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attack Templates */}
        <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
          <h2 className="text-2xl font-bold text-dragon-primary mb-6">📋 Attack Templates</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
              <h3 className="font-semibold text-white mb-2">SQL Injection</h3>
              <p className="text-gray-400 text-sm mb-3">Automated SQL injection testing with payload generation</p>
              <button className="bg-dragon-primary hover:bg-dragon-secondary text-white px-4 py-2 rounded text-sm">
                Start Template
              </button>
            </div>
            
            <div className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
              <h3 className="font-semibold text-white mb-2">XSS Detection</h3>
              <p className="text-gray-400 text-sm mb-3">Cross-site scripting vulnerability scanner</p>
              <button className="bg-dragon-primary hover:bg-dragon-secondary text-white px-4 py-2 rounded text-sm">
                Start Template
              </button>
            </div>
            
            <div className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
              <h3 className="font-semibold text-white mb-2">Directory Traversal</h3>
              <p className="text-gray-400 text-sm mb-3">Path traversal and file inclusion testing</p>
              <button className="bg-dragon-primary hover:bg-dragon-secondary text-white px-4 py-2 rounded text-sm">
                Start Template
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Details Modal */}
      {selectedAttack && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">Attack Details</h2>
              <button
                onClick={() => setSelectedAttack(null)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <h3 className="font-semibold text-white mb-2">{selectedAttack.name}</h3>
                <p className="text-gray-400">{selectedAttack.description}</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-gray-400 text-sm">Status:</span>
                  <div className="text-white">{selectedAttack.status}</div>
                </div>
                <div>
                  <span className="text-gray-400 text-sm">Success Rate:</span>
                  <div className="text-white">{selectedAttack.success_rate.toFixed(1)}%</div>
                </div>
              </div>
              
              <div>
                <h4 className="font-semibold text-white mb-2">Steps</h4>
                <div className="space-y-2">
                  {selectedAttack.steps.map((step) => (
                    <div key={step.id} className="bg-dragon-dark border border-dragon-border rounded p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white">{step.name}</span>
                        <span className={`px-2 py-1 rounded text-xs ${getStatusColor(step.status)}`}>
                          {step.status}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm">{step.description}</p>
                      {step.target && (
                        <p className="text-gray-400 text-sm">Target: {step.target}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AttacksPage; 