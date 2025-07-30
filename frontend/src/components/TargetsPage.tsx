import React, { useState, useEffect } from 'react';
import { Target, Plus, Search, Eye, Zap, AlertTriangle, Play, Square, Trash2, RefreshCw } from 'lucide-react';
import { ApiService } from '../services/api';
import type { Host, Vulnerability, AttackChain } from '../types/api';

interface TargetFormData {
  ip_address: string;
  hostname?: string;
  description?: string;
}

interface ScanResult {
  host: Host;
  vulnerabilities: Vulnerability[];
  scan_status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
}

const TargetsPage: React.FC = () => {
  const [targets, setTargets] = useState<Host[]>([]);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);


  useEffect(() => {
    loadTargets();
    const interval = setInterval(loadTargets, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadTargets = async () => {
    try {
      setError(null);
      const hosts = await ApiService.getHosts();
      setTargets(hosts);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  const addTarget = () => {
    const targetWindow = window.open('/targets/add', 'addTarget', 'width=500,height=600,scrollbars=yes,resizable=yes');
    if (targetWindow) {
      targetWindow.focus();
    }
  };

  const scanTarget = async (targetId: string) => {
    try {
      setError(null);
      await ApiService.scanTarget(targetId);
      // Update scan results
      const updatedResults = scanResults.map(result => 
        result.host.id === targetId 
          ? { ...result, scan_status: 'running' as const, progress: 0 }
          : result
      );
      setScanResults(updatedResults);
    } catch (err) {
      setError('Failed to start scan');
    }
  };

  const stageAttack = (targetId: string, vulnerabilityId: string) => {
    const attackWindow = window.open(`/attacks/stage?target=${targetId}&vuln=${vulnerabilityId}`, 'stageAttack', 'width=800,height=600,scrollbars=yes,resizable=yes');
    if (attackWindow) {
      attackWindow.focus();
    }
  };

  const getVulnerabilityColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getScanStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-blue-400';
      case 'completed': return 'text-green-400';
      case 'failed': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-dark text-white">
        <div className="container p-6">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
            <p className="mt-4 text-gray-400">Loading targets...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark text-white">
      {/* Header */}
      <div className="bg-primary p-6">
        <div className="container">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold mb-2">🎯 Target Management</h1>
              <p className="text-lg opacity-90">Add targets, scan for vulnerabilities, and stage attacks</p>
            </div>
            <button
              onClick={addTarget}
              className="btn btn-primary flex items-center"
            >
              <Plus className="w-5 h-5 mr-2" />
              Add Target
            </button>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="container p-4">
          <div className="bg-danger text-white p-4 rounded">
            <div className="flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" />
              <span>{error}</span>
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      <div className="container p-6">
        {/* Targets Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          {targets.map((target) => (
            <div key={target.id} className="card">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center">
                  <Target className="h-6 w-6 text-primary mr-2" />
                  <h3 className="text-lg font-semibold">{target.hostname || target.ip_address}</h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      const detailsWindow = window.open(`/targets/${target.id}`, 'targetDetails', 'width=800,height=600,scrollbars=yes,resizable=yes');
                      if (detailsWindow) {
                        detailsWindow.focus();
                      }
                    }}
                    className="text-info hover:text-blue-300 p-1"
                    title="View Details"
                  >
                    <Eye className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => scanTarget(target.id)}
                    className="text-warning hover:text-yellow-300 p-1"
                    title="Scan Target"
                  >
                    <Search className="w-4 h-4" />
                  </button>
                </div>
              </div>
              
              <div className="space-y-2 mb-4">
                <div className="text-sm">
                  <span className="text-gray-400">IP:</span> {target.ip_address}
                </div>
                {target.os_info && (
                  <div className="text-sm">
                    <span className="text-gray-400">OS:</span> {target.os_info}
                  </div>
                )}
                <div className="text-sm">
                  <span className="text-gray-400">Services:</span> {target.services.length}
                </div>
                <div className="text-sm">
                  <span className="text-gray-400">Vulnerabilities:</span> {target.vulnerabilities.length}
                </div>
              </div>

              {/* Vulnerability Summary */}
              {target.vulnerabilities.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-sm font-semibold mb-2">Vulnerabilities:</h4>
                  <div className="flex flex-wrap gap-1">
                    {target.vulnerabilities.slice(0, 3).map((vuln) => (
                      <span
                        key={vuln.id}
                        className={`px-2 py-1 rounded text-xs ${getVulnerabilityColor(vuln.level)}`}
                      >
                        {vuln.level}
                      </span>
                    ))}
                    {target.vulnerabilities.length > 3 && (
                      <span className="px-2 py-1 rounded text-xs bg-gray-500">
                        +{target.vulnerabilities.length - 3}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex gap-2">
                {target.vulnerabilities.length > 0 && (
                  <button
                    onClick={() => stageAttack(target.id, target.vulnerabilities[0].id)}
                    className="btn btn-primary text-sm flex-1"
                  >
                    <Zap className="w-4 h-4 mr-1" />
                    Stage Attack
                  </button>
                )}
                <button
                  onClick={() => scanTarget(target.id)}
                  className="btn btn-secondary text-sm"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Scan Results */}
        {scanResults.length > 0 && (
          <div className="card">
            <h2 className="text-2xl font-bold text-primary mb-6">🔍 Scan Results</h2>
            <div className="space-y-4">
              {scanResults.map((result) => (
                <div key={result.host.id} className="bg-dark border border-border rounded p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-semibold">{result.host.hostname || result.host.ip_address}</h3>
                    <span className={`text-sm ${getScanStatusColor(result.scan_status)}`}>
                      {result.scan_status}
                    </span>
                  </div>
                  
                  {result.scan_status === 'running' && (
                    <div className="mb-3">
                      <div className="w-full bg-dark rounded-full h-2">
                        <div 
                          className="bg-primary h-2 rounded-full transition-all duration-300"
                          style={{ width: `${result.progress}%` }}
                        ></div>
                      </div>
                      <div className="text-sm text-gray-400 mt-1">
                        Progress: {result.progress}%
                      </div>
                    </div>
                  )}

                  {result.vulnerabilities.length > 0 && (
                    <div>
                      <h4 className="font-semibold mb-2">Found Vulnerabilities:</h4>
                      <div className="space-y-2">
                        {result.vulnerabilities.map((vuln) => (
                          <div key={vuln.id} className="flex items-center justify-between p-2 bg-card rounded">
                            <div>
                              <div className="font-medium">{vuln.name}</div>
                              <div className="text-sm text-gray-400">{vuln.description}</div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-1 rounded text-xs ${getVulnerabilityColor(vuln.level)}`}>
                                {vuln.level}
                              </span>
                              <button
                                onClick={() => stageAttack(result.host.id, vuln.id)}
                                className="btn btn-primary text-xs"
                              >
                                Attack
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>


    </div>
  );
};

export default TargetsPage; 