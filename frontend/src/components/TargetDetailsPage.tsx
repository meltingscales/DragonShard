import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { X, Zap, Search, RefreshCw } from 'lucide-react';
import { ApiService } from '../services/api';
import type { Host } from '../types/api';

const TargetDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [target, setTarget] = useState<Host | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    if (id) {
      loadTarget();
    }
  }, [id]);

  const loadTarget = async () => {
    try {
      setError(null);
      const host = await ApiService.getTarget(id!);
      setTarget(host);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load target');
    } finally {
      setLoading(false);
    }
  };

  const scanTarget = async () => {
    if (!target) return;
    
    try {
      setScanning(true);
      setError(null);
      await ApiService.scanTarget(target.id);
      // Reload target to get updated scan results
      setTimeout(loadTarget, 2000);
    } catch (err) {
      setError('Failed to start scan');
    } finally {
      setScanning(false);
    }
  };

  const stageAttack = (vulnerabilityId: string) => {
    if (!target) return;
    
    const attackWindow = window.open(`/attacks/stage?target=${target.id}&vuln=${vulnerabilityId}`, 'stageAttack', 'width=800,height=600,scrollbars=yes,resizable=yes');
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

  const handleClose = () => {
    window.close();
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-dark text-white">
        <div className="container p-6">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
            <p className="mt-4 text-gray-400">Loading target details...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error || !target) {
    return (
      <div className="min-h-screen bg-dark text-white">
        <div className="container p-6">
          <div className="text-center">
            <div className="bg-danger text-white p-4 rounded">
              <span>{error || 'Target not found'}</span>
            </div>
            <button
              onClick={handleClose}
              className="btn btn-secondary mt-4"
            >
              Close Window
            </button>
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
            <div className="flex items-center">
              <button
                onClick={handleClose}
                className="mr-4 text-white hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
              <h1 className="text-2xl font-bold">Target Details</h1>
            </div>
            <button
              onClick={scanTarget}
              disabled={scanning}
              className="btn btn-secondary flex items-center"
            >
              {scanning ? (
                <RefreshCw className="w-5 h-5 mr-2 animate-spin" />
              ) : (
                <Search className="w-5 h-5 mr-2" />
              )}
              {scanning ? 'Scanning...' : 'Scan Target'}
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="container p-6">
        {error && (
          <div className="bg-danger text-white p-4 rounded mb-6">
            <div className="flex items-center">
              <span>{error}</span>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Target Information */}
          <div className="card">
            <h2 className="text-xl font-bold text-primary mb-4">Target Information</h2>
            <div className="space-y-4">
              <div>
                <span className="text-gray-400">Hostname:</span>
                <div className="text-white font-medium">{target.hostname || 'N/A'}</div>
              </div>
              <div>
                <span className="text-gray-400">IP Address:</span>
                <div className="text-white font-medium">{target.ip_address}</div>
              </div>
              {target.os_info && (
                <div>
                  <span className="text-gray-400">OS Info:</span>
                  <div className="text-white font-medium">{target.os_info}</div>
                </div>
              )}
              <div>
                <span className="text-gray-400">Discovered:</span>
                <div className="text-white font-medium">
                  {new Date(target.discovered_at).toLocaleString()}
                </div>
              </div>
              <div>
                <span className="text-gray-400">Last Seen:</span>
                <div className="text-white font-medium">
                  {new Date(target.last_seen).toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          {/* Services */}
          <div className="card">
            <h2 className="text-xl font-bold text-primary mb-4">Services ({target.services.length})</h2>
            {target.services.length > 0 ? (
              <div className="space-y-3">
                {target.services.map((service) => (
                  <div key={service.id} className="bg-dark border border-border rounded p-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium">{service.name}</div>
                        <div className="text-sm text-gray-400">
                          {service.type} on port {service.port}
                        </div>
                        {service.version && (
                          <div className="text-sm text-gray-400">
                            Version: {service.version}
                          </div>
                        )}
                      </div>
                      <div className="text-right">
                        <span className="text-sm text-gray-400">
                          {service.vulnerabilities.length} vulns
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-gray-400 text-center py-8">
                No services discovered
              </div>
            )}
          </div>
        </div>

        {/* Vulnerabilities */}
        {target.vulnerabilities.length > 0 && (
          <div className="card mt-6">
            <h2 className="text-xl font-bold text-primary mb-4">Vulnerabilities ({target.vulnerabilities.length})</h2>
            <div className="space-y-4">
              {target.vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="bg-dark border border-border rounded p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="font-medium text-lg">{vuln.name}</div>
                    <span className={`px-3 py-1 rounded text-sm ${getVulnerabilityColor(vuln.level)}`}>
                      {vuln.level.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-gray-400 mb-3">{vuln.description}</p>
                  {vuln.cve_id && (
                    <div className="text-sm text-gray-400 mb-3">
                      CVE: {vuln.cve_id}
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-gray-400">
                      Discovered: {new Date(vuln.discovered_at).toLocaleString()}
                    </div>
                    <button
                      onClick={() => stageAttack(vuln.id)}
                      className="btn btn-primary text-sm flex items-center"
                    >
                      <Zap className="w-4 h-4 mr-1" />
                      Stage Attack
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {target.vulnerabilities.length === 0 && (
          <div className="card mt-6">
            <div className="text-center py-8">
              <div className="text-gray-400 mb-4">No vulnerabilities discovered</div>
              <button
                onClick={scanTarget}
                disabled={scanning}
                className="btn btn-primary"
              >
                {scanning ? 'Scanning...' : 'Scan for Vulnerabilities'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TargetDetailsPage; 