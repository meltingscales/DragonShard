import React, { useState, useEffect } from 'react';
import { Target, Plus, Search, Eye, Zap, AlertTriangle, Play, Square, Trash2, RefreshCw, Globe } from 'lucide-react';
import { ApiService } from '../services/api';
import type { Host, Vulnerability, AttackChain } from '../types/api';
import Button from './ui/Button';

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
  const [crawlingWebsites, setCrawlingWebsites] = useState<string | null>(null);

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
      setLoading(true);
      
      // Start the scan
      const scanResult = await ApiService.scanTarget(targetId);
      
      // Reload targets to get updated data
      await loadTargets();
      
      // Show success message
      console.log(`Scan completed for target ${targetId}. Found ${scanResult.services_found} services.`);
      
    } catch (err) {
      setError('Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const crawlWebsites = async (targetId: string) => {
    try {
      setCrawlingWebsites(targetId);
      setError(null);
      
      // Crawl websites for this specific target
      const result = await ApiService.crawlService(targetId);
      
      // Show success message
      console.log(`Website crawling completed for target ${targetId}.`);
      
      // Optionally redirect to websites page to see results
      window.open('/websites', '_blank');
      
    } catch (err) {
      setError('Failed to crawl websites for this target');
    } finally {
      setCrawlingWebsites(null);
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

  // Check if target has HTTP/HTTPS services
  const hasWebServices = (target: Host) => {
    return target.services && target.services.some(service => 
      service.type === 'http' || service.type === 'https' || 
      service.name?.toLowerCase().includes('http')
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-dark text-white p-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-4">🎯 Target Management</h1>
          <p className="text-gray-300 mb-6">
            Add, scan, and manage network targets for vulnerability assessment and attack simulation.
          </p>
          
          {/* Workflow Information */}
          <div className="bg-card border border-primary rounded-lg p-6 mb-6">
            <h3 className="text-lg font-semibold mb-3 text-primary">🔄 Website Crawling Workflow</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="flex items-start gap-3">
                <div className="bg-primary text-white rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold mt-0.5">1</div>
                <div>
                  <p className="font-medium">Add Target</p>
                  <p className="text-gray-400">Add a host IP address to scan for services</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="bg-primary text-white rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold mt-0.5">2</div>
                <div>
                  <p className="font-medium">Scan Services</p>
                  <p className="text-gray-400">Click the refresh button to discover HTTP/HTTPS services</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div className="bg-primary text-white rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold mt-0.5">3</div>
                <div>
                  <p className="font-medium">Crawl Websites</p>
                  <p className="text-gray-400">Click the globe button to crawl discovered web services</p>
                </div>
              </div>
            </div>
            <div className="mt-4 p-3 bg-dark rounded border border-primary">
              <p className="text-sm text-gray-300">
                <strong>💡 Tip:</strong> After crawling websites, visit the <strong>Websites</strong> page to view discovered forms, 
                endpoints, and fuzzing targets. You can also go to <strong>Fuzzing Targets</strong> to see all discovered 
                forms and endpoints across all websites.
              </p>
            </div>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-6 p-4 bg-red-900 border border-red-500 rounded-lg">
            <div className="flex items-center">
              <AlertTriangle className="w-5 h-5 text-red-400 mr-2" />
              <span className="text-red-200">{error}</span>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-4 mb-8">
          <Button onClick={addTarget} variant="primary">
            <Plus className="w-4 h-4 mr-2" />
            Add Target
          </Button>
          <Button onClick={loadTargets} variant="secondary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Targets Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {targets.map((target) => (
            <div key={target.id} className="bg-card border border-primary rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold">{target.hostname || target.ip_address}</h3>
                  <p className="text-sm text-gray-400">{target.ip_address}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    onClick={() => window.open(`/targets/${target.id}`, '_blank')}
                    variant="info"
                    size="sm"
                  >
                    <Eye className="w-4 h-4" />
                  </Button>
                </div>
              </div>

              {/* Services Summary */}
              {target.services && target.services.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-sm font-semibold mb-2">Services ({target.services.length}):</h4>
                  <div className="flex flex-wrap gap-1">
                    {target.services.slice(0, 5).map((service) => (
                      <span
                        key={service.id}
                        className="px-2 py-1 rounded text-xs bg-primary text-white"
                      >
                        {service.port}/{service.type || 'unknown'}
                      </span>
                    ))}
                    {target.services.length > 5 && (
                      <span className="px-2 py-1 rounded text-xs bg-gray-500">
                        +{target.services.length - 5}
                      </span>
                    )}
                  </div>
                </div>
              )}

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
              <div className="flex gap-2 flex-wrap">
                {/* Scan Target Button */}
                <Button
                  onClick={() => scanTarget(target.id)}
                  variant="secondary"
                  size="sm"
                >
                  <RefreshCw className="w-4 h-4" />
                </Button>

                {/* Crawl Websites Button - Only show if target has web services */}
                {hasWebServices(target) && (
                  <Button
                    onClick={() => crawlWebsites(target.id)}
                    variant="info"
                    size="sm"
                    disabled={crawlingWebsites === target.id}
                  >
                    <Globe className="w-4 h-4" />
                    {crawlingWebsites === target.id ? 'Crawling...' : 'Crawl'}
                  </Button>
                )}

                {/* Stage Attack Button - Only show if vulnerabilities exist */}
                {target.vulnerabilities.length > 0 && (
                  <Button
                    onClick={() => stageAttack(target.id, target.vulnerabilities[0].id)}
                    variant="primary"
                    size="sm"
                  >
                    <Zap className="w-4 h-4 mr-1" />
                    Attack
                  </Button>
                )}
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
                              <Button
                                onClick={() => stageAttack(result.host.id, vuln.id)}
                                variant="primary"
                                size="sm"
                              >
                                Attack
                              </Button>
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