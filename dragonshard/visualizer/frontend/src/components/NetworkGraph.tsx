import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import type { NetworkTopology, Host } from '../types/api';

const NetworkGraph: React.FC = () => {
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadTopology();
    const interval = setInterval(loadTopology, 20000); // Refresh every 20 seconds
    return () => clearInterval(interval);
  }, []);

  const loadTopology = async () => {
    try {
      setError(null);
      const networkData = await ApiService.getNetworkTopology();
      setTopology(networkData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load network topology');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🗺️ Network Graph</h3>
        <div className="text-center text-gray-400">Loading network topology...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🗺️ Network Graph</h3>
        <div className="text-red-400">{error}</div>
      </div>
    );
  }

  if (!topology || topology.hosts.length === 0) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🗺️ Network Graph</h3>
        <div className="text-center text-gray-400 py-8">
          No hosts discovered
        </div>
      </div>
    );
  }

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <h3 className="text-dragon-primary font-semibold mb-4">🗺️ Network Graph</h3>
      
      {/* Network Summary */}
      <div className="grid grid-cols-3 gap-4 mb-4 text-center">
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-blue-400">{topology.total_hosts}</div>
          <div className="text-xs text-gray-400">Hosts</div>
        </div>
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-purple-400">{topology.total_services}</div>
          <div className="text-xs text-gray-400">Services</div>
        </div>
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-red-400">{topology.total_vulnerabilities}</div>
          <div className="text-xs text-gray-400">Vulnerabilities</div>
        </div>
      </div>

      {/* Hosts */}
      <div className="space-y-4 max-h-96 overflow-y-auto">
        {topology.hosts.map((host) => (
          <div key={host.id} className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h4 className="font-semibold text-white">{host.ip_address}</h4>
                {host.hostname && (
                  <p className="text-sm text-gray-400">{host.hostname}</p>
                )}
              </div>
              <div className="text-right text-xs text-gray-500">
                <div>Last seen: {new Date(host.last_seen).toLocaleString()}</div>
                {host.os_info && <div>OS: {host.os_info}</div>}
              </div>
            </div>

            {/* Services */}
            {host.services.length > 0 && (
              <div className="mb-3">
                <h5 className="text-sm font-semibold text-gray-300 mb-2">Services:</h5>
                <div className="flex flex-wrap gap-2">
                  {host.services.map((service) => (
                    <div key={service.id} className="bg-gray-700 px-2 py-1 rounded text-xs">
                      {service.name} ({service.port})
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Vulnerabilities */}
            {host.vulnerabilities.length > 0 && (
              <div>
                <h5 className="text-sm font-semibold text-gray-300 mb-2">Vulnerabilities:</h5>
                <div className="space-y-1">
                  {host.vulnerabilities.map((vuln) => (
                    <div key={vuln.id} className="flex items-center justify-between text-xs">
                      <span className="text-gray-400">{vuln.name}</span>
                      <span className={`px-2 py-1 rounded ${
                        vuln.level === 'critical' ? 'bg-red-500' :
                        vuln.level === 'high' ? 'bg-orange-500' :
                        vuln.level === 'medium' ? 'bg-yellow-500' :
                        'bg-green-500'
                      }`}>
                        {vuln.level}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default NetworkGraph; 