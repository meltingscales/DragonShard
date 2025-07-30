import React from 'react';
import { Network, Server, Globe } from 'lucide-react';

const NetworkPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-dragon-dark text-white">
      {/* Header */}
      <div className="bg-gradient-to-r from-dragon-primary to-dragon-secondary p-6">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-4xl font-bold mb-2">🌐 Network Topology</h1>
          <p className="text-lg opacity-90">Explore discovered hosts, services, and vulnerabilities</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center">
          <Network className="h-24 w-24 text-dragon-primary mx-auto mb-6" />
          <h2 className="text-2xl font-bold mb-4">Network Discovery</h2>
          <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
            This page will provide comprehensive network topology visualization including:
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <Server className="h-12 w-12 text-blue-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">Host Discovery</h3>
              <p className="text-gray-400 text-sm">
                Discover and map network hosts and their characteristics
              </p>
            </div>
            
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <Globe className="h-12 w-12 text-green-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">Service Mapping</h3>
              <p className="text-gray-400 text-sm">
                Identify running services and their configurations
              </p>
            </div>
            
            <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
              <Network className="h-12 w-12 text-purple-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">Vulnerability Overlay</h3>
              <p className="text-gray-400 text-sm">
                Visualize vulnerabilities in the context of network topology
              </p>
            </div>
          </div>
          
          <div className="bg-dragon-card border border-dragon-border rounded-lg p-8">
            <h3 className="text-xl font-semibold mb-4">Coming Soon</h3>
            <p className="text-gray-400">
              Advanced network topology features are currently in development. 
              Check back soon for interactive network graphs, host discovery, 
              service mapping, and vulnerability visualization capabilities.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkPage; 