import React, { useState, useEffect, useRef } from 'react';

interface ShellConnection {
  id: string;
  port: number;
  host: string;
  status: 'listening' | 'connected' | 'disconnected';
  createdAt: string;
  lastActivity: string;
  consoleHistory: string[];
}

interface PortAllocation {
  port: number;
  status: 'available' | 'allocated' | 'in_use';
}

const ReverseShellManager: React.FC = () => {
  const [connections, setConnections] = useState<ShellConnection[]>([]);
  const [allocatedPorts, setAllocatedPorts] = useState<PortAllocation[]>([]);
  const [selectedConnection, setSelectedConnection] = useState<string | null>(null);
  const [newPort, setNewPort] = useState<number>(4444);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const consoleRef = useRef<HTMLDivElement>(null);

  // Mock data for demonstration
  useEffect(() => {
    // Initialize with some mock data
    const mockConnections: ShellConnection[] = [
      {
        id: '1',
        port: 4444,
        host: '192.168.1.100',
        status: 'listening',
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        consoleHistory: ['[*] Listening on port 4444...', '[+] Connection established from 192.168.1.100']
      },
      {
        id: '2',
        port: 4445,
        host: '10.0.0.50',
        status: 'connected',
        createdAt: new Date(Date.now() - 300000).toISOString(),
        lastActivity: new Date().toISOString(),
        consoleHistory: [
          '[*] Listening on port 4445...',
          '[+] Connection established from 10.0.0.50',
          'root@target:~# whoami',
          'root',
          'root@target:~# pwd',
          '/root'
        ]
      }
    ];

    const mockPorts: PortAllocation[] = Array.from({ length: 10 }, (_, i) => ({
      port: 4444 + i,
      status: i < 2 ? 'allocated' : 'available'
    }));

    setConnections(mockConnections);
    setAllocatedPorts(mockPorts);
  }, []);

  const createListener = async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      const newConnection: ShellConnection = {
        id: Date.now().toString(),
        port: newPort,
        host: '0.0.0.0',
        status: 'listening',
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        consoleHistory: [`[*] Listening on port ${newPort}...`]
      };

      setConnections(prev => [...prev, newConnection]);
      setAllocatedPorts(prev => 
        prev.map(p => p.port === newPort ? { ...p, status: 'allocated' } : p)
      );

      setNewPort(prev => prev + 1);
    } catch (err) {
      setError('Failed to create listener');
    } finally {
      setIsLoading(false);
    }
  };

  const closeConnection = async (connectionId: string) => {
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));

      setConnections(prev => 
        prev.map(conn => 
          conn.id === connectionId 
            ? { ...conn, status: 'disconnected' }
            : conn
        )
      );

      const connection = connections.find(c => c.id === connectionId);
      if (connection) {
        setAllocatedPorts(prev => 
          prev.map(p => p.port === connection.port ? { ...p, status: 'available' } : p)
        );
      }
    } catch (err) {
      setError('Failed to close connection');
    }
  };

  const sendCommand = async (command: string) => {
    if (!selectedConnection) return;

    try {
      // Simulate command execution
      const response = `root@target:~# ${command}\nCommand executed: ${command}`;
      
      setConnections(prev => 
        prev.map(conn => 
          conn.id === selectedConnection
            ? {
                ...conn,
                consoleHistory: [...conn.consoleHistory, `root@target:~# ${command}`, response],
                lastActivity: new Date().toISOString()
              }
            : conn
        )
      );
    } catch (err) {
      setError('Failed to send command');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'listening': return 'text-yellow-400';
      case 'connected': return 'text-green-400';
      case 'disconnected': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getPortStatusColor = (status: string) => {
    switch (status) {
      case 'available': return 'text-green-400';
      case 'allocated': return 'text-yellow-400';
      case 'in_use': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="container mx-auto p-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-gray-800 to-gray-900 p-6 rounded-lg mb-6 border border-gray-700">
        <h1 className="text-red-400 text-4xl font-bold mb-2">🐉 DragonShard - Reverse Shell Manager</h1>
        <p className="text-gray-300 text-lg">Manage reverse shell connections and monitor active sessions</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1 space-y-6">
          {/* Create Listener */}
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-cyan-400 text-xl font-semibold mb-4 border-b border-gray-600 pb-2">
              Create Listener
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-gray-300 mb-2">Port:</label>
                <input
                  type="number"
                  value={newPort}
                  onChange={(e) => setNewPort(Number(e.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                  min="1024"
                  max="65535"
                />
              </div>
              <button
                onClick={createListener}
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 text-white py-2 px-4 rounded hover:from-cyan-600 hover:to-blue-600 transition-all duration-200 disabled:opacity-50"
              >
                {isLoading ? 'Creating...' : 'Create Listener'}
              </button>
            </div>
          </div>

          {/* Port Allocation */}
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-cyan-400 text-xl font-semibold mb-4 border-b border-gray-600 pb-2">
              Port Allocation
            </h3>
            <div className="space-y-2">
              {allocatedPorts.slice(0, 10).map((port) => (
                <div key={port.port} className="flex justify-between items-center">
                  <span className="text-gray-300">Port {port.port}</span>
                  <span className={getPortStatusColor(port.status)}>
                    {port.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Active Connections */}
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-cyan-400 text-xl font-semibold mb-4 border-b border-gray-600 pb-2">
              Active Connections
            </h3>
            <div className="space-y-3">
              {connections.map((connection) => (
                <div
                  key={connection.id}
                  className={`p-3 rounded border cursor-pointer transition-all ${
                    selectedConnection === connection.id
                      ? 'border-cyan-400 bg-gray-700'
                      : 'border-gray-600 hover:border-gray-500'
                  }`}
                  onClick={() => setSelectedConnection(connection.id)}
                >
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-white font-medium">Port {connection.port}</span>
                    <span className={getStatusColor(connection.status)}>
                      {connection.status}
                    </span>
                  </div>
                  <div className="text-sm text-gray-400">
                    {connection.host} • {new Date(connection.lastActivity).toLocaleTimeString()}
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      closeConnection(connection.id);
                    }}
                    className="mt-2 bg-red-500 hover:bg-red-600 text-white px-2 py-1 rounded text-xs"
                  >
                    Close
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Panel */}
        <div className="lg:col-span-2">
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-cyan-400 text-xl font-semibold mb-4 border-b border-gray-600 pb-2">
              Console Output
            </h3>
            
            {selectedConnection ? (
              <div className="space-y-4">
                {/* Console Display */}
                <div 
                  ref={consoleRef}
                  className="bg-black rounded p-4 h-96 overflow-y-auto font-mono text-sm"
                >
                  {connections.find(c => c.id === selectedConnection)?.consoleHistory.map((line, index) => (
                    <div key={index} className="text-green-400 mb-1">
                      {line}
                    </div>
                  ))}
                </div>

                {/* Command Input */}
                <div className="flex space-x-2">
                  <input
                    type="text"
                    placeholder="Enter command..."
                    className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        sendCommand(e.currentTarget.value);
                        e.currentTarget.value = '';
                      }
                    }}
                  />
                  <button
                    onClick={() => {
                      const input = document.querySelector('input[placeholder="Enter command..."]') as HTMLInputElement;
                      if (input?.value) {
                        sendCommand(input.value);
                        input.value = '';
                      }
                    }}
                    className="bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded"
                  >
                    Send
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-400 py-8">
                Select a connection to view console output
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="fixed bottom-4 right-4 bg-red-600 text-white px-4 py-2 rounded shadow-lg">
          {error}
        </div>
      )}
    </div>
  );
};

export default ReverseShellManager; 