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

  // Load initial data
  useEffect(() => {
    // Initialize with empty state
    const initialPorts: PortAllocation[] = Array.from({ length: 10 }, (_, i) => ({
      port: 4444 + i,
      status: 'available'
    }));

    setAllocatedPorts(initialPorts);
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
      case 'listening': return 'text-dragon-warning';
      case 'connected': return 'text-dragon-success';
      case 'disconnected': return 'text-dragon-danger';
      default: return 'text-dragon-text-muted';
    }
  };

  const getPortStatusColor = (status: string) => {
    switch (status) {
      case 'available': return 'text-dragon-success';
      case 'allocated': return 'text-dragon-warning';
      case 'in_use': return 'text-dragon-danger';
      default: return 'text-dragon-text-muted';
    }
  };

  return (
    <div className="container mx-auto p-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-dragon-card to-dragon-dark p-6 rounded-lg mb-6 border border-dragon-border">
        <h1 className="text-dragon-primary text-4xl font-bold mb-2">🐉 DragonShard - Reverse Shell Manager</h1>
        <p className="text-dragon-text-muted text-lg">Manage reverse shell connections and monitor active sessions</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1 space-y-6">
          {/* Create Listener */}
          <div className="bg-dragon-card rounded-lg p-6 border border-dragon-border">
            <h3 className="text-dragon-primary text-xl font-semibold mb-4 border-b border-dragon-border pb-2">
              Create Listener
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-dragon-text-muted mb-2">Port:</label>
                <input
                  type="number"
                  value={newPort}
                  onChange={(e) => setNewPort(Number(e.target.value))}
                  className="w-full bg-dragon-card border border-dragon-border rounded px-3 py-2 text-white"
                  min="1024"
                  max="65535"
                />
              </div>
              <button
                onClick={createListener}
                disabled={isLoading}
                className="w-full bg-dragon-primary hover:bg-dragon-secondary text-white py-2 px-4 rounded transition-all duration-200 disabled:opacity-50"
              >
                {isLoading ? 'Creating...' : 'Create Listener'}
              </button>
            </div>
          </div>

          {/* Port Allocation */}
          <div className="bg-dragon-card rounded-lg p-6 border border-dragon-border">
            <h3 className="text-dragon-primary text-xl font-semibold mb-4 border-b border-dragon-border pb-2">
              Port Allocation
            </h3>
            <div className="space-y-2">
              {allocatedPorts.slice(0, 10).map((port) => (
                <div key={port.port} className="flex justify-between items-center">
                  <span className="text-dragon-text-muted">Port {port.port}</span>
                  <span className={getPortStatusColor(port.status)}>
                    {port.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Active Connections */}
          <div className="bg-dragon-card rounded-lg p-6 border border-dragon-border">
            <h3 className="text-dragon-primary text-xl font-semibold mb-4 border-b border-dragon-border pb-2">
              Active Connections
            </h3>
            <div className="space-y-3">
              {connections.map((connection) => (
                <div
                  key={connection.id}
                  className={`p-3 rounded border cursor-pointer transition-all ${
                    selectedConnection === connection.id
                      ? 'border-dragon-primary bg-dragon-dark'
                      : 'border-dragon-border hover:border-dragon-primary'
                  }`}
                  onClick={() => setSelectedConnection(connection.id)}
                >
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-white font-medium">Port {connection.port}</span>
                    <span className={getStatusColor(connection.status)}>
                      {connection.status}
                    </span>
                  </div>
                  <div className="text-sm text-dragon-text-muted">
                    {connection.host} • {new Date(connection.lastActivity).toLocaleTimeString()}
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      closeConnection(connection.id);
                    }}
                    className="mt-2 bg-dragon-danger hover:bg-red-600 text-white px-2 py-1 rounded text-xs"
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
          <div className="bg-dragon-card rounded-lg p-6 border border-dragon-border">
            <h3 className="text-dragon-primary text-xl font-semibold mb-4 border-b border-dragon-border pb-2">
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
                    className="flex-1 bg-dragon-card border border-dragon-border rounded px-3 py-2 text-white"
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
                    className="bg-dragon-primary hover:bg-dragon-secondary text-white px-4 py-2 rounded"
                  >
                    Send
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center text-dragon-text-muted py-8">
                Select a connection to view console output
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="fixed bottom-4 right-4 bg-dragon-danger text-white px-4 py-2 rounded shadow-lg">
          {error}
        </div>
      )}
    </div>
  );
};

export default ReverseShellManager; 