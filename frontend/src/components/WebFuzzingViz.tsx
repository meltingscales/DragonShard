import React, { useState, useEffect, useRef } from 'react';
import { Line, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

interface WebFuzzingVizProps {
  sessionId?: string;
}

interface FuzzResult {
  id: string;
  payload: string;
  target: string;
  statusCode: number;
  responseTime: number;
  vulnerabilityScore: number;
  vulnerabilityType?: string;
  evidence?: string;
  timestamp: string;
}

interface MutationNode {
  id: string;
  payload: string;
  parentPayload?: string;
  generation: number;
  fitness: number;
  vulnerabilityScore: number;
  mutationType: string;
  responseAnalysis?: Record<string, any>;
  children: string[];
  timestamp: string;
}

const WebFuzzingViz: React.FC<WebFuzzingVizProps> = ({ sessionId }) => {
  const [isRunning, setIsRunning] = useState(false);
  const [targetUrl, setTargetUrl] = useState('http://localhost:8082');
  const [method, setMethod] = useState('GET');
  const [payloadType, setPayloadType] = useState('SQL_INJECTION');
  const [fuzzResults, setFuzzResults] = useState<FuzzResult[]>([]);
  const [mutationTree, setMutationTree] = useState<Record<string, MutationNode>>({});
  const [generationData, setGenerationData] = useState<any[]>([]);
  const [vulnerabilityHistory, setVulnerabilityHistory] = useState<any[]>([]);
  const [currentGeneration, setCurrentGeneration] = useState(0);
  const [totalRequests, setTotalRequests] = useState(0);
  const [successfulRequests, setSuccessfulRequests] = useState(0);
  const [vulnerabilitiesFound, setVulnerabilitiesFound] = useState(0);
  const [status, setStatus] = useState('Ready');
  const [error, setError] = useState<string | null>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const payloadTypes = [
    'SQL_INJECTION',
    'XSS',
    'COMMAND_INJECTION',
    'PATH_TRAVERSAL',
    'LDAP_INJECTION',
    'NO_SQL_INJECTION',
    'XML_INJECTION',
    'TEMPLATE_INJECTION'
  ];

  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];

  useEffect(() => {
    if (isRunning) {
      startWebSocket();
      startDataCollection();
    } else {
      stopWebSocket();
      stopDataCollection();
    }

    return () => {
      stopWebSocket();
      stopDataCollection();
    };
  }, [isRunning, sessionId]);

  const startWebSocket = () => {
    const ws = new WebSocket('ws://localhost:8000/ws');
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected for web fuzzing');
      ws.send(JSON.stringify({
        type: 'subscribe',
        stream: 'web_fuzzing',
        sessionId: sessionId
      }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setError('WebSocket connection failed');
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
    };
  };

  const stopWebSocket = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  };

  const startDataCollection = () => {
    intervalRef.current = setInterval(() => {
      fetchFuzzingData();
    }, 1000);
  };

  const stopDataCollection = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  };

  const handleWebSocketMessage = (data: any) => {
    switch (data.type) {
      case 'fuzz_result':
        updateFuzzResults(data.data);
        break;
      case 'mutation_tree':
        updateMutationTree(data.data);
        break;
      case 'generation_update':
        updateGenerationData(data.data);
        break;
      case 'vulnerability_found':
        updateVulnerabilityHistory(data.data);
        break;
      case 'fuzzing_error':
        setError(data.message);
        break;
    }
  };

  const updateFuzzResults = (data: FuzzResult) => {
    setFuzzResults(prev => [data, ...prev.slice(0, 99)]); // Keep last 100 results
    setTotalRequests(prev => prev + 1);
    if (data.statusCode >= 200 && data.statusCode < 300) {
      setSuccessfulRequests(prev => prev + 1);
    }
    if (data.vulnerabilityScore > 0.5) {
      setVulnerabilitiesFound(prev => prev + 1);
    }
  };

  const updateMutationTree = (data: any) => {
    setMutationTree(prev => ({
      ...prev,
      [data.id]: {
        id: data.id,
        payload: data.payload,
        parentPayload: data.parentPayload,
        generation: data.generation,
        fitness: data.fitness,
        vulnerabilityScore: data.vulnerabilityScore,
        mutationType: data.mutationType,
        responseAnalysis: data.responseAnalysis,
        children: data.children || [],
        timestamp: data.timestamp
      }
    }));
  };

  const updateGenerationData = (data: any) => {
    setGenerationData(prev => [...prev, data]);
    setCurrentGeneration(data.generation);
  };

  const updateVulnerabilityHistory = (data: any) => {
    setVulnerabilityHistory(prev => [...prev, data]);
  };

  const fetchFuzzingData = async () => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/fuzzing/stats`);
      if (response.ok) {
        const data = await response.json();
        // Update stats from API
      }
    } catch (error) {
      console.error('Error fetching fuzzing data:', error);
    }
  };

  const startFuzzing = async () => {
    try {
      setError(null);
      setStatus('Starting fuzzing...');
      
      const response = await fetch('http://localhost:8000/api/v1/fuzzing/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: targetUrl,
          method: method,
          payload_type: payloadType,
          population_size: 50,
          generations: 100,
          mutation_rate: 0.1,
          crossover_rate: 0.8
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setIsRunning(true);
        setStatus('Fuzzing running');
        setFuzzResults([]);
        setMutationTree({});
        setGenerationData([]);
        setVulnerabilityHistory([]);
        setCurrentGeneration(0);
        setTotalRequests(0);
        setSuccessfulRequests(0);
        setVulnerabilitiesFound(0);
      } else {
        throw new Error('Failed to start fuzzing');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to start fuzzing');
      setStatus('Error');
    }
  };

  const stopFuzzing = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/v1/fuzzing/stop', {
        method: 'POST',
      });

      if (response.ok) {
        setIsRunning(false);
        setStatus('Stopped');
      }
    } catch (error) {
      console.error('Error stopping fuzzing:', error);
    }
  };

  const exportResults = () => {
    const data = {
      fuzzResults,
      mutationTree,
      generationData,
      vulnerabilityHistory,
      settings: {
        targetUrl,
        method,
        payloadType,
        timestamp: new Date().toISOString()
      }
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `web_fuzzing_results_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const responseTimeChartData = {
    labels: fuzzResults.slice(0, 20).map(r => r.id.slice(-6)),
    datasets: [
      {
        label: 'Response Time (ms)',
        data: fuzzResults.slice(0, 20).map(r => r.responseTime),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.5)',
        tension: 0.1,
      },
    ],
  };

  const vulnerabilityChartData = {
    labels: vulnerabilityHistory.map(v => v.timestamp.slice(11, 19)),
    datasets: [
      {
        label: 'Vulnerability Score',
        data: vulnerabilityHistory.map(v => v.score),
        borderColor: 'rgb(255, 99, 132)',
        backgroundColor: 'rgba(255, 99, 132, 0.5)',
        tension: 0.1,
      },
    ],
  };

  const statusCodeChartData = {
    labels: ['200-299', '300-399', '400-499', '500-599'],
    datasets: [
      {
        label: 'Status Codes',
        data: [
          fuzzResults.filter(r => r.statusCode >= 200 && r.statusCode < 300).length,
          fuzzResults.filter(r => r.statusCode >= 300 && r.statusCode < 400).length,
          fuzzResults.filter(r => r.statusCode >= 400 && r.statusCode < 500).length,
          fuzzResults.filter(r => r.statusCode >= 500).length,
        ],
        backgroundColor: [
          'rgba(75, 192, 192, 0.5)',
          'rgba(255, 205, 86, 0.5)',
          'rgba(255, 99, 132, 0.5)',
          'rgba(255, 159, 64, 0.5)',
        ],
        borderColor: [
          'rgb(75, 192, 192)',
          'rgb(255, 205, 86)',
          'rgb(255, 99, 132)',
          'rgb(255, 159, 64)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const chartOptions: ChartOptions<'line'> = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top' as const,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <h3 className="text-dragon-primary font-semibold mb-4">🌐 Web Fuzzing Visualization</h3>
      
      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full bg-dragon-dark border border-dragon-border rounded px-3 py-2 text-white"
            disabled={isRunning}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Method</label>
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="w-full bg-dragon-dark border border-dragon-border rounded px-3 py-2 text-white"
            disabled={isRunning}
          >
            {methods.map(m => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Payload Type</label>
          <select
            value={payloadType}
            onChange={(e) => setPayloadType(e.target.value)}
            className="w-full bg-dragon-dark border border-dragon-border rounded px-3 py-2 text-white"
            disabled={isRunning}
          >
            {payloadTypes.map(type => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
        </div>
        
        <div className="flex items-end">
          <button
            onClick={isRunning ? stopFuzzing : startFuzzing}
            className={`w-full px-4 py-2 rounded font-medium ${
              isRunning
                ? 'bg-red-600 hover:bg-red-700 text-white'
                : 'bg-dragon-primary hover:bg-dragon-secondary text-white'
            }`}
          >
            {isRunning ? 'Stop Fuzzing' : 'Start Fuzzing'}
          </button>
        </div>
        
        <div className="flex items-end">
          <button
            onClick={exportResults}
            className="w-full px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded font-medium"
            disabled={fuzzResults.length === 0}
          >
            Export Results
          </button>
        </div>
      </div>

      {/* Status and Stats */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-400">Status: {status}</span>
            <span className="text-sm text-gray-400">Generation: {currentGeneration}</span>
            <span className="text-sm text-gray-400">Total Requests: {totalRequests}</span>
            <span className="text-sm text-gray-400">Vulnerabilities: {vulnerabilitiesFound}</span>
          </div>
          <div className={`w-3 h-3 rounded-full ${isRunning ? 'bg-green-400' : 'bg-red-400'}`}></div>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Success Rate</div>
            <div className="text-2xl font-bold text-green-400">
              {totalRequests > 0 ? ((successfulRequests / totalRequests) * 100).toFixed(1) : 0}%
            </div>
          </div>
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Avg Response Time</div>
            <div className="text-2xl font-bold text-blue-400">
              {fuzzResults.length > 0 
                ? (fuzzResults.reduce((sum, r) => sum + r.responseTime, 0) / fuzzResults.length).toFixed(0)
                : 0}ms
            </div>
          </div>
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Mutation Tree Nodes</div>
            <div className="text-2xl font-bold text-purple-400">{Object.keys(mutationTree).length}</div>
          </div>
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Generations</div>
            <div className="text-2xl font-bold text-yellow-400">{currentGeneration}</div>
          </div>
        </div>
        
        {error && (
          <div className="mt-4 p-2 bg-red-600 text-white rounded text-sm">
            Error: {error}
          </div>
        )}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="bg-dragon-dark border border-dragon-border rounded p-4">
          <Line data={responseTimeChartData} options={chartOptions} />
        </div>
        
        <div className="bg-dragon-dark border border-dragon-border rounded p-4">
          <Line data={vulnerabilityChartData} options={chartOptions} />
        </div>
        
        <div className="bg-dragon-dark border border-dragon-border rounded p-4">
          <Bar data={statusCodeChartData} options={chartOptions} />
        </div>
      </div>

      {/* Recent Results */}
      <div className="mt-6">
        <h4 className="text-dragon-primary font-medium mb-3">Recent Fuzz Results</h4>
        <div className="bg-dragon-dark border border-dragon-border rounded overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-dragon-border">
                <tr>
                  <th className="px-4 py-2 text-left">Payload</th>
                  <th className="px-4 py-2 text-left">Status</th>
                  <th className="px-4 py-2 text-left">Time (ms)</th>
                  <th className="px-4 py-2 text-left">Vuln Score</th>
                  <th className="px-4 py-2 text-left">Type</th>
                </tr>
              </thead>
              <tbody>
                {fuzzResults.slice(0, 10).map((result, index) => (
                  <tr key={result.id} className="border-b border-dragon-border">
                    <td className="px-4 py-2 font-mono text-xs">
                      {result.payload.length > 30 ? result.payload.substring(0, 30) + '...' : result.payload}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`px-2 py-1 rounded text-xs ${
                        result.statusCode >= 200 && result.statusCode < 300
                          ? 'bg-green-600 text-white'
                          : result.statusCode >= 400
                          ? 'bg-red-600 text-white'
                          : 'bg-yellow-600 text-white'
                      }`}>
                        {result.statusCode}
                      </span>
                    </td>
                    <td className="px-4 py-2">{result.responseTime}ms</td>
                    <td className="px-4 py-2">
                      <span className={`px-2 py-1 rounded text-xs ${
                        result.vulnerabilityScore > 0.7
                          ? 'bg-red-600 text-white'
                          : result.vulnerabilityScore > 0.4
                          ? 'bg-yellow-600 text-white'
                          : 'bg-green-600 text-white'
                      }`}>
                        {result.vulnerabilityScore.toFixed(2)}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs">{result.vulnerabilityType || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WebFuzzingViz; 