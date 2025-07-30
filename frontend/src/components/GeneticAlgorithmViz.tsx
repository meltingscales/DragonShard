import React, { useState, useEffect, useRef } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
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
  Title,
  Tooltip,
  Legend
);

interface GeneticAlgorithmVizProps {
  sessionId?: string;
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

interface GenerationData {
  generation: number;
  bestFitness: number;
  averageFitness: number;
  populationSize: number;
  diversity: number;
  mutationsCount: number;
  successfulPayloads: number;
}

const GeneticAlgorithmViz: React.FC<GeneticAlgorithmVizProps> = ({ sessionId }) => {
  const [isRunning, setIsRunning] = useState(false);
  const [targetUrl, setTargetUrl] = useState('http://localhost:8082');
  const [payloadType, setPayloadType] = useState('SQL_INJECTION');
  const [generationData, setGenerationData] = useState<GenerationData[]>([]);
  const [mutationTree, setMutationTree] = useState<Record<string, MutationNode>>({});
  const [currentGeneration, setCurrentGeneration] = useState(0);
  const [bestFitness, setBestFitness] = useState(0);
  const [averageFitness, setAverageFitness] = useState(0);
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
      console.log('WebSocket connected for genetic algorithm');
      ws.send(JSON.stringify({
        type: 'subscribe',
        stream: 'genetic_algorithm',
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
      fetchGeneticData();
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
      case 'genetic_generation':
        updateGenerationData(data.data);
        break;
      case 'genetic_mutation':
        updateMutationTree(data.data);
        break;
      case 'genetic_fitness':
        updateFitnessData(data.data);
        break;
      case 'genetic_error':
        setError(data.message);
        break;
    }
  };

  const updateGenerationData = (data: any) => {
    setGenerationData(prev => [...prev, {
      generation: data.generation,
      bestFitness: data.bestFitness,
      averageFitness: data.averageFitness,
      populationSize: data.populationSize,
      diversity: data.diversity,
      mutationsCount: data.mutationsCount,
      successfulPayloads: data.successfulPayloads
    }]);
    setCurrentGeneration(data.generation);
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

  const updateFitnessData = (data: any) => {
    setBestFitness(data.bestFitness);
    setAverageFitness(data.averageFitness);
  };

  const fetchGeneticData = async () => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/fuzzing/stats`);
      if (response.ok) {
        const data = await response.json();
        setBestFitness(data.best_fitness);
        setAverageFitness(data.average_fitness);
      }
    } catch (error) {
      console.error('Error fetching genetic data:', error);
    }
  };

  const startEvolution = async () => {
    try {
      setError(null);
      setStatus('Starting evolution...');
      
      const response = await fetch('http://localhost:8000/api/v1/fuzzing/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: targetUrl,
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
        setStatus('Evolution running');
        setGenerationData([]);
        setMutationTree({});
        setCurrentGeneration(0);
      } else {
        throw new Error('Failed to start evolution');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to start evolution');
      setStatus('Error');
    }
  };

  const stopEvolution = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/v1/fuzzing/stop', {
        method: 'POST',
      });

      if (response.ok) {
        setIsRunning(false);
        setStatus('Stopped');
      }
    } catch (error) {
      console.error('Error stopping evolution:', error);
    }
  };

  const exportResults = () => {
    const data = {
      generationData,
      mutationTree,
      settings: {
        targetUrl,
        payloadType,
        timestamp: new Date().toISOString()
      }
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `genetic_algorithm_results_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const fitnessChartData = {
    labels: generationData.map(d => `Gen ${d.generation}`),
    datasets: [
      {
        label: 'Best Fitness',
        data: generationData.map(d => d.bestFitness),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.5)',
        tension: 0.1,
      },
      {
        label: 'Average Fitness',
        data: generationData.map(d => d.averageFitness),
        borderColor: 'rgb(255, 99, 132)',
        backgroundColor: 'rgba(255, 99, 132, 0.5)',
        tension: 0.1,
      },
    ],
  };

  const fitnessChartOptions: ChartOptions<'line'> = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'Fitness Evolution',
      },
    },
    scales: {
      y: {
        beginAtZero: true,
      },
    },
  };

  const diversityChartData = {
    labels: generationData.map(d => `Gen ${d.generation}`),
    datasets: [
      {
        label: 'Population Diversity',
        data: generationData.map(d => d.diversity),
        borderColor: 'rgb(153, 102, 255)',
        backgroundColor: 'rgba(153, 102, 255, 0.5)',
        tension: 0.1,
      },
    ],
  };

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <h3 className="text-dragon-primary font-semibold mb-4">🧬 Genetic Algorithm Visualization</h3>
      
      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div>
          <label className="block text-sm font-medium text-dragon-text-muted mb-1">Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full bg-dragon-dark border border-dragon-border rounded px-3 py-2 text-white"
            disabled={isRunning}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-dragon-text-muted mb-1">Payload Type</label>
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
            onClick={isRunning ? stopEvolution : startEvolution}
            className={`w-full px-4 py-2 rounded font-medium ${
              isRunning
                ? 'bg-red-600 hover:bg-red-700 text-white'
                : 'bg-dragon-primary hover:bg-dragon-secondary text-white'
            }`}
          >
            {isRunning ? 'Stop Evolution' : 'Start Evolution'}
          </button>
        </div>
        
        <div className="flex items-end">
          <button
            onClick={exportResults}
            className="w-full px-4 py-2 bg-dragon-card hover:bg-dragon-border text-white rounded font-medium"
            disabled={generationData.length === 0}
          >
            Export Results
          </button>
        </div>
      </div>

      {/* Status and Error */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <span className="text-sm text-dragon-text-muted">Status: {status}</span>
            <span className="text-sm text-dragon-text-muted">Generation: {currentGeneration}</span>
            <span className="text-sm text-dragon-text-muted">Best Fitness: {bestFitness.toFixed(2)}</span>
            <span className="text-sm text-dragon-text-muted">Avg Fitness: {averageFitness.toFixed(2)}</span>
          </div>
          <div className={`w-3 h-3 rounded-full ${isRunning ? 'bg-green-400' : 'bg-red-400'}`}></div>
        </div>
        {error && (
          <div className="mt-2 p-2 bg-red-600 text-white rounded text-sm">
            Error: {error}
          </div>
        )}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-dragon-dark border border-dragon-border rounded p-4">
          <Line data={fitnessChartData} options={fitnessChartOptions} />
        </div>
        
        <div className="bg-dragon-dark border border-dragon-border rounded p-4">
          <Line data={diversityChartData} options={fitnessChartOptions} />
        </div>
      </div>

      {/* Mutation Tree Summary */}
      <div className="mt-6">
        <h4 className="text-dragon-primary font-medium mb-3">Mutation Tree Summary</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Total Nodes</div>
            <div className="text-2xl font-bold">{Object.keys(mutationTree).length}</div>
          </div>
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Generations</div>
            <div className="text-2xl font-bold">{currentGeneration}</div>
          </div>
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Best Fitness</div>
            <div className="text-2xl font-bold text-green-400">{bestFitness.toFixed(2)}</div>
          </div>
          <div className="bg-dragon-dark border border-dragon-border rounded p-3">
            <div className="text-dragon-primary font-medium">Avg Fitness</div>
            <div className="text-2xl font-bold text-blue-400">{averageFitness.toFixed(2)}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GeneticAlgorithmViz; 