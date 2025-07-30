import React, { useState, useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { MutationNode } from '../types/api';

interface MutationTreeProps {
  nodes: Record<string, MutationNode>;
  height?: string;
  onNodeSelect?: (node: MutationNode) => void;
}

const MutationTree: React.FC<MutationTreeProps> = ({ 
  nodes, 
  height = "600px",
  onNodeSelect 
}) => {
  const cyRef = useRef<HTMLDivElement>(null);
  const cyInstanceRef = useRef<any>(null);
  const [layoutType, setLayoutType] = useState('spring');
  const [showFitness, setShowFitness] = useState(true);
  const [showVulnerabilities, setShowVulnerabilities] = useState(true);
  const [maxNodes, setMaxNodes] = useState(200);

  useEffect(() => {
    if (!cyRef.current || !nodes) return;

    // Clear previous instance
    if (cyInstanceRef.current) {
      cyInstanceRef.current.destroy();
    }

    // Create elements from nodes
    const elements: any[] = [];
    const nodeMap = new Map<string, string>();

    // Limit nodes for performance
    const nodeEntries = Object.entries(nodes);
    const displayNodes = nodeEntries.slice(-maxNodes);

    // Add nodes
    displayNodes.forEach(([nodeId, node]) => {
      elements.push({
        data: {
          id: nodeId,
          label: node.payload.substring(0, 20) + (node.payload.length > 20 ? '...' : ''),
          payload: node.payload,
          payloadType: node.payloadType,
          fitnessScore: node.fitnessScore,
          generation: node.generation,
          mutationType: node.mutationType,
          successful: node.successful,
          vulnerabilityDetected: node.vulnerabilityDetected,
          parentId: node.parentId,
          children: node.children
        }
      });
    });

    // Add edges
    displayNodes.forEach(([nodeId, node]) => {
      if (node.parentId && nodes[node.parentId]) {
        elements.push({
          data: {
            id: `edge-${node.parentId}-${nodeId}`,
            source: node.parentId,
            target: nodeId
          }
        });
      }
    });

    // Initialize Cytoscape with mutation tree styling
    cyInstanceRef.current = cytoscape({
      container: cyRef.current,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': function(ele: any) {
              const node = ele.data();
              if (node.vulnerabilityDetected) return '#e53e3e'; // Red for vulnerabilities
              if (node.successful) return '#38a169'; // Green for successful
              return '#667eea'; // Blue for normal
            },
            'border-color': '#2d3748',
            'border-width': 2,
            'color': '#ffffff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 10,
            'font-weight': 'bold',
            'width': function(ele: any) {
              const node = ele.data();
              if (node.vulnerabilityDetected) return 60;
              if (node.successful) return 50;
              return 40;
            },
            'height': function(ele: any) {
              const node = ele.data();
              if (node.vulnerabilityDetected) return 60;
              if (node.successful) return 50;
              return 40;
            },
            'shape': 'ellipse'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#4a5568',
            'target-arrow-color': '#4a5568',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier'
          }
        }
      ],
      layout: {
        name: layoutType === 'spring' ? 'cose' : layoutType === 'circular' ? 'circle' : 'concentric',
        animate: true,
        animationDuration: 1000,
        nodeDimensionsIncludeLabels: true,
        fit: true,
        padding: 50
      }
    });

    // Add event listeners
    cyInstanceRef.current.on('tap', 'node', function(evt: any) {
      const node = evt.target;
      const data = node.data();
      const mutationNode: MutationNode = {
        id: data.id,
        payload: data.payload,
        payloadType: data.payloadType,
        fitnessScore: data.fitnessScore,
        generation: data.generation,
        mutationType: data.mutationType,
        successful: data.successful,
        vulnerabilityDetected: data.vulnerabilityDetected,
        parentId: data.parentId,
        children: data.children
      };
      
      if (onNodeSelect) {
        onNodeSelect(mutationNode);
      }
    });

    // Fit the graph to the container
    cyInstanceRef.current.fit();

  }, [nodes, layoutType, maxNodes]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (cyInstanceRef.current) {
        cyInstanceRef.current.destroy();
      }
    };
  }, []);

  const handleLayoutChange = (newLayout: string) => {
    setLayoutType(newLayout);
  };

  const handleMaxNodesChange = (value: number) => {
    setMaxNodes(value);
  };

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-dragon-primary font-semibold">🧬 Mutation Tree</h3>
        
        {/* Controls */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <label className="text-sm text-gray-400">Layout:</label>
            <select 
              value={layoutType} 
              onChange={(e) => handleLayoutChange(e.target.value)}
              className="bg-dragon-dark border border-dragon-border rounded px-2 py-1 text-sm"
            >
              <option value="spring">Spring</option>
              <option value="circular">Circular</option>
              <option value="hierarchical">Hierarchical</option>
            </select>
          </div>
          
          <div className="flex items-center space-x-2">
            <label className="text-sm text-gray-400">Max Nodes:</label>
            <input 
              type="number" 
              value={maxNodes} 
              onChange={(e) => handleMaxNodesChange(Number(e.target.value))}
              min="10" 
              max="500"
              className="bg-dragon-dark border border-dragon-border rounded px-2 py-1 text-sm w-20"
            />
          </div>
          
          <div className="flex items-center space-x-4">
            <label className="flex items-center space-x-2 text-sm">
              <input 
                type="checkbox" 
                checked={showFitness} 
                onChange={(e) => setShowFitness(e.target.checked)}
                className="rounded"
              />
              <span className="text-gray-400">Fitness</span>
            </label>
            
            <label className="flex items-center space-x-2 text-sm">
              <input 
                type="checkbox" 
                checked={showVulnerabilities} 
                onChange={(e) => setShowVulnerabilities(e.target.checked)}
                className="rounded"
              />
              <span className="text-gray-400">Vulnerabilities</span>
            </label>
          </div>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-4 gap-4 mb-4 text-center">
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-blue-400">{Object.keys(nodes).length}</div>
          <div className="text-xs text-gray-400">Total Nodes</div>
        </div>
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-green-400">
            {Object.values(nodes).filter(n => n.successful).length}
          </div>
          <div className="text-xs text-gray-400">Successful</div>
        </div>
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-red-400">
            {Object.values(nodes).filter(n => n.vulnerabilityDetected).length}
          </div>
          <div className="text-xs text-gray-400">Vulnerabilities</div>
        </div>
        <div className="bg-dragon-dark rounded-lg p-3">
          <div className="text-2xl font-bold text-yellow-400">
            {Math.max(...Object.values(nodes).map(n => n.generation), 0)}
          </div>
          <div className="text-xs text-gray-400">Generations</div>
        </div>
      </div>

      {/* Graph Container */}
      <div 
        ref={cyRef} 
        style={{ 
          width: '100%', 
          height: height,
          backgroundColor: '#1a1f2e',
          border: '1px solid #2d3748',
          borderRadius: '8px'
        }} 
      />
    </div>
  );
};

export default MutationTree; 