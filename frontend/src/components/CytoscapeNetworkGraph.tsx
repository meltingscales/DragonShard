import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { NetworkTopology, Host } from '../types/api';

interface CytoscapeNetworkGraphProps {
  topology: NetworkTopology;
  height?: string;
}

const CytoscapeNetworkGraph: React.FC<CytoscapeNetworkGraphProps> = ({ 
  topology, 
  height = "400px" 
}) => {
  const cyRef = useRef<HTMLDivElement>(null);
  const cyInstanceRef = useRef<any>(null);

  useEffect(() => {
    if (!cyRef.current || !topology) return;

    // Clear previous instance
    if (cyInstanceRef.current) {
      cyInstanceRef.current.destroy();
    }

    // Create nodes and edges from topology
    const elements: any[] = [];
    const nodeMap = new Map<string, string>();

    // Add nodes for each host
    topology.hosts.forEach((host, index) => {
      const nodeId = `host-${host.id}`;
      nodeMap.set(host.id, nodeId);
      
      elements.push({
        data: {
          id: nodeId,
          label: host.ip_address,
          hostname: host.hostname,
          os: host.os_info,
          services: host.services.length,
          vulnerabilities: host.vulnerabilities.length,
          type: 'host'
        }
      });
    });

    // Add nodes for services
    topology.hosts.forEach(host => {
      host.services.forEach(service => {
        const serviceId = `service-${service.id}`;
        elements.push({
          data: {
            id: serviceId,
            label: `${service.name}:${service.port}`,
            service: service.name,
            port: service.port,
            type: 'service'
          }
        });
        
        // Add edge from host to service
        elements.push({
          data: {
            id: `edge-${host.id}-${service.id}`,
            source: nodeMap.get(host.id),
            target: serviceId
          }
        });
      });
    });

    // Add nodes for vulnerabilities
    topology.hosts.forEach(host => {
      host.vulnerabilities.forEach(vuln => {
        const vulnId = `vuln-${vuln.id}`;
        elements.push({
          data: {
            id: vulnId,
            label: vuln.name,
            level: vuln.level,
            cve: vuln.cve_id,
            type: 'vulnerability'
          }
        });
        
        // Add edge from host to vulnerability
        elements.push({
          data: {
            id: `edge-${host.id}-${vuln.id}`,
            source: nodeMap.get(host.id),
            target: vulnId
          }
        });
      });
    });

    // Initialize Cytoscape with dark theme
    cyInstanceRef.current = cytoscape({
      container: cyRef.current,
      elements: elements,
      style: [
        {
          selector: 'node[type="host"]',
          style: {
            'background-color': '#667eea',
            'border-color': '#764ba2',
            'border-width': 2,
            'color': '#ffffff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 12,
            'font-weight': 'bold',
            'width': 60,
            'height': 60,
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="service"]',
          style: {
            'background-color': '#38a169',
            'border-color': '#2f855a',
            'border-width': 1,
            'color': '#ffffff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 10,
            'width': 40,
            'height': 40,
            'shape': 'rectangle'
          }
        },
        {
          selector: 'node[type="vulnerability"]',
          style: {
            'background-color': function(ele: any) {
              const level = ele.data('level');
              switch (level) {
                case 'critical': return '#e53e3e';
                case 'high': return '#dd6b20';
                case 'medium': return '#d69e2e';
                case 'low': return '#38a169';
                default: return '#718096';
              }
            },
            'border-color': '#2d3748',
            'border-width': 1,
            'color': '#ffffff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': 9,
            'width': 30,
            'height': 30,
            'shape': 'triangle'
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
        name: 'cose',
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
      
      // Show node details in console (could be replaced with a modal)
      console.log('Node clicked:', data);
    });

    // Fit the graph to the container
    cyInstanceRef.current.fit();

  }, [topology]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (cyInstanceRef.current) {
        cyInstanceRef.current.destroy();
      }
    };
  }, []);

  return (
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
  );
};

export default CytoscapeNetworkGraph; 