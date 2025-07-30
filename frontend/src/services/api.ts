// API Service for DragonShard Visualization

const API_BASE = 'http://localhost:8000/api/v1';

export class ApiService {
  private static async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
      ...options,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  // Attack endpoints
  static async getAttacks(): Promise<AttackChain[]> {
    return this.request<AttackChain[]>('/attacks/');
  }

  static async getAttack(id: string): Promise<AttackChain> {
    return this.request<AttackChain>(`/attacks/${id}`);
  }

  static async getAttackSummary(): Promise<AttackSummary> {
    return this.request<AttackSummary>('/attacks/summary/stats');
  }

  static async getRunningAttacks(): Promise<AttackChain[]> {
    return this.request<AttackChain[]>('/attacks/current/running');
  }

  static async startAttack(attackId: string): Promise<any> {
    return this.request<any>(`/attacks/${attackId}/start`, {
      method: 'POST',
    });
  }

  static async stopAttack(attackId: string): Promise<any> {
    return this.request<any>(`/attacks/${attackId}/stop`, {
      method: 'POST',
    });
  }

  static async deleteAttack(attackId: string): Promise<any> {
    return this.request<any>(`/attacks/${attackId}`, {
      method: 'DELETE',
    });
  }

  // Vulnerability endpoints
  static async getVulnerabilities(): Promise<Vulnerability[]> {
    return this.request<Vulnerability[]>('/vulnerabilities/');
  }

  static async getVulnerabilitySummary(): Promise<VulnerabilitySummary> {
    return this.request<VulnerabilitySummary>('/vulnerabilities/summary');
  }

  // Network endpoints
  static async getNetworkTopology(): Promise<NetworkTopology> {
    return this.request<NetworkTopology>('/network/topology');
  }

  static async getHosts(): Promise<Host[]> {
    return this.request<Host[]>('/network/hosts');
  }

  // Fuzzing endpoints
  static async getFuzzingSessions(): Promise<FuzzingSession[]> {
    return this.request<FuzzingSession[]>('/fuzzing/sessions');
  }

  static async getFuzzingStats(): Promise<GeneticAlgorithmStats> {
    return this.request<GeneticAlgorithmStats>('/fuzzing/stats');
  }

  static async getMutationTree(): Promise<Record<string, MutationNode>> {
    return this.request<Record<string, MutationNode>>('/fuzzing/mutation-tree');
  }

  static async getFuzzingProgress(sessionId: string): Promise<FuzzingProgress[]> {
    return this.request<FuzzingProgress[]>(`/fuzzing/progress/${sessionId}`);
  }

  // Genetic Algorithm endpoints
  static async startGeneticAlgorithm(params: any): Promise<any> {
    return this.request<any>('/genetic/start', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  static async stopGeneticAlgorithm(): Promise<any> {
    return this.request<any>('/genetic/stop', {
      method: 'POST',
    });
  }

  static async getGeneticStats(): Promise<any> {
    return this.request<any>('/genetic/stats');
  }

  static async getGeneticSessions(): Promise<any[]> {
    return this.request<any[]>('/genetic/sessions');
  }

  static async getGenerationData(): Promise<any[]> {
    return this.request<any[]>('/genetic/generations');
  }

  // Session endpoints
  static async getSessions(): Promise<Session[]> {
    return this.request<Session[]>('/sessions/');
  }

  static async getSessionSummary(): Promise<SessionSummary> {
    return this.request<SessionSummary>('/sessions/summary/stats');
  }
}

// WebSocket service
export class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;

  constructor(private url: string = 'ws://localhost:8000/ws') {}

  connect(onMessage: (message: WebSocketMessage) => void, onError?: (error: Event) => void) {
    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          onMessage(message);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.attemptReconnect(onMessage, onError);
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        if (onError) onError(error);
      };
    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
    }
  }

  private attemptReconnect(onMessage: (message: WebSocketMessage) => void, onError?: (error: Event) => void) {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
      
      setTimeout(() => {
        this.connect(onMessage, onError);
      }, this.reconnectDelay * this.reconnectAttempts);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  send(message: WebSocketMessage) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  subscribe(stream: string) {
    this.send({ 
      type: 'subscribe', 
      stream,
      timestamp: new Date().toISOString()
    });
  }

  ping() {
    this.send({ 
      type: 'ping',
      timestamp: new Date().toISOString()
    });
  }
}

// Import types
import type {
  AttackChain,
  AttackSummary,
  Vulnerability,
  VulnerabilitySummary,
  NetworkTopology,
  Host,
  FuzzingSession,
  GeneticAlgorithmStats,
  FuzzingProgress,
  Session,
  SessionSummary,
  WebSocketMessage,
  MutationNode,
} from '../types/api'; 