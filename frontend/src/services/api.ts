// API Service for DragonShard Visualization

import type {
  AttackChain,
  AttackSummary,
  FuzzingSession,
  GeneticAlgorithmStats,
  FuzzingProgress,
  MutationNode,
  Session,
  SessionSummary,
  Host,
  NetworkTopology,
  Vulnerability,
  VulnerabilitySummary,
  Website,
  WebsitePage,
  WebsitePageForm,
  WebsitePageEndpoint,
  WebsiteStatistics,
  WebSocketMessage,
} from '../types/api';

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

  // Website crawling endpoints
  static async getWebsites(): Promise<{ websites: Website[]; total: number; skip: number; limit: number }> {
    return this.request<{ websites: Website[]; total: number; skip: number; limit: number }>('/websites/');
  }

  static async getWebsite(id: string): Promise<Website> {
    return this.request<Website>(`/websites/${id}`);
  }

  static async getWebsitePages(websiteId: string): Promise<{ pages: WebsitePage[]; total: number; skip: number; limit: number }> {
    return this.request<{ pages: WebsitePage[]; total: number; skip: number; limit: number }>(`/websites/${websiteId}/pages`);
  }

  static async getWebsiteForms(websiteId: string): Promise<{ forms: WebsitePageForm[]; total: number; skip: number; limit: number }> {
    return this.request<{ forms: WebsitePageForm[]; total: number; skip: number; limit: number }>(`/websites/${websiteId}/forms`);
  }

  static async getWebsiteEndpoints(websiteId: string): Promise<{ endpoints: WebsitePageEndpoint[]; total: number; skip: number; limit: number }> {
    return this.request<{ endpoints: WebsitePageEndpoint[]; total: number; skip: number; limit: number }>(`/websites/${websiteId}/endpoints`);
  }

  static async getAllForms(): Promise<{ forms: WebsitePageForm[]; total: number; skip: number; limit: number }> {
    return this.request<{ forms: WebsitePageForm[]; total: number; skip: number; limit: number }>('/websites/forms/all');
  }

  static async getAllEndpoints(): Promise<{ endpoints: WebsitePageEndpoint[]; total: number; skip: number; limit: number }> {
    return this.request<{ endpoints: WebsitePageEndpoint[]; total: number; skip: number; limit: number }>('/websites/endpoints/all');
  }

  static async getWebsiteStatistics(): Promise<{ statistics: WebsiteStatistics; timestamp: number }> {
    return this.request<{ statistics: WebsiteStatistics; timestamp: number }>('/websites/statistics');
  }

  static async crawlAllWebsites(): Promise<{ message: string; websites_crawled: number; website_ids: string[] }> {
    return this.request<{ message: string; websites_crawled: number; website_ids: string[] }>('/websites/crawl-all', {
      method: 'POST',
    });
  }

  static async crawlService(serviceId: string): Promise<{ message: string; website: Website }> {
    return this.request<{ message: string; website: Website }>(`/websites/crawl-service/${serviceId}`, {
      method: 'POST',
    });
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
    return this.request<SessionSummary>('/sessions/summary');
  }

  // Target endpoints
  static async addTarget(targetData: any): Promise<Host> {
    return this.request<Host>('/network/hosts/simple', {
      method: 'POST',
      body: JSON.stringify(targetData),
    });
  }

  static async getTargets(): Promise<Host[]> {
    return this.request<Host[]>('/network/hosts');
  }

  static async getTarget(id: string): Promise<Host> {
    return this.request<Host>(`/network/hosts/${id}`);
  }

  static async deleteTarget(id: string): Promise<any> {
    return this.request<any>(`/network/hosts/${id}`, {
      method: 'DELETE',
    });
  }

  static async scanTarget(targetId: string): Promise<any> {
    return this.request<any>(`/network/hosts/${targetId}/scan`, {
      method: 'POST',
    });
  }

  static async getScanStatus(targetId: string): Promise<any> {
    return this.request<any>(`/network/hosts/${targetId}/scan/status`);
  }

  static async getScanResults(targetId: string): Promise<any> {
    return this.request<any>(`/network/hosts/${targetId}/scan/results`);
  }

  // Attack staging endpoints
  static async stageAttack(targetId: string, vulnerabilityId: string): Promise<AttackChain> {
    return this.request<AttackChain>('/attacks/stage', {
      method: 'POST',
      body: JSON.stringify({
        target_id: targetId,
        vulnerability_id: vulnerabilityId,
      }),
    });
  }

  static async getStagedAttacks(): Promise<AttackChain[]> {
    return this.request<AttackChain[]>('/attacks/staged');
  }
}

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
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          setTimeout(() => {
            this.attemptReconnect(onMessage, onError);
          }, this.reconnectDelay);
        }
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
    this.reconnectAttempts++;
    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    this.connect(onMessage, onError);
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
      timestamp: new Date().toISOString(),
    });
  }

  ping() {
    this.send({
      type: 'ping',
      timestamp: new Date().toISOString(),
    });
  }
} 