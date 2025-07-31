// API Types for DragonShard Visualization

export enum AttackStatus {
  PENDING = "pending",
  RUNNING = "running",
  COMPLETED = "completed",
  FAILED = "failed",
  CANCELLED = "cancelled"
}

export enum VulnerabilityLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical"
}

export enum ServiceType {
  HTTP = "http",
  HTTPS = "https",
  SSH = "ssh",
  FTP = "ftp",
  SMTP = "smtp",
  DNS = "dns",
  RDP = "rdp",
  SMB = "smb",
  MYSQL = "mysql",
  POSTGRES = "postgres",
  REDIS = "redis",
  MONGODB = "mongodb"
}

export enum FuzzingStatus {
  IDLE = "idle",
  RUNNING = "running",
  PAUSED = "paused",
  COMPLETED = "completed"
}

// Website Crawling Models
export interface WebsitePageForm {
  form_id: string;
  page_id: string;
  form_action?: string;
  form_method: string;
  form_name?: string;
  form_id_attribute?: string;
  form_class?: string;
  discovered_at: number;
  is_login_form: boolean;
  is_search_form: boolean;
  form_fields: FormField[];
}

export interface FormField {
  name: string;
  type: string;
  id?: string;
  required: boolean;
  placeholder?: string;
}

export interface WebsitePageEndpoint {
  endpoint_id: string;
  page_id: string;
  endpoint_path?: string;
  method: string;
  content_type?: string;
  discovered_at: number;
  is_api_endpoint: boolean;
  parameters: any[];
}

export interface WebsitePage {
  page_id: string;
  website_id: string;
  url: string;
  method: string;
  status_code?: number;
  content_type?: string;
  title?: string;
  discovered_at: number;
  last_accessed_at: number;
  response_size?: number;
  response_time?: number;
  is_accessible: boolean;
  depth: number;
  parent_page_id?: string;
}

export interface Website {
  website_id: string;
  service_id: string;
  base_url: string;
  title?: string;
  description?: string;
  discovered_at: number;
  last_crawled_at: number;
  crawl_status: string;
  total_pages: number;
  total_forms: number;
  total_endpoints: number;
  crawl_depth: number;
  max_pages: number;
}

export interface WebsiteStatistics {
  total_websites: number;
  total_pages: number;
  total_forms: number;
  total_endpoints: number;
  websites_by_status: {
    pending: number;
    crawling: number;
    completed: number;
    failed: number;
  };
}

// Base Models
export interface BaseResponse {
  success: boolean;
  message?: string;
  timestamp: string;
}

// Attack Models
export interface AttackStep {
  id: string;
  name: string;
  description: string;
  status: AttackStatus;
  target: string;
  payload?: string;
  result?: Record<string, any>;
  start_time?: string;
  end_time?: string;
  duration?: number;
}

export interface AttackChain {
  id: string;
  name: string;
  description: string;
  status: AttackStatus;
  steps: AttackStep[];
  total_steps: number;
  completed_steps: number;
  start_time?: string;
  end_time?: string;
  duration?: number;
  success_rate: number;
}

export interface AttackSummary {
  total_attacks: number;
  running_attacks: number;
  completed_attacks: number;
  failed_attacks: number;
  success_rate: number;
  average_duration: number;
}

// Vulnerability Models
export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  level: VulnerabilityLevel;
  cve_id?: string;
  target: string;
  service?: string;
  port?: number;
  discovered_at: string;
  details?: Record<string, any>;
}

export interface VulnerabilitySummary {
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  by_service: Record<string, number>;
  by_level: Record<string, number>;
}

// Network Models
export interface Service {
  id: string;
  name: string;
  type: ServiceType;
  port: number;
  version?: string;
  banner?: string;
  discovered_at: string;
  vulnerabilities: Vulnerability[];
}

export interface Host {
  id: string;
  ip_address: string;
  hostname?: string;
  os_info?: string;
  discovered_at: string;
  last_seen: string;
  services: Service[];
  vulnerabilities: Vulnerability[];
}

export interface NetworkTopology {
  hosts: Host[];
  total_hosts: number;
  total_services: number;
  total_vulnerabilities: number;
  network_range?: string;
}

// Fuzzing Models
export interface FuzzingSession {
  id: string;
  name: string;
  status: FuzzingStatus;
  target: string;
  payload_type: string;
  generation: number;
  population_size: number;
  best_fitness: number;
  average_fitness: number;
  mutations_count: number;
  start_time?: string;
  end_time?: string;
  duration?: number;
}

export interface FuzzingProgress {
  session_id: string;
  generation: number;
  population_size: number;
  best_fitness: number;
  average_fitness: number;
  diversity: number;
  mutations_count: number;
  successful_payloads: number;
  timestamp: string;
}

export interface GeneticAlgorithmStats {
  total_sessions: number;
  active_sessions: number;
  total_generations: number;
  total_mutations: number;
  average_fitness: number;
  best_fitness: number;
}

export interface MutationNode {
  id: string;
  payload: string;
  payloadType: string;
  fitnessScore: number;
  generation: number;
  mutationType: string;
  successful: boolean;
  vulnerabilityDetected: boolean;
  parentId?: string;
  children: string[];
}

// Session Models
export interface Session {
  id: string;
  target: string;
  authenticated: boolean;
  auth_method?: string;
  cookies: Record<string, string>;
  headers: Record<string, string>;
  created_at: string;
  last_used: string;
  requests_count: number;
}

export interface SessionSummary {
  total_sessions: number;
  authenticated_sessions: number;
  active_sessions: number;
  by_target: Record<string, number>;
}

// WebSocket Models
export interface WebSocketMessage {
  type: string;
  data?: Record<string, any>;
  stream?: string;
  sessionId?: string;
  timestamp: string;
} 