export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';

export interface ProviderResult {
  provider: string;
  indicator_type: string;
  indicator_value: string;
  status: string;
  matched: boolean;
  verified: boolean;
  reference?: string | null;
  details?: Record<string, any> | null;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface RiskReport {
  report_id: string;
  summary: string;
  evidence: string[];
  recommendations: string[];
  report_hash: string;
  verification_status: string;
  blockchain_tx?: string | null;
  created_at: string;
}

export interface ScanEvent {
  event_type: string;
  description: string;
  created_at: string;
}

export interface MessageIndicator {
  category: string;
  severity: string;
  description: string;
}

export interface ScanDetail {
  scan_id: string;
  scan_type: 'url' | 'domain' | 'message';
  target: string;
  normalized_target?: string | null;
  domain?: string | null;
  hostname?: string | null;
  status: string;
  risk_level: RiskLevel;
  risk_score: number;
  created_at: string;
  providers_checked: ProviderResult[];
  report: RiskReport;
  events: ScanEvent[];
  message_indicators?: MessageIndicator[];
  analysis_engine?: string;
}

export interface ScanListItem {
  id: string;
  scan_type: string;
  target: string;
  status: string;
  risk_level: RiskLevel;
  risk_score: number;
  created_at: string;
  report_hash?: string | null;
  verification_status?: string | null;
}

export interface ScanListResponse {
  total: number;
  items: ScanListItem[];
}

export interface VerifyReportResponse {
  report_id: string;
  stored_hash: string;
  recalculated_hash: string;
  is_valid: boolean;
  verification_status: string;
  audit_notes: string;
  blockchain_verified: boolean;
  blockchain_tx?: string | null;
}

export interface ProviderStatusItem {
  provider_name: string;
  category: string;
  configured: boolean;
  status: string;
  details: string;
  env_variable: string;
}

export interface SystemStatusResponse {
  status: string;
  database_connected: boolean;
  database_type: string;
  providers: ProviderStatusItem[];
  app_version: string;
  environment: string;
}

export interface StatsOverviewResponse {
  total_scans: number;
  malicious_count: number;
  suspicious_count: number;
  benign_count: number;
  risk_distribution: Record<string, number>;
  recent_scans: ScanListItem[];
}
