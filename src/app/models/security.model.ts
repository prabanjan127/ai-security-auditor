export type Severity = 'CRITICAL' | 'WARNING' | 'INFO' | 'CLEAN';

export interface LogEntry {
  id: string;
  timestamp: Date;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  port: number;
  event: string;
  rawLine: string;
  severity: Severity;
  threatCategory: string;
  sanitized?: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface RemediationAction {
  id: string;
  command: string;
  description: string;
  category: 'iptables' | 'fail2ban' | 'nginx' | 'ufw' | 'system';
  priority: 'high' | 'medium' | 'low';
  executed?: boolean;
}

export interface ThreatReport {
  id: string;
  entry: LogEntry;
  riskScore: number;
  confidenceScore: number;
  attackVector: string;
  mitreTechnique: MitreTechnique;
  recommendedActions: RemediationAction[];
  aiAnalysis: string;
  indicatorsOfCompromise: string[];
}

export interface DashboardMetrics {
  totalLogsIngested: number;
  criticalThreats: number;
  activeWarnings: number;
  cleanTraffic: number;
  securityHealthScore: number;
  sanitizedTokensCount: number;
  threatsByVector: Record<string, number>;
  lastUpdated: Date;
}

export interface AttackPreset {
  id: string;
  name: string;
  icon: string;
  description: string;
  count: number;
}
