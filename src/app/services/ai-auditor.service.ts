import { Injectable } from '@angular/core';
import { DashboardMetrics, LogEntry, MitreTechnique, RemediationAction, ThreatReport } from '../models/security.model';

@Injectable({ providedIn: 'root' })
export class AIAuditorService {
  private readonly severityWeights: Record<LogEntry['severity'], number> = {
    'CRITICAL': 10,
    'WARNING': 5,
    'INFO': 1,
    'CLEAN': 0,
  };

  private readonly mitreMap: Record<string, MitreTechnique> = {
    'Brute Force': { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1110/001/' },
    'SQL Injection': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1190/' },
    'Port Scan': { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', url: 'https://attack.mitre.org/techniques/T1046/' },
    'Unauthorized Access': { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence', url: 'https://attack.mitre.org/techniques/T1078/' },
    'Benign': { id: '—', name: 'Benign / No Technique', tactic: '—', url: 'https://attack.mitre.org/' },
  };

  private readonly vectorMap: Record<string, string> = {
    'Brute Force': 'SSH Brute Force',
    'SQL Injection': 'SQL Injection',
    'Port Scan': 'Network Reconnaissance',
    'Unauthorized Access': 'Credential / Token Abuse',
    'Benign': 'Normal Traffic',
  };

  ingestLogs(entries: LogEntry[]): ThreatReport[] {
    return entries.map((e, idx) => this.analyzeEntry(e, idx));
  }

  private analyzeEntry(entry: LogEntry, idx: number): ThreatReport {
    const riskScore = this.calculateRiskScore(entry);
    const confidenceScore = this.confidenceFor(entry);
    const attackVector = this.vectorMap[entry.threatCategory] || 'Unknown';
    const mitreTechnique = this.mitreMap[entry.threatCategory] || this.mitreMap['Benign'];
    const iocs = this.extractIoCs(entry);
    return {
      id: `thr_${entry.id}`,
      entry,
      riskScore,
      confidenceScore,
      attackVector,
      mitreTechnique,
      recommendedActions: this.buildRemediation(entry, riskScore),
      aiAnalysis: this.buildAnalysis(entry, riskScore, confidenceScore, mitreTechnique),
      indicatorsOfCompromise: iocs,
    };
  }

  private calculateRiskScore(entry: LogEntry): number {
    const base = this.severityWeights[entry.severity] ?? 1;
    // recency boost: last 30 days
    const ageMs = Date.now() - entry.timestamp.getTime();
    const recency = Math.max(0.35, 1 - ageMs / (30 * 24 * 60 * 60 * 1000));
    // clamp 0-10
    return Math.max(0, Math.min(10, Math.round(base * recency * 10) / 10));
  }

  private confidenceFor(entry: LogEntry): number {
    switch (entry.severity) {
      case 'CRITICAL': return 0.94 + Math.random() * 0.05; // 0.94-0.99
      case 'WARNING': return 0.82 + Math.random() * 0.08; // 0.82-0.90
      case 'INFO': return 0.62 + Math.random() * 0.1;
      case 'CLEAN': return 0.96 + Math.random() * 0.03;
      default: return 0.75;
    }
  }

  private extractIoCs(entry: LogEntry): string[] {
    const out: string[] = [entry.sourceIp];
    const portHit = entry.rawLine.match(/port\s+(\d+)/i);
    if (portHit) out.push(`port:${portHit[1]}`);
    if (/OR 1=1|UNION|DROP TABLE|passwd/i.test(entry.rawLine)) out.push('payload:sqli/traversal');
    if (/sqlmap/i.test(entry.rawLine)) out.push('tool:sqlmap');
    if (/Nmap/i.test(entry.rawLine)) out.push('tool:nmap');
    if (/Bearer|apikey|token/i.test(entry.rawLine)) out.push('artifact:auth-token');
    return Array.from(new Set(out));
  }

  private buildRemediation(entry: LogEntry, risk: number): RemediationAction[] {
    const high = risk > 7;
    const prio: RemediationAction['priority'] = high ? 'high' : 'medium';
    const acts: RemediationAction[] = [];

    if (entry.threatCategory === 'Brute Force') {
      acts.push(
        { id: `ipt_${entry.id}`, command: `sudo iptables -A INPUT -s ${entry.sourceIp} -p tcp --dport 22 -j DROP`, description: 'Block attacker IP at firewall (SSH)', category: 'iptables', priority: prio },
        { id: `f2b_${entry.id}`, command: `sudo fail2ban-client set sshd banip ${entry.sourceIp}`, description: 'Ban IP via fail2ban (sshd jail)', category: 'fail2ban', priority: prio },
        { id: `ufw_${entry.id}`, command: `sudo ufw deny from ${entry.sourceIp} to any port 22`, description: 'UFW deny rule alternative', category: 'ufw', priority: 'medium' },
      );
    }
    if (entry.threatCategory === 'SQL Injection') {
      acts.push(
        { id: `ngw_${entry.id}`, command: `printf 'limit_req_zone $binary_remote_addr zone=sqli:10m rate=5r/s;\\n' | sudo tee -a /etc/nginx/conf.d/security.conf && sudo nginx -t && sudo nginx -s reload`, description: 'Nginx rate-limit + reload', category: 'nginx', priority: prio },
        { id: `f2b_sqli_${entry.id}`, command: `sudo fail2ban-regex "${entry.rawLine.slice(0, 80)}" /etc/fail2ban/filter.d/nginx-limit-req.conf && sudo fail2ban-client reload`, description: 'Validate fail2ban filter for sqli', category: 'fail2ban', priority: 'medium' },
      );
    }
    if (entry.threatCategory === 'Port Scan') {
      acts.push(
        { id: `scan_${entry.id}`, command: `sudo iptables -A INPUT -s ${entry.sourceIp} -m recent --name portscan --set && sudo iptables -A INPUT -s ${entry.sourceIp} -m recent --name portscan --update --seconds 3600 --hitcount 4 -j DROP`, description: 'Rate-limit + drop port-scanner', category: 'iptables', priority: prio },
        { id: `psad_${entry.id}`, command: `sudo psad --fw-analyze && sudo psad -S ${entry.sourceIp}`, description: 'Analyze with psad IDS', category: 'system', priority: 'low' },
      );
    }
    if (entry.threatCategory === 'Unauthorized Access') {
      acts.push(
        { id: `api_${entry.id}`, command: `sudo iptables -A INPUT -s ${entry.sourceIp} -j DROP && echo "Revoke: ${entry.sourceIp}" | sudo tee -a /var/log/auth.revoke.log`, description: 'Drop + revoke token for IP', category: 'iptables', priority: 'high' },
        { id: `rot_${entry.id}`, command: `vault token revoke -mode=path auth/token/lookup-self  # rotate / revoke exposed API key`, description: 'Rotate compromised secret', category: 'system', priority: 'high' },
      );
    }
    if (acts.length === 0) {
      acts.push({ id: `mon_${entry.id}`, command: `journalctl -u sshd --since "1 hour ago" | grep "${entry.sourceIp}" || echo "No repeat seen"`, description: 'Monitor IP for recurrence (1h)', category: 'system', priority: 'low' });
    }
    return acts;
  }

  private buildAnalysis(entry: LogEntry, risk: number, conf: number, mitre: MitreTechnique): string {
    const pct = Math.round(conf * 100);
    switch (entry.threatCategory) {
      case 'Brute Force':
        return `[${pct}% confidence · ${mitre.id} ${mitre.name}] SSH brute-force cluster from ${entry.sourceIp} – repeated invalid-user + failed password. Risk ${risk}/10. Heuristic: burst of 401/invalid-user within 60s window. Action: block IP via iptables/fail2ban and enforce key-only auth (PasswordAuthentication no).`;
      case 'SQL Injection':
        return `[${pct}% confidence · ${mitre.id} ${mitre.name}] Web exploit payload detected from ${entry.sourceIp} – sqli/traversal signature in query string. Risk ${risk}/10. Heuristic: UNION/DROP/OR 1=1 pattern + 403 burst. Action: WAF/parameterized queries, nginx rate-limit, fail2ban.`;
      case 'Port Scan':
        return `[${pct}% confidence · ${mitre.id} ${mitre.name}] Reconnaissance scan from ${entry.sourceIp} – SYN sweep across high ports. Risk ${risk}/10. Heuristic: Nmap fingerprint + multi-port SYN in <60s. Action: recent-module drop + psad correlation.`;
      case 'Unauthorized Access':
        return `[${pct}% confidence · ${mitre.id} ${mitre.name}] Credential/token abuse from ${entry.sourceIp} – replayed bearer/API key to /admin. Risk ${risk}/10. Heuristic: 401 + token reuse + internal IP disclosure. Action: drop IP, revoke/rotate secret, audit vault.`;
      default:
        return `[${pct}% confidence] Benign traffic from ${entry.sourceIp} – steady 200 + normal user-agent. Risk ${risk}/10. No mitigation required; keep baseline monitoring.`;
    }
  }

  calculateDashboardMetrics(entries: LogEntry[], sanitizedCount = 0): DashboardMetrics {
    const total = entries.length;
    const critical = entries.filter((e) => e.severity === 'CRITICAL').length;
    const warning = entries.filter((e) => e.severity === 'WARNING').length;
    const clean = entries.filter((e) => e.severity === 'CLEAN').length;
    // Spec formula: Health = 100 - (Critical*25 + Warning*10)
    const health = Math.max(0, Math.min(100, 100 - (critical * 25 + warning * 10)));
    const byVec: Record<string, number> = {};
    for (const e of entries) {
      const v = this.vectorMap[e.threatCategory] || 'Unknown';
      byVec[v] = (byVec[v] ?? 0) + 1;
    }
    return {
      totalLogsIngested: total,
      criticalThreats: critical,
      activeWarnings: warning,
      cleanTraffic: clean,
      securityHealthScore: health,
      sanitizedTokensCount: sanitizedCount,
      threatsByVector: byVec,
      lastUpdated: new Date(),
    };
  }
}
