import { Injectable } from '@angular/core';
import { AttackPreset, LogEntry } from '../models/security.model';

@Injectable({ providedIn: 'root' })
export class LogGeneratorService {
  private sanitizedTokensCount = 0;

  getSanitizedTokensCount(): number {
    return this.sanitizedTokensCount;
  }

  resetSanitizedCounter(): void {
    this.sanitizedTokensCount = 0;
  }

  getAttackPresets(): AttackPreset[] {
    return [
      { id: 'full', name: 'Full Attack Suite', icon: 'fa-layer-group', description: '49 logs · All vectors', count: 49 },
      { id: 'ssh-brute', name: 'SSH Brute Force', icon: 'fa-key', description: '15 attempts · 203.0.113.x', count: 15 },
      { id: 'sqli', name: 'SQL Injection', icon: 'fa-database', description: '8 payloads · Web exploits', count: 8 },
      { id: 'recon', name: 'Recon / Port Scan', icon: 'fa-crosshairs', description: '5 Nmap scans · Discovery', count: 5 },
      { id: 'api-abuse', name: 'API Token Abuse', icon: 'fa-user-secret', description: '1 critical · Token theft', count: 1 },
      { id: 'clean', name: 'Clean Traffic', icon: 'fa-shield', description: '20 benign · Baseline', count: 20 },
    ];
  }

  /** Sanitize private credentials before any AI inference */
  sanitizeLine(line: string): string {
    let out = line;
    const patterns: RegExp[] = [
      /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
      /api[_-]?key[=:]\s*[A-Za-z0-9\-_]+/gi,
      /token[=:]\s*[A-Za-z0-9\-_.]+/gi,
      /password[=:]\s*\S+/gi,
      /passwd[=:]\s*\S+/gi,
      /Authorization:\s*Basic\s+\S+/gi,
    ];
    for (const re of patterns) {
      if (re.test(out)) {
        out = out.replace(re, (m) => {
          this.sanitizedTokensCount++;
          // keep key name, redact value
          const eq = m.indexOf('=') >= 0 ? '=' : m.indexOf(':') >= 0 ? ':' : ' ';
          const parts = m.split(eq);
          return parts.length > 1 ? `${parts[0]}${eq}[REDACTED]` : '[REDACTED]';
        });
      }
    }
    // redact internal 10.x.x.x that might be sensitive when set as env
    return out;
  }

  getSampleLogs(): LogEntry[] {
    return this.buildLogs('full');
  }

  getSampleLogsByPreset(presetId: string): LogEntry[] {
    return this.buildLogs(presetId);
  }

  private buildLogs(preset: string): LogEntry[] {
    this.resetSanitizedCounter();
    const now = new Date();
    const all: LogEntry[] = [];

    const sshLogs: LogEntry[] = Array.from({ length: 15 }, (_, i) => {
      const ts = new Date(now.getTime() - i * 60_000);
      const ip = `203.0.113.${5 + i}`;
      const users = ['admin', 'root', 'deploy', 'ubuntu', 'test'];
      const user = users[i % users.length];
      return {
        id: `ssh_${i}_${ts.getTime()}`,
        timestamp: ts,
        sourceIp: ip,
        destinationIp: '10.0.1.5',
        protocol: 'SSH',
        port: 22,
        event: `Failed password for ${i % 3 === 0 ? 'invalid user ' : ''}${user} from ${ip}`,
        rawLine: this.sanitizeLine(`Aug 24 ${ts.toISOString().slice(11, 19)} web-prod-01 sshd[1847]: Failed password for ${i % 3 === 0 ? 'invalid user ' : ''}${user} from ${ip} port ${4000 + i * 137} ssh2`),
        severity: 'CRITICAL' as const,
        threatCategory: 'Brute Force',
      };
    });

    const sqliLogs: LogEntry[] = Array.from({ length: 8 }, (_, i) => {
      const ts = new Date(now.getTime() - (20 + i * 3) * 60_000);
      const ip = `198.51.100.${10 + i}`;
      const payloads = [
        `' OR '1'='1' --`,
        `' UNION SELECT null,username,password FROM users--`,
        `1; DROP TABLE sessions; --`,
        `admin'--`,
        `1' AND 1=1 UNION SELECT 1,2,3--`,
        `%27%20OR%201=1--`,
        `' OR 1=1 LIMIT 1 --`,
        `../../../../etc/passwd`,
      ];
      const payload = payloads[i % payloads.length];
      return {
        id: `sqli_${i}_${ts.getTime()}`,
        timestamp: ts,
        sourceIp: ip,
        destinationIp: '10.0.1.10',
        protocol: 'HTTP',
        port: 80,
        event: `SQLi payload: ${payload}`,
        rawLine: this.sanitizeLine(`${ip} - - [${ts.toUTCString()}] "GET /api/search?q=${encodeURIComponent(payload)} HTTP/1.1" 403 512 "-" "sqlmap/1.7" token=Bearer eyJhbGciOiJIUzI1NiJ9.[REDACTED]`),
        severity: 'WARNING' as const,
        threatCategory: 'SQL Injection',
      };
    });

    const reconLogs: LogEntry[] = Array.from({ length: 5 }, (_, i) => {
      const ts = new Date(now.getTime() - (60 + i * 12) * 60_000);
      const ip = `192.0.2.${20 + i}`;
      const ports = ['22,80,443,3306,6379', '22,25,80,443,8080', '1-65535', '80,443', '22,3000,5000'];
      return {
        id: `recon_${i}_${ts.getTime()}`,
        timestamp: ts,
        sourceIp: ip,
        destinationIp: '10.0.1.5',
        protocol: 'TCP',
        port: 0,
        event: `Nmap SYN scan ports ${ports[i]}`,
        rawLine: this.sanitizeLine(`[**] [1:1000001:1] ET SCAN Nmap SYN Scan ${ports[i]} [**] [Priority: 2] {TCP} ${ip}:54321 -> 10.0.1.5:${ports[i].split(',')[0]}`),
        severity: 'WARNING' as const,
        threatCategory: 'Port Scan',
      };
    });

    const apiLogs: LogEntry[] = [
      {
        id: `api_${now.getTime()}`,
        timestamp: new Date(now.getTime() - 2 * 60_000),
        sourceIp: '172.16.0.44',
        destinationIp: '10.0.1.20',
        protocol: 'HTTPS',
        port: 443,
        event: 'Unauthorized API token replay /admin/export',
        rawLine: this.sanitizeLine(`2025-08-24T10:13:02Z api-gateway: WARN apikey=sk_live_51H8x9B2eZvKYlo2C token=Bearer [REDACTED] src=172.16.0.44 GET /admin/export 401 Unauthorized`),
        severity: 'CRITICAL' as const,
        threatCategory: 'Unauthorized Access',
      },
    ];

    const cleanLogs: LogEntry[] = Array.from({ length: 20 }, (_, i) => {
      const ts = new Date(now.getTime() - (300 + i * 7) * 60_000);
      const ip = `10.0.0.${10 + i}`;
      const paths = ['/api/health', '/static/app.js', '/api/user/profile', '/login', '/dashboard'];
      return {
        id: `clean_${i}_${ts.getTime()}`,
        timestamp: ts,
        sourceIp: ip,
        destinationIp: '10.0.1.10',
        protocol: 'HTTPS',
        port: 443,
        event: `GET ${paths[i % paths.length]} 200 OK`,
        rawLine: this.sanitizeLine(`${ip} - - [${ts.toUTCString()}] "GET ${paths[i % paths.length]} HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`),
        severity: 'CLEAN' as const,
        threatCategory: 'Benign',
      };
    });

    switch (preset) {
      case 'ssh-brute':
        all.push(...sshLogs);
        break;
      case 'sqli':
        all.push(...sqliLogs);
        break;
      case 'recon':
        all.push(...reconLogs);
        break;
      case 'api-abuse':
        all.push(...apiLogs);
        break;
      case 'clean':
        all.push(...cleanLogs);
        break;
      case 'full':
      default:
        all.push(...sshLogs, ...sqliLogs, ...reconLogs, ...apiLogs, ...cleanLogs);
        break;
    }

    // sort newest first
    return all.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  parseRawLogLines(raw: string): LogEntry[] {
    this.resetSanitizedCounter();
    const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return [];

    const entries: LogEntry[] = [];
    const now = new Date();

    for (let idx = 0; idx < lines.length; idx++) {
      const original = lines[idx];
      const line = this.sanitizeLine(original);

      // heuristic: discard 90% benign 200 GET noise if requested? we keep but mark CLEAN
      const isBenign200 = /"GET .*?" 200 /.test(line) && !/Union|OR 1=1|Failed|Nmap|Unauthorized|401|403/i.test(line);
      const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      const ip = ipMatch ? ipMatch[1] : `0.0.0.${idx % 255}`;

      let severity: LogEntry['severity'] = 'INFO';
      let category = 'Benign';
      let event = line.slice(0, 120);
      let port = 443;
      let protocol = 'TCP';

      if (/Failed password|Invalid user|sshd.*Failed|Brute/i.test(line)) {
        severity = 'CRITICAL';
        category = 'Brute Force';
        event = 'SSH brute-force authentication failure';
        port = 22;
        protocol = 'SSH';
      } else if (/UNION|OR 1=1|sqlmap|%27|DROP TABLE|\/etc\/passwd|SELECT.*FROM/i.test(line)) {
        severity = 'WARNING';
        category = 'SQL Injection';
        event = 'Possible SQL injection / traversal payload';
        port = 80;
        protocol = 'HTTP';
      } else if (/Nmap|ET SCAN|SYN Scan|Port scan|open ports/i.test(line)) {
        severity = 'WARNING';
        category = 'Port Scan';
        event = 'Network reconnaissance / port scan';
        port = 0;
        protocol = 'TCP';
      } else if (/Unauthorized|401|403.*admin|apikey|Bearer.*REDACTED|token/i.test(line)) {
        severity = 'CRITICAL';
        category = 'Unauthorized Access';
        event = 'Unauthorized API / credential abuse';
        port = 443;
        protocol = 'HTTPS';
      } else if (isBenign200) {
        severity = 'CLEAN';
        category = 'Benign';
        event = 'Benign HTTP 200 traffic';
      } else if (/404|500|error/i.test(line)) {
        severity = 'INFO';
        category = 'Benign';
        event = 'Application error / 4xx';
      }

      entries.push({
        id: `parsed_${idx}_${now.getTime()}`,
        timestamp: new Date(now.getTime() - idx * 30_000),
        sourceIp: ip,
        destinationIp: '10.0.1.5',
        protocol,
        port,
        event,
        rawLine: line,
        severity,
        threatCategory: category,
        sanitized: original !== line,
      });
    }

    return entries;
  }
}
