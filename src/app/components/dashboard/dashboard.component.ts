import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AttackPreset, DashboardMetrics, ThreatReport } from '../../models/security.model';
import { AIAuditorService } from '../../services/ai-auditor.service';
import { LogGeneratorService } from '../../services/log-generator.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent implements OnInit {
  private readonly logGen = inject(LogGeneratorService);
  private readonly auditor = inject(AIAuditorService);

  attackPresets: AttackPreset[] = this.logGen.getAttackPresets();
  activePresetId = 'full';

  threatReports: ThreatReport[] = [];
  filtered: ThreatReport[] = [];
  metrics: DashboardMetrics = {
    totalLogsIngested: 0,
    criticalThreats: 0,
    activeWarnings: 0,
    cleanTraffic: 0,
    securityHealthScore: 100,
    sanitizedTokensCount: 0,
    threatsByVector: {},
    lastUpdated: new Date(),
  };

  selected: ThreatReport | null = null;

  // filters
  search = '';
  severityFilter: string = 'ALL';
  vectorFilter: string = 'ALL';

  dragOver = false;
  showPaste = false;
  pasteText = '';
  terminalOutput: string[] = [];
  copiedId: string | null = null;

  vectorOptions: string[] = [];

  ngOnInit(): void {
    this.loadPreset('full');
  }

  loadPreset(id: string): void {
    this.activePresetId = id;
    const logs = this.logGen.getSampleLogsByPreset(id);
    const reports = this.auditor.ingestLogs(logs);
    this.threatReports = reports;
    this.metrics = this.auditor.calculateDashboardMetrics(logs, this.logGen.getSanitizedTokensCount());
    this.vectorOptions = Object.keys(this.metrics.threatsByVector);
    this.selected = this.threatReports[0] ?? null;
    this.terminalOutput = [
      `[${new Date().toLocaleTimeString()}] Ingested ${logs.length} lines · Sanitized ${this.metrics.sanitizedTokensCount} tokens · Heuristic pre-filter removed ~90% benign noise`,
      `[${new Date().toLocaleTimeString()}] Structured inference: ${this.threatReports.length} anomalies → JSON schema (threatLevel, attackVector, mitre, confidence, remediation)`,
      `[${new Date().toLocaleTimeString()}] Health = 100 - (Critical×25 + Warning×10) = ${this.metrics.securityHealthScore}`,
    ];
    this.applyFilters();
  }

  loadSampleLogs(): void {
    this.loadPreset('full');
  }

  // file
  onFileSelected(evt: Event): void {
    const input = evt.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) this.handleFile(file);
    input.value = '';
  }

  onDragOver(evt: DragEvent): void {
    evt.preventDefault();
    this.dragOver = true;
  }
  onDragLeave(): void {
    this.dragOver = false;
  }
  onDrop(evt: DragEvent): void {
    evt.preventDefault();
    this.dragOver = false;
    const file = evt.dataTransfer?.files?.[0];
    if (!file) {
      const text = evt.dataTransfer?.getData('text');
      if (text) this.ingestRawText(text);
      return;
    }
    this.handleFile(file);
  }

  private handleFile(file: File): void {
    const reader = new FileReader();
    reader.onload = () => {
      const txt = (reader.result as string) || '';
      this.ingestRawText(txt);
    };
    reader.readAsText(file);
  }

  togglePaste(): void {
    this.showPaste = !this.showPaste;
  }

  ingestRawText(raw: string): void {
    if (!raw.trim()) return;
    const logs = this.logGen.parseRawLogLines(raw);
    const reports = this.auditor.ingestLogs(logs);
    this.threatReports = reports;
    this.metrics = this.auditor.calculateDashboardMetrics(logs, this.logGen.getSanitizedTokensCount());
    this.vectorOptions = Object.keys(this.metrics.threatsByVector);
    this.selected = this.threatReports[0] ?? null;
    this.terminalOutput = [
      `[${new Date().toLocaleTimeString()}] Custom ingestion: ${logs.length} lines · Sanitized ${this.metrics.sanitizedTokensCount} credential tokens`,
      `[${new Date().toLocaleTimeString()}] Heuristic: burst 401/403 + SSH invalid-user + sqli regex clustering applied`,
      `[${new Date().toLocaleTimeString()}] Health = ${this.metrics.securityHealthScore} · Critical ${this.metrics.criticalThreats} · Warning ${this.metrics.activeWarnings}`,
    ];
    this.showPaste = false;
    this.pasteText = '';
    this.activePresetId = 'custom';
    this.applyFilters();
  }

  onPasteAnalyze(): void {
    this.ingestRawText(this.pasteText);
  }

  // filters
  applyFilters(): void {
    const q = this.search.trim().toLowerCase();
    this.filtered = this.threatReports.filter((r) => {
      const sevOk = this.severityFilter === 'ALL' || r.entry.severity === this.severityFilter;
      const vecOk = this.vectorFilter === 'ALL' || r.attackVector === this.vectorFilter;
      const textOk =
        !q ||
        r.entry.sourceIp.toLowerCase().includes(q) ||
        r.entry.threatCategory.toLowerCase().includes(q) ||
        r.attackVector.toLowerCase().includes(q) ||
        r.entry.event.toLowerCase().includes(q) ||
        r.mitreTechnique.id.toLowerCase().includes(q);
      return sevOk && vecOk && textOk;
    });
    if (this.selected && !this.filtered.find((x) => x.id === this.selected!.id)) {
      this.selected = this.filtered[0] ?? null;
    }
    if (!this.selected) this.selected = this.filtered[0] ?? null;
  }

  clearFilters(): void {
    this.search = '';
    this.severityFilter = 'ALL';
    this.vectorFilter = 'ALL';
    this.applyFilters();
  }

  selectReport(r: ThreatReport): void {
    this.selected = r;
  }

  getSeverityClass(s: string): string {
    switch (s) {
      case 'CRITICAL': return 'badge-critical';
      case 'WARNING': return 'badge-warning';
      case 'INFO': return 'badge-info';
      default: return 'badge-clean';
    }
  }

  healthColor(): string {
    const h = this.metrics.securityHealthScore;
    if (h >= 70) return '#10b981';
    if (h >= 40) return '#f59e0b';
    return '#ef4444';
  }

  // terminal actions
  async copy(cmd: string, id: string): Promise<void> {
    try { await navigator.clipboard.writeText(cmd); } catch { /* fallback */ }
    this.copiedId = id;
    this.terminalOutput = [...this.terminalOutput, `[${new Date().toLocaleTimeString()}] Copied: ${cmd.slice(0, 80)}...`];
    setTimeout(() => (this.copiedId = null), 1400);
  }

  copyAll(): void {
    if (!this.selected) return;
    const all = this.selected.recommendedActions.map((a) => a.command).join(' && \\\n');
    this.copy(all, 'all');
  }

  downloadScript(): void {
    if (!this.selected) return;
    const cmds = this.selected.recommendedActions.map((a) => `# ${a.description}\n${a.command}`).join('\n\n');
    const blob = new Blob([`#!/bin/bash\n# AI Security Auditor - ${this.selected.entry.sourceIp} - ${this.selected.attackVector}\nset -e\n\n${cmds}\n\necho "Mitigations applied."`], { type: 'text/x-sh' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mitigate-${this.selected.entry.sourceIp}-${Date.now()}.sh`;
    a.click();
    URL.revokeObjectURL(url);
    this.terminalOutput = [...this.terminalOutput, `[${new Date().toLocaleTimeString()}] Downloaded script for ${this.selected.entry.sourceIp}`];
  }

  execute(actionId: string): void {
    const act = this.selected?.recommendedActions.find((x) => x.id === actionId);
    if (!act) return;
    (act as any).executed = true;
    const ts = new Date().toLocaleTimeString();
    this.terminalOutput = [
      ...this.terminalOutput,
      `[${ts}] $ ${act.command}`,
      `[${ts}] [SIM] Executing ${act.category} ...`,
      `[${ts}] [SUCCESS] ${act.description} — applied (simulated)`,
    ];
  }

  executeAll(): void {
    if (!this.selected) return;
    for (const a of this.selected.recommendedActions) this.execute(a.id);
  }
}
