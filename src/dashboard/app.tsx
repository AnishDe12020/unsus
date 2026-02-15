import React, { useState, useEffect, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type Severity = 'info' | 'warning' | 'danger' | 'critical';
type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';

interface Finding {
  type: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  code: string;
}

interface IOC {
  type: string;
  value: string;
  context: string;
  threatMatch?: { source: string; detail: string };
}

interface DynamicResult {
  networkAttempts: { domain: string; port: string; raw: string }[];
  resourceSamples: { ts: number; cpu: number; mem: number }[];
  fsChanges: string[];
  installExit: number;
  installDuration: number;
  timedOut: boolean;
}

interface AIAnalysis {
  verdict: 'safe' | 'suspicious' | 'malicious' | 'skipped';
  aiScore: number | null;
  analysis: string;
  reason: string;
  provider: string | null;
}

interface ScanResult {
  id?: number;
  packageName: string;
  version: string;
  riskScore: number;
  riskLevel: RiskLevel;
  findings: Finding[];
  iocs: IOC[];
  dynamicAnalysis?: DynamicResult;
  aiAnalysis?: AIAnalysis;
  summary: string;
}

interface HistoryEntry {
  id: number;
  packageName: string;
  version: string;
  riskScore: number;
  riskLevel: RiskLevel;
  timestamp: number;
}

interface StageInfo {
  stage: string;
  status: 'pending' | 'running' | 'done' | 'error';
  message: string;
  logs: string[];
}

const LEVEL_COLORS: Record<string, string> = {
  safe: '#22c55e', low: '#3b82f6', medium: '#eab308', high: '#f97316', critical: '#ef4444',
};

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444', danger: '#f97316', warning: '#eab308', info: '#6b7280',
};

const VERDICT_COLORS: Record<string, string> = {
  safe: '#22c55e', suspicious: '#eab308', malicious: '#ef4444', skipped: '#6b7280',
};

const STAGE_LABELS: Record<string, string> = {
  fetch: 'Fetch Package',
  static: 'Static Analysis',
  dynamic: 'Dynamic Analysis',
  ai: 'AI Analysis',
};

const STAGE_ORDER = ['fetch', 'static', 'dynamic', 'ai'];

function App() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [stages, setStages] = useState<StageInfo[]>([]);

  useEffect(() => { loadHistory(); }, []);

  async function loadHistory() {
    try {
      const res = await fetch('/api/history');
      setHistory(await res.json());
    } catch {}
  }

  async function doScan(pkg: string) {
    setLoading(true);
    setError('');
    setResult(null);
    setStages(STAGE_ORDER.map(s => ({ stage: s, status: 'pending', message: '', logs: [] })));

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: pkg }),
      });

      if (!res.ok) {
        const body = await res.text();
        setError(`Server error (${res.status}): ${body}`);
        return;
      }

      if (!res.body) {
        setError('No response stream');
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let gotResult = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        let eventType = '';
        for (const line of lines) {
          if (line.startsWith(': ')) continue; // SSE comment (keepalive)
          if (line.startsWith('event: ')) {
            eventType = line.slice(7);
          } else if (line.startsWith('data: ') && eventType) {
            try {
              const data = JSON.parse(line.slice(6));
              if (eventType === 'result') gotResult = true;
              handleSSE(eventType, data);
            } catch {}
            eventType = '';
          }
        }
      }

      if (!gotResult && !error) {
        setError('Connection closed before scan completed');
      }
    } catch (e: any) {
      setError(e.message === 'Failed to fetch'
        ? 'Connection lost — scan may still be running on server. Refresh to check history.'
        : `Connection error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  function handleSSE(event: string, data: any) {
    if (event === 'stage') {
      setStages(prev => prev.map(s =>
        s.stage === data.stage ? { ...s, status: data.status, message: data.message } : s
      ));
    } else if (event === 'log') {
      setStages(prev => prev.map(s =>
        s.stage === data.stage ? { ...s, logs: [...s.logs, data.message] } : s
      ));
    } else if (event === 'result') {
      setResult(data);
      loadHistory();
    } else if (event === 'error') {
      setError(data.error);
    }
  }

  async function loadScan(id: number) {
    const res = await fetch(`/api/scan/${id}`);
    const data = await res.json();
    if (!data.error) {
      setResult(data);
      setStages([]);
    }
  }

  return (
    <div className="app">
      <header>
        <h1>unsus</h1>
        <span className="subtitle">npm supply chain malware scanner</span>
      </header>

      <ScanForm query={query} setQuery={setQuery} onScan={doScan} loading={loading} />

      {error && <div className="error-banner">{error}</div>}
      {loading && <ProgressPanel stages={stages} />}

      {result && <ScanView result={result} />}

      <HistoryFeed entries={history} onSelect={loadScan} />
    </div>
  );
}

function ScanForm({ query, setQuery, onScan, loading }: {
  query: string; setQuery: (s: string) => void; onScan: (s: string) => void; loading: boolean;
}) {
  return (
    <form className="scan-form" onSubmit={e => { e.preventDefault(); if (query.trim()) onScan(query.trim()); }}>
      <input
        type="text"
        value={query}
        onChange={e => setQuery(e.target.value)}
        placeholder="package name (e.g. axios, lodash, is-odd)"
        disabled={loading}
        autoFocus
      />
      <button type="submit" disabled={loading || !query.trim()}>
        {loading ? 'Scanning...' : 'Scan'}
      </button>
    </form>
  );
}

function ProgressPanel({ stages }: { stages: StageInfo[] }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const toggle = (stage: string) =>
    setExpanded(prev => ({ ...prev, [stage]: !prev[stage] }));

  return (
    <div className="progress-panel">
      {stages.map(s => (
        <div key={s.stage} className={`progress-stage stage-${s.status}`}>
          <div className="stage-header" onClick={() => s.logs.length > 0 && toggle(s.stage)}>
            <span className="stage-icon">
              {s.status === 'pending' && <span className="icon-pending" />}
              {s.status === 'running' && <span className="icon-spinner" />}
              {s.status === 'done' && <span className="icon-check" />}
              {s.status === 'error' && <span className="icon-error" />}
            </span>
            <span className="stage-label">{STAGE_LABELS[s.stage] || s.stage}</span>
            {s.message && <span className="stage-message">{s.message}</span>}
            {s.logs.length > 0 && (
              <span className="stage-expand">{expanded[s.stage] ? '\u25B4' : '\u25BE'}</span>
            )}
          </div>
          {expanded[s.stage] && s.logs.length > 0 && (
            <div className="stage-logs">
              {s.logs.map((log, i) => (
                <div key={i} className="stage-log-line">{log}</div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ScanView({ result }: { result: ScanResult }) {
  const color = LEVEL_COLORS[result.riskLevel] || '#fff';

  return (
    <div className="scan-view">
      <div className="scan-header" style={{ borderColor: color }}>
        <RiskGauge score={result.riskScore} level={result.riskLevel} />
        <div className="scan-meta">
          <h2>{result.packageName}@{result.version}</h2>
          <p className="summary">{result.summary}</p>
        </div>
      </div>

      {result.aiAnalysis && <AIPanel ai={result.aiAnalysis} scannerScore={result.riskScore} />}
      {result.findings.length > 0 && <FindingsList findings={result.findings} />}
      {result.iocs.length > 0 && <IOCTable iocs={result.iocs} />}
      {result.dynamicAnalysis && <DynamicPanel data={result.dynamicAnalysis} />}
    </div>
  );
}

function RiskGauge({ score, level }: { score: number; level: RiskLevel }) {
  const color = LEVEL_COLORS[level] || '#fff';
  const pct = (score / 10) * 100;
  const r = 54;
  const circ = 2 * Math.PI * r;
  const dashoffset = circ - (pct / 100) * circ;

  return (
    <div className="risk-gauge">
      <svg viewBox="0 0 120 120" width="120" height="120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#2a2a2a" strokeWidth="10" />
        <circle
          cx="60" cy="60" r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={dashoffset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
          style={{ transition: 'stroke-dashoffset 0.5s ease' }}
        />
        <text x="60" y="55" textAnchor="middle" fill={color} fontSize="24" fontWeight="bold">
          {score.toFixed(1)}
        </text>
        <text x="60" y="75" textAnchor="middle" fill={color} fontSize="13" textTransform="uppercase">
          {level}
        </text>
      </svg>
    </div>
  );
}

function FindingsList({ findings }: { findings: Finding[] }) {
  const [collapsed, setCollapsed] = useState(findings.length > 8);
  const grouped = { critical: [] as Finding[], danger: [] as Finding[], warning: [] as Finding[], info: [] as Finding[] };
  for (const f of findings) {
    (grouped[f.severity] || grouped.info).push(f);
  }
  const shown = collapsed ? findings.slice(0, 8) : findings;
  const shownGrouped = { critical: [] as Finding[], danger: [] as Finding[], warning: [] as Finding[], info: [] as Finding[] };
  for (const f of shown) {
    (shownGrouped[f.severity] || shownGrouped.info).push(f);
  }

  return (
    <div className="findings">
      <h3>Findings ({findings.length})</h3>
      {(['critical', 'danger', 'warning', 'info'] as Severity[]).map(sev => {
        const list = shownGrouped[sev];
        if (!list.length) return null;
        return (
          <div key={sev} className="finding-group">
            {list.map((f, i) => (
              <div key={i} className="finding-card">
                <span className="sev-badge" style={{ background: SEV_COLORS[f.severity] }}>
                  {f.severity}
                </span>
                <span className="finding-msg">{f.message}</span>
                {f.file && <span className="finding-loc">{f.file}{f.line ? `:${f.line}` : ''}</span>}
              </div>
            ))}
          </div>
        );
      })}
      {findings.length > 8 && (
        <button className="show-more" onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? `Show all ${findings.length} findings` : 'Show less'}
        </button>
      )}
    </div>
  );
}

function IOCTable({ iocs }: { iocs: IOC[] }) {
  return (
    <div className="iocs">
      <h3>IOCs ({iocs.length})</h3>
      <table>
        <thead>
          <tr><th>Type</th><th>Value</th><th>Location</th></tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={i} className={ioc.threatMatch ? 'threat-match' : ''}>
              <td className="ioc-type">{ioc.type}</td>
              <td className="ioc-value">
                {ioc.value.length > 60 ? ioc.value.slice(0, 57) + '...' : ioc.value}
                {ioc.threatMatch && <span className="threat-badge">{ioc.threatMatch.source}</span>}
              </td>
              <td className="ioc-ctx">{ioc.context}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DynamicPanel({ data }: { data: DynamicResult }) {
  const avgCpu = data.resourceSamples.length > 2
    ? data.resourceSamples.reduce((s, x) => s + x.cpu, 0) / data.resourceSamples.length
    : 0;

  return (
    <div className="dynamic">
      <h3>Dynamic Analysis</h3>
      <div className="dynamic-stats">
        <div>Install: {data.timedOut ? 'TIMED OUT' : data.installExit === 0 ? 'OK' : `exit ${data.installExit}`} ({data.installDuration}s)</div>
        {avgCpu > 0 && <div>CPU: avg {avgCpu.toFixed(0)}%</div>}
      </div>
      {data.networkAttempts.length > 0 && (
        <div className="network-attempts">
          <h4>Blocked outbound requests:</h4>
          {data.networkAttempts.map((n, i) => (
            <div key={i} className="net-attempt">{'\u2192'} {n.domain}:{n.port}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function AIPanel({ ai, scannerScore }: { ai: AIAnalysis; scannerScore: number }) {
  const [collapsed, setCollapsed] = useState(false);

  if (ai.verdict === 'skipped' && ai.reason.includes('too low')) return null;
  if (ai.verdict === 'skipped') {
    return <div className="ai-panel ai-skipped"><span className="ai-skip-reason">{ai.reason}</span></div>;
  }
  if (ai.verdict === 'safe' && !ai.analysis) return null;

  const color = VERDICT_COLORS[ai.verdict] || '#6b7280';
  const provider = ai.provider ? ai.provider[0]!.toUpperCase() + ai.provider.slice(1) : 'AI';

  const finalScore = ai.aiScore !== null
    ? Math.round((scannerScore * 0.4 + ai.aiScore * 0.6) * 10) / 10
    : scannerScore;

  return (
    <div className="ai-panel" style={{ borderColor: color }}>
      <div className="ai-top" onClick={() => setCollapsed(!collapsed)}>
        <div className="ai-header">
          <span className="ai-verdict" style={{ color }}>
            {ai.verdict.toUpperCase()}
          </span>
          <span className="ai-provider">{provider}</span>
          {ai.aiScore !== null && (
            <span className="ai-scores-inline">
              Scanner: {scannerScore.toFixed(1)} / AI: {ai.aiScore.toFixed(1)} / <strong>Final: {finalScore.toFixed(1)}</strong>
            </span>
          )}
        </div>
        <span className="ai-toggle">{collapsed ? '\u25BE' : '\u25B4'}</span>
      </div>
      {!collapsed && ai.analysis && <p className="ai-analysis">{ai.analysis}</p>}
    </div>
  );
}

function HistoryFeed({ entries, onSelect }: { entries: HistoryEntry[]; onSelect: (id: number) => void }) {
  if (!entries.length) return null;

  return (
    <div className="history">
      <h3>Scan History</h3>
      <div className="history-list">
        {entries.map(e => (
          <button key={e.id} className="history-entry" onClick={() => onSelect(e.id)}>
            <span className="history-pkg">{e.packageName}@{e.version}</span>
            <span className="history-score" style={{ color: LEVEL_COLORS[e.riskLevel] }}>
              {e.riskScore.toFixed(1)} {e.riskLevel}
            </span>
            <span className="history-time">{new Date(e.timestamp * 1000).toLocaleTimeString()}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
