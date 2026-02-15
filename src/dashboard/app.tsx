import React, { useState, useEffect } from 'react';
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
}

interface DynamicResult {
  networkAttempts: { domain: string; port: string; raw: string }[];
  resourceSamples: { ts: number; cpu: number; mem: number }[];
  fsChanges: string[];
  installExit: number;
  installDuration: number;
  timedOut: boolean;
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

const LEVEL_COLORS: Record<string, string> = {
  safe: '#22c55e',
  low: '#3b82f6',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  danger: '#f97316',
  warning: '#eab308',
  info: '#6b7280',
};

function App() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  useEffect(() => { loadHistory(); }, []);

  async function loadHistory() {
    const res = await fetch('/api/history');
    setHistory(await res.json());
  }

  async function doScan(pkg: string) {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: pkg }),
      });
      const data = await res.json();
      if (data.error) { setError(data.error); return; }
      setResult(data);
      loadHistory();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadScan(id: number) {
    const res = await fetch(`/api/scan/${id}`);
    const data = await res.json();
    if (!data.error) setResult(data);
  }

  return (
    <div className="app">
      <header>
        <h1>unsus</h1>
        <span className="subtitle">npm supply chain malware scanner</span>
      </header>

      <ScanForm query={query} setQuery={setQuery} onScan={doScan} loading={loading} />

      {error && <div className="error-banner">{error}</div>}
      {loading && <div className="loading">Fetching and scanning...</div>}

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
  const grouped = { critical: [] as Finding[], danger: [] as Finding[], warning: [] as Finding[], info: [] as Finding[] };
  for (const f of findings) {
    (grouped[f.severity] || grouped.info).push(f);
  }

  return (
    <div className="findings">
      <h3>Findings ({findings.length})</h3>
      {(['critical', 'danger', 'warning', 'info'] as Severity[]).map(sev => {
        const list = grouped[sev];
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
            <tr key={i}>
              <td className="ioc-type">{ioc.type}</td>
              <td className="ioc-value">{ioc.value.length > 60 ? ioc.value.slice(0, 57) + '...' : ioc.value}</td>
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
            <div key={i} className="net-attempt">→ {n.domain}:{n.port}</div>
          ))}
        </div>
      )}
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
