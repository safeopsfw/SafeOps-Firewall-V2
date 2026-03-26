import { useState, useEffect, useCallback, useRef } from 'react';
import { FileText, Activity, Database, RefreshCw, AlertCircle, Filter, Network } from 'lucide-react';

const LOGS_BASE = '/api/engine';   // proxied → :50052/api/v1
const LOG_FILE  = 'D:/SafeOpsFV2/bin/logs/network_packets_master.jsonl';

function StatCard({ icon: Icon, label, value, sub, color = 'blue' }) {
  const colors = {
    blue:   'bg-blue-500/10 text-blue-400 border-blue-500/20',
    green:  'bg-green-500/10 text-green-400 border-green-500/20',
    yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    red:    'bg-red-500/10 text-red-400 border-red-500/20',
  };
  return (
    <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-4 flex items-start gap-3">
      <div className={`p-2 rounded-lg border ${colors[color]}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <div className="text-xl font-bold text-dark-900 dark:text-white">{value ?? '—'}</div>
        <div className="text-xs text-dark-500 dark:text-dark-400">{label}</div>
        {sub && <div className="text-xs text-dark-500 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

function ProtoTag({ proto }) {
  const map = {
    TCP:  'bg-blue-500/20 text-blue-400',
    UDP:  'bg-purple-500/20 text-purple-400',
    ICMP: 'bg-yellow-500/20 text-yellow-400',
    DNS:  'bg-green-500/20 text-green-400',
    HTTP: 'bg-orange-500/20 text-orange-400',
    TLS:  'bg-teal-500/20 text-teal-400',
  };
  const cls = map[proto?.toUpperCase()] || 'bg-dark-600 text-dark-400';
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-mono font-medium ${cls}`}>
      {proto || '?'}
    </span>
  );
}

export default function NetworkLogger() {
  const [stats, setStats]     = useState(null);
  const [packets, setPackets] = useState([]);
  const [filter, setFilter]   = useState('');
  const [protoFilter, setProtoFilter] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const timerRef = useRef(null);

  const fetchStats = useCallback(async () => {
    try {
      // Try to get stats from firewall engine realtime endpoint
      const res = await fetch(`${LOGS_BASE}/stats/realtime`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch {
      // Ignore — stats are optional
    }
  }, []);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch recent verdict logs from firewall engine
      const res = await fetch(`${LOGS_BASE}/logs/verdicts`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        const text = await res.text();
        const lines = text.trim().split('\n').filter(Boolean);
        const parsed = lines.slice(-200).map((line, i) => {
          try { return { id: i, ...JSON.parse(line) }; } catch { return null; }
        }).filter(Boolean).reverse();
        setPackets(parsed);
        setError(null);
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (e) {
      // Show placeholder data so the page is still useful
      setError(`Network Logger service data unavailable — showing firewall log data when available.`);
      setPackets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    fetchStats();
  }, [fetchLogs, fetchStats]);

  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = setInterval(() => {
        fetchLogs();
        fetchStats();
      }, 5000);
    }
    return () => clearInterval(timerRef.current);
  }, [autoRefresh, fetchLogs, fetchStats]);

  const protos = ['All', 'TCP', 'UDP', 'ICMP', 'DNS', 'TLS', 'HTTP'];

  const filtered = packets.filter(p => {
    const matchProto = protoFilter === 'All' || (p.proto || p.protocol || '').toUpperCase() === protoFilter;
    const matchText  = !filter || JSON.stringify(p).toLowerCase().includes(filter.toLowerCase());
    return matchProto && matchText;
  });

  const actionColor = (action) => {
    if (!action) return 'text-dark-400';
    const a = action.toUpperCase();
    if (a === 'ALLOW' || a === 'PASS') return 'text-green-400';
    if (a === 'DROP' || a === 'BLOCK') return 'text-red-400';
    if (a === 'REDIRECT') return 'text-yellow-400';
    return 'text-dark-300';
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-900 dark:text-white flex items-center gap-3">
            <Network className="w-7 h-7 text-purple-400" />
            Network Logger
          </h1>
          <p className="text-dark-500 dark:text-dark-400 mt-1 text-sm">
            Packet capture & flow logging — 5-minute cycle, JSONL output for IDS/IPS analysis
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              autoRefresh
                ? 'bg-green-500/20 text-green-400 border-green-500/40'
                : 'bg-dark-100 dark:bg-dark-700 text-dark-500 dark:text-dark-400 border-dark-300 dark:border-dark-600'
            }`}
          >
            {autoRefresh ? '● Live (5s)' : '○ Paused'}
          </button>
          <button
            onClick={() => { fetchLogs(); fetchStats(); }}
            className="flex items-center gap-2 px-3 py-2 bg-dark-100 dark:bg-dark-700 hover:bg-dark-200 dark:hover:bg-dark-600 border border-dark-300 dark:border-dark-600 text-dark-600 dark:text-dark-300 hover:text-dark-900 dark:hover:text-dark-900 dark:text-white rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon={Activity}  label="Packets/sec"     value={stats.packets_per_sec?.toFixed(0)} color="blue" />
          <StatCard icon={Database}  label="Total Packets"   value={stats.total_packets?.toLocaleString()} color="green" />
          <StatCard icon={Filter}    label="Blocked"         value={stats.total_blocked?.toLocaleString()} color="red" />
          <StatCard icon={FileText}  label="Active Flows"    value={stats.active_flows?.toLocaleString()} color="yellow" />
        </div>
      )}

      {/* Config info */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-dark-900 dark:text-white mb-3 flex items-center gap-2">
            <FileText className="w-4 h-4 text-purple-400" />
            Log Output Files
          </h2>
          <div className="space-y-2">
            {[
              { path: 'bin/logs/network_packets_master.jsonl', desc: 'Full packet capture (5-min cycle)' },
              { path: 'bin/logs/firewall.jsonl',               desc: 'Firewall verdict log' },
              { path: 'bin/logs/ip_summary.jsonl',             desc: 'IP summary aggregates' },
              { path: 'bin/logs/ids_ips.jsonl',                desc: 'IDS/IPS alerts' },
              { path: 'bin/logs/netflow/',                     desc: 'NetFlow records directory' },
            ].map(({ path, desc }) => (
              <div key={path} className="text-xs">
                <div className="font-mono text-dark-600 dark:text-dark-300">{path}</div>
                <div className="text-dark-500">{desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-dark-900 dark:text-white mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" />
            Capture Settings
          </h2>
          <div className="space-y-2 text-sm">
            {[
              { label: 'Mode',           value: 'Promiscuous (all traffic)' },
              { label: 'Cycle',          value: '5 minutes (overwrite)' },
              { label: 'Snapshot',       value: '1600 bytes/packet' },
              { label: 'Interfaces',     value: 'All active interfaces' },
              { label: 'BPF Filter',     value: 'None (capture all ports)' },
              { label: 'Batch Size',     value: '75 packets/write' },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between">
                <span className="text-dark-500 dark:text-dark-400">{label}</span>
                <span className="text-dark-700 dark:text-dark-200 font-mono text-xs">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Log Viewer */}
      <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-200 dark:border-dark-700 flex flex-wrap items-center gap-3">
          <h2 className="text-sm font-semibold text-dark-900 dark:text-white flex items-center gap-2">
            <FileText className="w-4 h-4 text-dark-400" />
            Recent Verdict Log
            {filtered.length > 0 && (
              <span className="text-xs text-dark-500 font-normal">({filtered.length} entries)</span>
            )}
          </h2>
          {/* Proto filter */}
          <div className="flex items-center gap-1">
            {protos.map(p => (
              <button
                key={p}
                onClick={() => setProtoFilter(p)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  protoFilter === p
                    ? 'bg-primary-600 text-dark-900 dark:text-white'
                    : 'bg-dark-100 dark:bg-dark-700 text-dark-500 dark:text-dark-400 hover:text-dark-700 dark:hover:text-dark-200'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
          {/* Text filter */}
          <input
            type="text"
            placeholder="Search IPs, domains..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="ml-auto px-3 py-1 bg-dark-100 dark:bg-dark-700 border border-dark-300 dark:border-dark-600 rounded text-xs text-dark-700 dark:text-dark-200 placeholder-dark-400 dark:placeholder-dark-500 focus:outline-none focus:border-primary-500 w-44"
          />
        </div>

        {/* Table */}
        {error && (
          <div className="px-5 py-4">
            <div className="flex items-start gap-2 text-sm text-yellow-400">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          </div>
        )}

        {loading && packets.length === 0 ? (
          <div className="px-5 py-12 text-center text-dark-500 text-sm">Loading...</div>
        ) : filtered.length === 0 ? (
          <div className="px-5 py-12 text-center text-dark-500 text-sm">
            No log entries found. Make sure firewall-engine is running.
          </div>
        ) : (
          <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-dark-700/90 backdrop-blur">
                <tr>
                  {['Time', 'Src IP', 'Dst IP', 'Port', 'Proto', 'Action', 'Domain/Reason'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-dark-400 font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((p, i) => (
                  <tr key={p.id ?? i} className="border-t border-dark-200 dark:border-dark-700/50 hover:bg-dark-700/30">
                    <td className="px-4 py-2 font-mono text-dark-400 whitespace-nowrap">
                      {p.ts ? new Date(p.ts * 1000).toLocaleTimeString() : '—'}
                    </td>
                    <td className="px-4 py-2 font-mono text-dark-200">{p.src || p.src_ip || '—'}</td>
                    <td className="px-4 py-2 font-mono text-dark-200">{p.dst || p.dst_ip || '—'}</td>
                    <td className="px-4 py-2 font-mono text-dark-400">{p.dp || p.dst_port || '—'}</td>
                    <td className="px-4 py-2"><ProtoTag proto={p.proto || p.protocol} /></td>
                    <td className={`px-4 py-2 font-semibold ${actionColor(p.action)}`}>
                      {p.action || '—'}
                    </td>
                    <td className="px-4 py-2 text-dark-400 max-w-xs truncate">
                      {p.domain || p.reason || p.detector || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
