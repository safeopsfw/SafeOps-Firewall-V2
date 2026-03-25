import { useState, useEffect, useCallback, useRef, Component } from 'react';

// ─── API base (proxied through Node backend) ────────────────────────────────
const API = '/api/engine';

async function apiFetch(path, options = {}) {
  const r = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ message: r.statusText }));
    throw new Error(err.message || r.statusText);
  }
  return r.json();
}

// ─── Tiny UI primitives ─────────────────────────────────────────────────────
function Card({ children, className = '' }) {
  return (
    <div className={`bg-dark-800 rounded-xl border border-dark-700 p-5 ${className}`}>
      {children}
    </div>
  );
}

function Badge({ children, color = 'primary' }) {
  const colors = {
    primary: 'bg-primary-900/40 text-primary-400 border-primary-700',
    green:   'bg-green-900/40 text-green-400 border-green-700',
    red:     'bg-red-900/40 text-red-400 border-red-700',
    yellow:  'bg-yellow-900/40 text-yellow-400 border-yellow-700',
    gray:    'bg-dark-700 text-dark-300 border-dark-600',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors[color] || colors.primary}`}>
      {children}
    </span>
  );
}

function Alert({ type = 'info', children }) {
  const s = {
    info:    'bg-primary-900/20 border-primary-700 text-primary-300',
    error:   'bg-red-900/20 border-red-700 text-red-300',
    success: 'bg-green-900/20 border-green-700 text-green-300',
    warn:    'bg-yellow-900/20 border-yellow-700 text-yellow-300',
  }[type];
  return <div className={`border rounded-lg px-4 py-3 text-sm mb-4 ${s}`}>{children}</div>;
}

function Toggle({ checked, onChange, label }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer">
      <div
        onClick={() => onChange(!checked)}
        className={`relative w-10 h-5 rounded-full transition-colors ${checked ? 'bg-primary-600' : 'bg-dark-600'}`}
      >
        <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-5' : ''}`} />
      </div>
      {label && <span className="text-sm text-dark-300">{label}</span>}
    </label>
  );
}

function Input({ label, value, onChange, type = 'text', min, step, className = '' }) {
  return (
    <div className={`flex flex-col gap-1 ${className}`}>
      {label && <label className="text-xs text-dark-400 font-medium">{label}</label>}
      <input
        type={type}
        value={value}
        min={min}
        step={step}
        onChange={e => onChange(e.target.value)}
        className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500"
      />
    </div>
  );
}

function Btn({ children, onClick, variant = 'primary', size = 'sm', disabled = false, className = '' }) {
  const base = 'inline-flex items-center gap-1.5 rounded-lg font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed';
  const sizes = { sm: 'px-3 py-1.5 text-sm', md: 'px-4 py-2 text-sm', lg: 'px-5 py-2.5 text-base' };
  const variants = {
    primary: 'bg-primary-600 hover:bg-primary-700 text-white',
    danger:  'bg-red-600/80 hover:bg-red-700 text-white',
    ghost:   'bg-dark-700 hover:bg-dark-600 text-dark-200',
    outline: 'border border-dark-600 hover:border-primary-500 text-dark-300 hover:text-white',
  };
  return (
    <button onClick={onClick} disabled={disabled} className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}>
      {children}
    </button>
  );
}

function StatCard({ label, value, sub, color = 'primary' }) {
  const colors = { primary: 'text-primary-400', green: 'text-green-400', red: 'text-red-400', yellow: 'text-yellow-400' };
  return (
    <Card>
      <div className="text-xs text-dark-400 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${colors[color]}`}>{value}</div>
      {sub && <div className="text-xs text-dark-500 mt-1">{sub}</div>}
    </Card>
  );
}

function SectionHeader({ title, subtitle, action }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <h3 className="text-base font-semibold text-white">{title}</h3>
        {subtitle && <p className="text-xs text-dark-400 mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

function LoadingSpinner() {
  return <div className="flex justify-center py-10"><div className="w-8 h-8 border-4 border-primary-500 border-t-transparent rounded-full animate-spin" /></div>;
}

// ─── TAB DEFINITIONS ────────────────────────────────────────────────────────
const TABS = [
  { id: 'overview',    label: 'Overview',       icon: '📊' },
  { id: 'domains',     label: 'Domain Rules',   icon: '🌐' },
  { id: 'ips',         label: 'IP Rules',       icon: '🔒' },
  { id: 'ratelimit',   label: 'Rate Limiting',  icon: '⚡' },
  { id: 'ddos',        label: 'DDoS',           icon: '🛡️' },
  { id: 'bruteforce',  label: 'Brute Force',    icon: '🔑' },
  { id: 'portscan',    label: 'Port Scan',      icon: '🔍' },
  { id: 'geoip',       label: 'GeoIP',          icon: '🌍' },
  { id: 'customrules', label: 'Custom Rules',   icon: '📋' },
  { id: 'verdicts',    label: 'Verdict Logs',   icon: '📝' },
  { id: 'alerts',      label: 'Alerts',         icon: '🚨' },
];

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Overview
// ═══════════════════════════════════════════════════════════════════════════
function OverviewTab() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const data = await apiFetch('/dashboard/stats');
      setStats(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);

  if (loading) return <LoadingSpinner />;
  if (error) return <Alert type="error">Failed to load engine stats: {error}. Is the Firewall Engine running?</Alert>;
  if (!stats) return null;

  const s = stats;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Packets" value={s.total_packets?.toLocaleString() ?? '—'} sub="processed" color="primary" />
        <StatCard label="Blocked" value={s.blocked_packets?.toLocaleString() ?? '—'} sub="packets dropped" color="red" />
        <StatCard label="Domain Blocks" value={s.domain_blocks?.toLocaleString() ?? '—'} sub="DNS/SNI/HTTP" color="yellow" />
        <StatCard label="Threat Intel Hits" value={s.threat_intel_hits?.toLocaleString() ?? '—'} sub="malicious matches" color="red" />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Auto-Blocked Domains" value={s.auto_blocked_domains ?? '—'} sub="threshold exceeded" color="red" />
        <StatCard label="Active Bans" value={s.active_bans?.toLocaleString() ?? '—'} sub="IP bans" color="yellow" />
        <StatCard label="DDoS Events" value={s.ddos_events?.toLocaleString() ?? '—'} sub="detected" color="red" />
        <StatCard label="Uptime" value={s.uptime ?? '—'} sub="engine running" color="green" />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <h4 className="text-sm font-semibold text-white mb-3">Engine Status</h4>
          <div className="space-y-2 text-sm">
            {[
              ['Version', s.version],
              ['Workers', s.workers],
              ['Verdict Cache TTL', `${s.verdict_cache_ttl_seconds ?? '—'}s`],
              ['SafeOps Connection', s.safeops_connected ? '✅ Connected' : '❌ Disconnected'],
              ['Threat Intel DB', s.threat_intel_available ? '✅ Available' : '❌ Unavailable'],
              ['WFP Engine', s.wfp_enabled ? '✅ Active' : '—'],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between items-center py-1 border-b border-dark-700">
                <span className="text-dark-400">{k}</span>
                <span className="text-white font-medium">{v ?? '—'}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card>
          <h4 className="text-sm font-semibold text-white mb-3">Domain Filter</h4>
          <div className="space-y-2 text-sm">
            {[
              ['Config Domains', s.domain_filter?.config_domains],
              ['Active Categories', s.domain_filter?.categories_active],
              ['CDN Providers', s.domain_filter?.cdn_providers],
              ['Threat Intel', s.domain_filter?.threat_intel_available ? '✅' : '—'],
              ['Auto-Block Threshold', s.domain_filter?.visit_threshold > 0 ? `${s.domain_filter?.visit_threshold} visits` : 'Disabled'],
              ['Auto-Blocked Count', s.domain_filter?.auto_blocked_count],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between items-center py-1 border-b border-dark-700">
                <span className="text-dark-400">{k}</span>
                <span className="text-white font-medium">{v ?? '—'}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Domain Rules
// ═══════════════════════════════════════════════════════════════════════════
const CATEGORIES = ['social_media','streaming','gaming','ads','trackers','adult','gambling','vpn_proxy'];

function DomainRulesTab() {
  const [domains, setDomains] = useState([]);
  const [newDomain, setNewDomain] = useState('');
  const [categories, setCategories] = useState({});
  const [blocklist, setBlocklist] = useState(null);
  const [autoBlocked, setAutoBlocked] = useState([]);
  const [maliciousVisits, setMaliciousVisits] = useState([]);
  const [threshold, setThreshold] = useState(10);
  const [thresholdInput, setThresholdInput] = useState('10');
  const [activeSubTab, setActiveSubTab] = useState('manual');
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const [search, setSearch] = useState('');

  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try {
      const [d, c, b, ab, mv, vt] = await Promise.allSettled([
        apiFetch('/rules/domains'),
        apiFetch('/rules/categories'),
        apiFetch('/rules/blocklist'),
        apiFetch('/domains/auto-blocked'),
        apiFetch('/domains/malicious-visits'),
        apiFetch('/domains/visit-threshold'),
      ]);
      if (d.status === 'fulfilled') setDomains(d.value.domains || []);
      if (c.status === 'fulfilled') setCategories(c.value.categories || {});
      if (b.status === 'fulfilled') setBlocklist(b.value);
      if (ab.status === 'fulfilled') setAutoBlocked(ab.value.domains || []);
      if (mv.status === 'fulfilled') setMaliciousVisits(mv.value.domains || []);
      if (vt.status === 'fulfilled') { setThreshold(vt.value.threshold); setThresholdInput(String(vt.value.threshold)); }
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const addDomain = async () => {
    if (!newDomain.trim()) return;
    try {
      await apiFetch('/rules/domains', { method: 'POST', body: JSON.stringify({ domain: newDomain.trim() }) });
      setNewDomain('');
      flash('success', `Domain "${newDomain.trim()}" added`);
      load();
    } catch (e) { flash('error', e.message); }
  };

  const removeDomain = async (d) => {
    try {
      await apiFetch(`/rules/domains/${encodeURIComponent(d)}`, { method: 'DELETE' });
      flash('success', `Domain "${d}" removed`);
      load();
    } catch (e) { flash('error', e.message); }
  };

  const saveCategories = async () => {
    try {
      await apiFetch('/rules/categories', { method: 'PUT', body: JSON.stringify({ categories }) });
      flash('success', 'Category settings saved');
      load();
    } catch (e) { flash('error', e.message); }
  };

  const removeAutoBlock = async (d) => {
    try {
      await apiFetch(`/domains/auto-blocked/${encodeURIComponent(d)}`, { method: 'DELETE' });
      flash('success', `Auto-block removed for "${d}"`);
      load();
    } catch (e) { flash('error', e.message); }
  };

  const saveThreshold = async () => {
    const n = parseInt(thresholdInput, 10);
    if (isNaN(n) || n < 0) { flash('error', 'Threshold must be a number >= 0'); return; }
    try {
      await apiFetch('/domains/visit-threshold', { method: 'PUT', body: JSON.stringify({ threshold: n }) });
      setThreshold(n);
      flash('success', n === 0 ? 'Auto-block disabled (alert-only mode)' : `Threshold set to ${n} visits`);
    } catch (e) { flash('error', e.message); }
  };

  const filtered = domains.filter(d => d.toLowerCase().includes(search.toLowerCase()));

  const SUB_TABS = [
    { id: 'manual', label: `Manual (${domains.length})` },
    { id: 'categories', label: 'Categories' },
    { id: 'autoblock', label: `Auto-Blocked (${autoBlocked.length})` },
    { id: 'malicious', label: `Malicious Visits (${maliciousVisits.length})` },
    { id: 'settings', label: 'Settings' },
  ];

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}

      <div className="flex gap-2 border-b border-dark-700 pb-0">
        {SUB_TABS.map(t => (
          <button key={t.id} onClick={() => setActiveSubTab(t.id)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeSubTab === t.id ? 'border-primary-500 text-primary-400' : 'border-transparent text-dark-400 hover:text-white'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Manual Domains */}
      {activeSubTab === 'manual' && (
        <div>
          <SectionHeader title="Manual Domain Blocklist" subtitle="Domains blocked regardless of threat intel score" />
          <div className="flex gap-2 mb-4">
            <input value={newDomain} onChange={e => setNewDomain(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addDomain()}
              placeholder="evil.com  (wildcards auto-added)"
              className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500" />
            <Btn onClick={addDomain} size="md">+ Add Domain</Btn>
          </div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search domains…"
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500 mb-3" />
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {filtered.length === 0 ? <p className="text-dark-500 text-sm py-4 text-center">No domains found</p> :
              filtered.map(d => (
                <div key={d} className="flex items-center justify-between px-3 py-2 bg-dark-900 rounded-lg">
                  <span className="text-sm text-dark-200 font-mono">{d}</span>
                  <Btn variant="danger" onClick={() => removeDomain(d)}>Remove</Btn>
                </div>
              ))
            }
          </div>
        </div>
      )}

      {/* Categories */}
      {activeSubTab === 'categories' && (
        <div>
          <SectionHeader title="Category Blocking" subtitle="Block entire categories of domains" action={<Btn onClick={saveCategories}>Save Changes</Btn>} />
          <div className="grid grid-cols-2 gap-3">
            {CATEGORIES.map(cat => (
              <Card key={cat}>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-white capitalize">{cat.replace('_', ' ')}</div>
                    <div className="text-xs text-dark-500">Block all {cat.replace('_', ' ')} domains</div>
                  </div>
                  <Toggle
                    checked={!!categories[cat]}
                    onChange={v => setCategories(prev => ({ ...prev, [cat]: v }))}
                  />
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Auto-Blocked */}
      {activeSubTab === 'autoblock' && (
        <div>
          <SectionHeader title="Auto-Blocked Domains"
            subtitle={`Domains automatically blocked after reaching the visit threshold (currently: ${threshold === 0 ? 'disabled' : threshold + ' visits'})`} />
          {autoBlocked.length === 0 ? (
            <Card><p className="text-dark-500 text-sm text-center py-4">No auto-blocked domains yet</p></Card>
          ) : (
            <div className="space-y-2">
              {autoBlocked.map(entry => (
                <Card key={entry.domain}>
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-mono text-sm text-white">{entry.domain}</div>
                      <div className="text-xs text-dark-400 mt-0.5">
                        {entry.visit_count} visits · Score {entry.threat_score} · Blocked {new Date(entry.blocked_at).toLocaleString()} · via {entry.source}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Badge color="red">AUTO-BLOCKED</Badge>
                      <Btn variant="ghost" onClick={() => removeAutoBlock(entry.domain)}>Unblock</Btn>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Malicious Visits */}
      {activeSubTab === 'malicious' && (
        <div>
          <SectionHeader title="Malicious Domain Visit Tracker"
            subtitle="Threat-intel-flagged domains and their visit counts. Auto-blocks at threshold." />
          {maliciousVisits.length === 0 ? (
            <Card><p className="text-dark-500 text-sm text-center py-4">No malicious domain visits tracked yet</p></Card>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-dark-400 border-b border-dark-700">
                    <th className="pb-2 pr-4">Domain</th>
                    <th className="pb-2 pr-4">Visits</th>
                    <th className="pb-2 pr-4">Threat Score</th>
                    <th className="pb-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {maliciousVisits.map(entry => (
                    <tr key={entry.domain} className="border-b border-dark-800 hover:bg-dark-800/50">
                      <td className="py-2 pr-4 font-mono text-dark-200">{entry.domain}</td>
                      <td className="py-2 pr-4">
                        <span className={`font-bold ${entry.visit_count >= threshold && threshold > 0 ? 'text-red-400' : 'text-yellow-400'}`}>
                          {entry.visit_count}
                        </span>
                        {threshold > 0 && <span className="text-dark-500"> / {threshold}</span>}
                      </td>
                      <td className="py-2 pr-4">
                        {entry.threat_score ? <Badge color={entry.threat_score >= 80 ? 'red' : 'yellow'}>{entry.threat_score}</Badge> : '—'}
                      </td>
                      <td className="py-2">
                        {entry.auto_blocked ? <Badge color="red">Blocked</Badge> : <Badge color="yellow">Alert Only</Badge>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Settings */}
      {activeSubTab === 'settings' && (
        <div className="space-y-4">
          <Card>
            <h4 className="text-sm font-semibold text-white mb-3">Auto-Block Threshold</h4>
            <p className="text-xs text-dark-400 mb-3">
              Threat-intel-flagged domains are alerted for the first N-1 visits.
              On the Nth visit they are automatically promoted to the blocked list (in-memory only; resets on restart).
              Set to 0 to disable auto-blocking entirely.
            </p>
            <div className="flex items-end gap-3">
              <Input
                label="Visit Threshold (0 = disabled)"
                value={thresholdInput}
                onChange={setThresholdInput}
                type="number"
                min="0"
                className="w-48"
              />
              <Btn onClick={saveThreshold} size="md">Apply</Btn>
            </div>
            {threshold === 0 && <Alert type="warn" className="mt-3">Auto-block is disabled — threat intel domains will only generate alerts.</Alert>}
          </Card>

          {blocklist && (
            <Card>
              <h4 className="text-sm font-semibold text-white mb-3">Threat Intel Settings</h4>
              <div className="space-y-2 text-sm">
                {[
                  ['Enabled', blocklist.threat_intel?.enabled ? '✅ Yes' : '❌ No'],
                  ['IP Block Threshold', blocklist.threat_intel?.ip_block_threshold],
                  ['Domain Block Threshold', blocklist.threat_intel?.domain_block_threshold],
                  ['Block Anonymizers', blocklist.threat_intel?.block_anonymizers ? '✅ Yes' : '❌ No'],
                  ['Anonymizer Threshold', blocklist.threat_intel?.anonymizer_block_threshold],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between py-1 border-b border-dark-700">
                    <span className="text-dark-400">{k}</span>
                    <span className="text-white">{v ?? '—'}</span>
                  </div>
                ))}
              </div>
              <p className="text-xs text-dark-500 mt-2">Edit via blocklist.toml or Blocklist Policy section.</p>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: IP Rules
// ═══════════════════════════════════════════════════════════════════════════
function IPRulesTab() {
  const [ips, setIps] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [bans, setBans] = useState([]);
  const [newIP, setNewIP] = useState('');
  const [newWL, setNewWL] = useState('');
  const [banIP, setBanIP] = useState('');
  const [banDur, setBanDur] = useState('30');
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const [activeSubTab, setActiveSubTab] = useState('blocked');
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    const [i, w, b] = await Promise.allSettled([
      apiFetch('/rules/ips'),
      apiFetch('/rules/ips/whitelist'),
      apiFetch('/security/bans'),
    ]);
    if (i.status === 'fulfilled') setIps(i.value.ips || []);
    if (w.status === 'fulfilled') setWhitelist(w.value.ips || []);
    if (b.status === 'fulfilled') setBans(b.value.bans || []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const addIP = async () => {
    if (!newIP.trim()) return;
    try {
      await apiFetch('/rules/ips', { method: 'POST', body: JSON.stringify({ ip: newIP.trim() }) });
      setNewIP(''); flash('success', 'IP added to blocklist'); load();
    } catch (e) { flash('error', e.message); }
  };

  const removeIP = async (ip) => {
    try {
      await apiFetch(`/rules/ips/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      flash('success', 'IP removed'); load();
    } catch (e) { flash('error', e.message); }
  };

  const addWhitelist = async () => {
    if (!newWL.trim()) return;
    try {
      await apiFetch('/rules/ips/whitelist', { method: 'POST', body: JSON.stringify({ ip: newWL.trim() }) });
      setNewWL(''); flash('success', 'IP whitelisted'); load();
    } catch (e) { flash('error', e.message); }
  };

  const createBan = async () => {
    if (!banIP.trim()) return;
    try {
      await apiFetch('/security/bans', { method: 'POST', body: JSON.stringify({ ip: banIP.trim(), duration_minutes: parseInt(banDur) }) });
      setBanIP(''); flash('success', `Banned ${banIP} for ${banDur}m`); load();
    } catch (e) { flash('error', e.message); }
  };

  const deleteBan = async (ip) => {
    try {
      await apiFetch(`/security/bans/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      flash('success', 'Ban removed'); load();
    } catch (e) { flash('error', e.message); }
  };

  const SUB_TABS = [
    { id: 'blocked', label: `Blocked IPs (${ips.length})` },
    { id: 'whitelist', label: `Whitelisted (${whitelist.length})` },
    { id: 'bans', label: `Active Bans (${bans.length})` },
  ];

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <div className="flex gap-2 border-b border-dark-700 pb-0">
        {SUB_TABS.map(t => (
          <button key={t.id} onClick={() => setActiveSubTab(t.id)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${activeSubTab === t.id ? 'border-primary-500 text-primary-400' : 'border-transparent text-dark-400 hover:text-white'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {activeSubTab === 'blocked' && (
        <div>
          <SectionHeader title="Blocked IPs & CIDRs" subtitle="Manually blocked IP addresses and CIDR ranges" />
          <div className="flex gap-2 mb-4">
            <input value={newIP} onChange={e => setNewIP(e.target.value)} onKeyDown={e => e.key === 'Enter' && addIP()}
              placeholder="1.2.3.4 or 10.0.0.0/8"
              className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500" />
            <Btn onClick={addIP} size="md">+ Add</Btn>
          </div>
          <div className="space-y-1 max-h-80 overflow-y-auto">
            {ips.length === 0 ? <p className="text-dark-500 text-sm text-center py-4">No manually blocked IPs</p> :
              ips.map(ip => (
                <div key={ip} className="flex items-center justify-between px-3 py-2 bg-dark-900 rounded-lg">
                  <span className="font-mono text-sm text-dark-200">{ip}</span>
                  <Btn variant="danger" onClick={() => removeIP(ip)}>Remove</Btn>
                </div>
              ))
            }
          </div>
        </div>
      )}

      {activeSubTab === 'whitelist' && (
        <div>
          <SectionHeader title="IP Whitelist" subtitle="IPs that bypass ALL blocking checks (emergency override)" />
          <div className="flex gap-2 mb-4">
            <input value={newWL} onChange={e => setNewWL(e.target.value)} onKeyDown={e => e.key === 'Enter' && addWhitelist()}
              placeholder="1.2.3.4 or 192.168.0.0/24"
              className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500" />
            <Btn onClick={addWhitelist} size="md">+ Whitelist</Btn>
          </div>
          <div className="space-y-1 max-h-80 overflow-y-auto">
            {whitelist.length === 0 ? <p className="text-dark-500 text-sm text-center py-4">No whitelisted IPs</p> :
              whitelist.map(ip => (
                <div key={ip} className="flex items-center justify-between px-3 py-2 bg-dark-900 rounded-lg">
                  <span className="font-mono text-sm text-dark-200">{ip}</span>
                  <Badge color="green">Whitelisted</Badge>
                </div>
              ))
            }
          </div>
        </div>
      )}

      {activeSubTab === 'bans' && (
        <div>
          <SectionHeader title="Active IP Bans" subtitle="Escalating bans: 30m → 2h → 8h → 32h → permanent" />
          <div className="flex gap-2 mb-4">
            <input value={banIP} onChange={e => setBanIP(e.target.value)} placeholder="1.2.3.4"
              className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500" />
            <select value={banDur} onChange={e => setBanDur(e.target.value)}
              className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white">
              {[['30', '30 min'],['120', '2 hr'],['480', '8 hr'],['1440', '24 hr'],['43200', '30 days']].map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
            <Btn variant="danger" onClick={createBan}>Ban IP</Btn>
          </div>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {bans.length === 0 ? <p className="text-dark-500 text-sm text-center py-4">No active bans</p> :
              bans.map(ban => (
                <div key={ban.ip} className="flex items-center justify-between px-3 py-2 bg-dark-900 rounded-lg">
                  <div>
                    <span className="font-mono text-sm text-white">{ban.ip}</span>
                    <div className="text-xs text-dark-500">{ban.reason} · expires {ban.expires_at ? new Date(ban.expires_at).toLocaleString() : 'permanent'}</div>
                  </div>
                  <Btn variant="ghost" onClick={() => deleteBan(ban.ip)}>Unban</Btn>
                </div>
              ))
            }
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════
function RateLimitTab() {
  const [cfg, setCfg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try {
      const data = await apiFetch('/rules/detection');
      setCfg(data.config || data);
    } catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    try {
      await apiFetch('/rules/detection', { method: 'PUT', body: JSON.stringify(cfg) });
      flash('success', 'Rate limit settings saved');
    } catch (e) { flash('error', e.message); }
  };

  const update = (path, val) => {
    setCfg(prev => {
      const next = JSON.parse(JSON.stringify(prev));
      const keys = path.split('.');
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) obj = obj[keys[i]];
      obj[keys[keys.length - 1]] = val;
      return next;
    });
  };

  if (loading) return <LoadingSpinner />;
  if (!cfg) return <Alert type="error">Failed to load detection config</Alert>;

  const rl = cfg.rate_limit || {};

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <Card>
        <SectionHeader title="Rate Limiting" subtitle="Token bucket per-IP rate limiting" action={<Btn onClick={save}>Save</Btn>} />
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Toggle checked={!!rl.enabled} onChange={v => update('rate_limit.enabled', v)} label="Enable rate limiting" />
          </div>
          <Input label="Default Rate (packets/sec per IP)" type="number" min="1"
            value={rl.default_rate ?? 1000} onChange={v => update('rate_limit.default_rate', parseInt(v))} />
          <Input label="Burst Size (max burst above rate)" type="number" min="1"
            value={rl.burst_size ?? 2000} onChange={v => update('rate_limit.burst_size', parseInt(v))} />
          <Input label="Global Rate (total packets/sec)" type="number" min="1"
            value={rl.global_rate ?? 100000} onChange={v => update('rate_limit.global_rate', parseInt(v))} />
          <Input label="Cleanup Interval (seconds)" type="number" min="10"
            value={rl.cleanup_interval_seconds ?? 60} onChange={v => update('rate_limit.cleanup_interval_seconds', parseInt(v))} />
        </div>
      </Card>
      <Alert type="info">
        Token bucket algorithm: each IP gets <strong>{rl.default_rate} pps</strong> sustained with burst up to <strong>{rl.burst_size} pps</strong>.
        IPs exceeding these limits are throttled. Global cap: <strong>{(rl.global_rate || 100000).toLocaleString()} pps</strong>.
      </Alert>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: DDoS Protection
// ═══════════════════════════════════════════════════════════════════════════
function DDoSTab() {
  const [cfg, setCfg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try { const data = await apiFetch('/rules/detection'); setCfg(data.config || data); } catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    try { await apiFetch('/rules/detection', { method: 'PUT', body: JSON.stringify(cfg) }); flash('success', 'DDoS settings saved'); }
    catch (e) { flash('error', e.message); }
  };

  const update = (path, val) => {
    setCfg(prev => {
      const next = JSON.parse(JSON.stringify(prev));
      const keys = path.split('.');
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) obj = obj[keys[i]];
      obj[keys[keys.length - 1]] = val;
      return next;
    });
  };

  if (loading) return <LoadingSpinner />;
  if (!cfg) return <Alert type="error">Failed to load config</Alert>;

  const d = cfg.ddos || {};

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <Card>
        <SectionHeader title="DDoS Detection" subtitle="SYN/UDP/ICMP flood detection with escalating bans" action={<Btn onClick={save}>Save</Btn>} />
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Toggle checked={!!d.enabled} onChange={v => update('ddos.enabled', v)} label="Enable DDoS detection" />
          </div>
          <Input label="SYN Rate Threshold (pps)" type="number" value={d.syn_rate_threshold ?? 1000} onChange={v => update('ddos.syn_rate_threshold', parseInt(v))} />
          <Input label="UDP Rate Threshold (pps)" type="number" value={d.udp_rate_threshold ?? 5000} onChange={v => update('ddos.udp_rate_threshold', parseInt(v))} />
          <Input label="ICMP Rate Threshold (pps)" type="number" value={d.icmp_rate_threshold ?? 100} onChange={v => update('ddos.icmp_rate_threshold', parseInt(v))} />
          <Input label="Connection Ratio Threshold" type="number" step="0.001" value={d.connection_ratio_threshold ?? 0.01} onChange={v => update('ddos.connection_ratio_threshold', parseFloat(v))} />
          <Input label="Window (seconds)" type="number" value={d.window_seconds ?? 10} onChange={v => update('ddos.window_seconds', parseInt(v))} />
          <Input label="Initial Ban Duration (minutes)" type="number" value={d.ban_duration_minutes ?? 30} onChange={v => update('ddos.ban_duration_minutes', parseInt(v))} />
          <Input label="Max Ban Duration (hours)" type="number" value={d.max_ban_duration_hours ?? 720} onChange={v => update('ddos.max_ban_duration_hours', parseInt(v))} />
          <Input label="Escalation Multiplier" type="number" value={d.escalation_multiplier ?? 4} onChange={v => update('ddos.escalation_multiplier', parseInt(v))} />
        </div>
      </Card>
      <Alert type="info">
        Ban escalation: {d.ban_duration_minutes ?? 30}m → {(d.ban_duration_minutes ?? 30) * (d.escalation_multiplier ?? 4)}m → … → max {d.max_ban_duration_hours ?? 720}h.
        Connection ratio &lt; {d.connection_ratio_threshold ?? 0.01} (SYN to ESTABLISHED) indicates a SYN flood.
      </Alert>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Brute Force
// ═══════════════════════════════════════════════════════════════════════════
function BruteForceTab() {
  const [cfg, setCfg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try { const data = await apiFetch('/rules/detection'); setCfg(data.config || data); } catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    try { await apiFetch('/rules/detection', { method: 'PUT', body: JSON.stringify(cfg) }); flash('success', 'Brute force settings saved'); }
    catch (e) { flash('error', e.message); }
  };

  const update = (path, val) => {
    setCfg(prev => {
      const next = JSON.parse(JSON.stringify(prev));
      const keys = path.split('.');
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) obj = obj[keys[i]];
      obj[keys[keys.length - 1]] = val;
      return next;
    });
  };

  if (loading) return <LoadingSpinner />;
  if (!cfg) return <Alert type="error">Failed to load config</Alert>;

  const bf = cfg.brute_force || {};
  const services = bf.services || {};

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <Card>
        <SectionHeader title="Brute Force Detection" subtitle="Per-service failure counting and ban triggers" action={<Btn onClick={save}>Save</Btn>} />
        <div className="mb-4">
          <Toggle checked={!!bf.enabled} onChange={v => update('brute_force.enabled', v)} label="Enable brute force detection" />
        </div>
        <div className="mb-4">
          <Input label="Default Window (seconds)" type="number" value={bf.window_seconds ?? 120} onChange={v => update('brute_force.window_seconds', parseInt(v))} className="w-48" />
        </div>
        <h4 className="text-sm font-medium text-dark-300 mb-3">Per-Service Thresholds</h4>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-dark-400 border-b border-dark-700">
                <th className="pb-2 pr-4">Service</th>
                <th className="pb-2 pr-4">Port</th>
                <th className="pb-2 pr-4">Max Failures</th>
                <th className="pb-2">Window (sec)</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(services).map(([svc, conf]) => (
                <tr key={svc} className="border-b border-dark-800">
                  <td className="py-2 pr-4 font-medium text-white uppercase text-xs">{svc}</td>
                  <td className="py-2 pr-4">
                    <input type="number" value={conf.port ?? ''} onChange={e => update(`brute_force.services.${svc}.port`, parseInt(e.target.value))}
                      className="w-20 bg-dark-900 border border-dark-600 rounded px-2 py-1 text-xs text-white" />
                  </td>
                  <td className="py-2 pr-4">
                    <input type="number" value={conf.max_failures ?? ''} onChange={e => update(`brute_force.services.${svc}.max_failures`, parseInt(e.target.value))}
                      className="w-20 bg-dark-900 border border-dark-600 rounded px-2 py-1 text-xs text-white" />
                  </td>
                  <td className="py-2">
                    <input type="number" value={conf.window_seconds ?? ''} onChange={e => update(`brute_force.services.${svc}.window_seconds`, parseInt(e.target.value))}
                      className="w-20 bg-dark-900 border border-dark-600 rounded px-2 py-1 text-xs text-white" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Port Scan
// ═══════════════════════════════════════════════════════════════════════════
function PortScanTab() {
  const [cfg, setCfg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try { const data = await apiFetch('/rules/detection'); setCfg(data.config || data); } catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    try { await apiFetch('/rules/detection', { method: 'PUT', body: JSON.stringify(cfg) }); flash('success', 'Port scan settings saved'); }
    catch (e) { flash('error', e.message); }
  };

  const update = (path, val) => {
    setCfg(prev => {
      const next = JSON.parse(JSON.stringify(prev));
      const keys = path.split('.');
      let obj = next;
      for (let i = 0; i < keys.length - 1; i++) obj = obj[keys[i]];
      obj[keys[keys.length - 1]] = val;
      return next;
    });
  };

  if (loading) return <LoadingSpinner />;
  if (!cfg) return <Alert type="error">Failed to load config</Alert>;

  const ps = cfg.port_scan || {};
  const an = cfg.anomaly || {};

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <Card>
        <SectionHeader title="Port Scan Detection" subtitle="Detects sequential and random port scanning" action={<Btn onClick={save}>Save</Btn>} />
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <Toggle checked={!!ps.enabled} onChange={v => update('port_scan.enabled', v)} label="Enable port scan detection" />
          </div>
          <Input label="Port Threshold (unique ports/window)" type="number" value={ps.port_threshold ?? 100} onChange={v => update('port_scan.port_threshold', parseInt(v))} />
          <Input label="Sequential Threshold" type="number" value={ps.sequential_threshold ?? 20} onChange={v => update('port_scan.sequential_threshold', parseInt(v))} />
          <Input label="Window (seconds)" type="number" value={ps.window_seconds ?? 10} onChange={v => update('port_scan.window_seconds', parseInt(v))} />
          <Input label="Ban Duration (minutes)" type="number" value={ps.ban_duration_minutes ?? 15} onChange={v => update('port_scan.ban_duration_minutes', parseInt(v))} />
        </div>
      </Card>
      <Card>
        <h4 className="text-sm font-semibold text-white mb-3">Anomaly Detection</h4>
        <div className="grid grid-cols-2 gap-3">
          {[
            ['Protocol Violations (SYN+FIN, Xmas, Null)', 'anomaly.enable_protocol_violations', an.enable_protocol_violations],
            ['Packet Size Anomalies (zero-byte, oversized)', 'anomaly.enable_packet_size', an.enable_packet_size],
            ['Beaconing (C2 callback detection)', 'anomaly.enable_beaconing', an.enable_beaconing],
          ].map(([label, path, val]) => (
            <Card key={path} className="col-span-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-dark-300">{label}</span>
                <Toggle checked={!!val} onChange={v => update(path, v)} />
              </div>
            </Card>
          ))}
        </div>
        <div className="mt-3">
          <Input label="Oversized Packet Threshold (bytes)" type="number"
            value={an.oversized_packet_bytes ?? 65535} onChange={v => update('anomaly.oversized_packet_bytes', parseInt(v))} className="w-48" />
        </div>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: GeoIP
// ═══════════════════════════════════════════════════════════════════════════
function GeoIPTab() {
  const [cfg, setCfg] = useState(null);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const [newCountry, setNewCountry] = useState('');
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try {
      const resp = await apiFetch('/rules/geoip');
      // API may return {config:{...}, stats:{...}} or flat config
      setCfg(resp.config || resp);
    } catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    try { await apiFetch('/rules/geoip', { method: 'PUT', body: JSON.stringify(cfg) }); flash('success', 'GeoIP settings saved'); }
    catch (e) { flash('error', e.message); }
  };

  const addCountry = () => {
    const cc = newCountry.trim().toUpperCase();
    if (!cc || cc.length !== 2) { flash('error', 'Use ISO 3166-1 alpha-2 code (e.g. CN, RU)'); return; }
    setCfg(prev => ({ ...prev, extra_blocked_countries: [...(prev.extra_blocked_countries || []), cc] }));
    setNewCountry('');
  };

  const removeCountry = (cc) => {
    setCfg(prev => ({ ...prev, extra_blocked_countries: (prev.extra_blocked_countries || []).filter(c => c !== cc) }));
  };

  if (loading) return <LoadingSpinner />;
  if (!cfg) return <Alert type="error">Failed to load GeoIP config</Alert>;

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <Card>
        <SectionHeader title="GeoIP Blocking" subtitle="Block traffic from specific countries/ASNs" action={<Btn onClick={save}>Save</Btn>} />
        <div className="mb-4">
          <Toggle checked={!!cfg.enabled} onChange={v => setCfg(p => ({ ...p, enabled: v }))} label="Enable GeoIP blocking" />
        </div>
        <div className="mb-4">
          <label className="text-xs text-dark-400 block mb-1">Blocking Mode</label>
          <select value={cfg.mode || 'deny'} onChange={e => setCfg(p => ({ ...p, mode: e.target.value }))}
            className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white">
            <option value="deny">Deny Listed Countries</option>
            <option value="allow">Allow Listed Countries Only</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-dark-400 block mb-2">Blocked Countries (ISO 3166-1 alpha-2)</label>
          <div className="flex gap-2 mb-3">
            <input value={newCountry} onChange={e => setNewCountry(e.target.value)} onKeyDown={e => e.key === 'Enter' && addCountry()}
              placeholder="CN" maxLength={2}
              className="w-20 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white text-center uppercase focus:outline-none focus:border-primary-500" />
            <Btn onClick={addCountry}>+ Add</Btn>
          </div>
          <div className="flex flex-wrap gap-2">
            {(cfg.extra_blocked_countries || []).map(cc => (
              <div key={cc} className="flex items-center gap-1 bg-dark-900 border border-dark-700 rounded px-2 py-1">
                <span className="text-sm text-white">{cc}</span>
                <button onClick={() => removeCountry(cc)} className="text-dark-500 hover:text-red-400 ml-1">×</button>
              </div>
            ))}
            {(cfg.extra_blocked_countries || []).length === 0 && (
              <span className="text-dark-500 text-sm">No extra countries blocked (primary config in geoip.toml)</span>
            )}
          </div>
        </div>
      </Card>
      <Alert type="info">Primary country/ASN deny list is configured in <code>geoip.toml</code>. These are additional quick-toggle overrides.</Alert>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Custom Rules
// ═══════════════════════════════════════════════════════════════════════════
function CustomRulesTab() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try { const data = await apiFetch('/rules/custom'); setRules(data.rules || []); }
    catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggle = async (name, enabled) => {
    try {
      await apiFetch(`/rules/custom/${encodeURIComponent(name)}/toggle`, { method: 'PUT', body: JSON.stringify({ enabled }) });
      flash('success', `Rule "${name}" ${enabled ? 'enabled' : 'disabled'}`);
      load();
    } catch (e) { flash('error', e.message); }
  };

  const severityColor = (s) => ({ LOW: 'gray', MEDIUM: 'yellow', HIGH: 'red', CRITICAL: 'red' }[s] || 'gray');
  const actionColor = (a) => ({ ALERT: 'yellow', LOG: 'gray', DROP: 'red', BAN: 'red' }[a] || 'gray');

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <SectionHeader title="Custom Detection Rules" subtitle="TOML-driven rules from rules.toml (hot-reloadable)" />
      <Alert type="info">Rules are defined in <code>bin/firewall-engine/configs/rules.toml</code>. Toggle enabled/disabled here. Edit the file for full control.</Alert>
      {rules.length === 0 ? <Card><p className="text-dark-500 text-sm text-center py-4">No custom rules loaded</p></Card> :
        rules.map(rule => (
          <Card key={rule.name}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-semibold text-white">{rule.name}</span>
                  <Badge color={severityColor(rule.severity)}>{rule.severity}</Badge>
                  <Badge color={actionColor(rule.action)}>{rule.action}</Badge>
                  {rule.threshold_count > 0 && <Badge color="primary">threshold:{rule.threshold_count}</Badge>}
                </div>
                {rule.description && <p className="text-xs text-dark-400">{rule.description}</p>}
                <div className="text-xs text-dark-500 mt-1 font-mono">
                  {rule.dst_port ? `port:${rule.dst_port} ` : ''}{rule.protocol ? `proto:${rule.protocol} ` : ''}{rule.domain ? `domain:${rule.domain} ` : ''}
                  {rule.hits > 0 ? <span className="text-primary-400">{rule.hits} hits</span> : ''}
                </div>
              </div>
              <Toggle checked={!!rule.enabled} onChange={v => toggle(rule.name, v)} />
            </div>
          </Card>
        ))
      }
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Verdict Logs
// ═══════════════════════════════════════════════════════════════════════════
function VerdictLogsTab() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [msg, setMsg] = useState(null);

  const load = useCallback(async () => {
    try {
      const resp = await fetch(`${API}/logs/verdicts?limit=200`);
      const text = await resp.text();
      const lines = text.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      setLogs(lines.reverse());
    } catch (e) { setMsg({ type: 'error', text: e.message }); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = logs.filter(l => {
    if (actionFilter && l.action !== actionFilter) return false;
    if (filter) {
      const q = filter.toLowerCase();
      return (l.src || '').includes(q) || (l.dst || '').includes(q) || (l.domain || '').includes(q) || (l.reason || '').includes(q);
    }
    return true;
  });

  const actionBadge = (a) => ({ DROP: 'red', BLOCK: 'red', REDIRECT: 'yellow', ALLOW: 'green' }[a] || 'gray');

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <div className="flex gap-3 items-center">
        <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by IP, domain, reason…"
          className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500" />
        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)}
          className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white">
          <option value="">All Actions</option>
          {['DROP','BLOCK','REDIRECT','ALLOW'].map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <Btn variant="ghost" onClick={load}>Refresh</Btn>
      </div>
      <div className="text-xs text-dark-500">{filtered.length} entries shown (last 200 verdicts)</div>
      <div className="overflow-x-auto max-h-[60vh] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-dark-800">
            <tr className="text-left text-dark-400 border-b border-dark-700">
              <th className="pb-2 pr-3">Time</th>
              <th className="pb-2 pr-3">Action</th>
              <th className="pb-2 pr-3">Source</th>
              <th className="pb-2 pr-3">Destination</th>
              <th className="pb-2 pr-3">Domain</th>
              <th className="pb-2">Reason</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((l, i) => (
              <tr key={i} className="border-b border-dark-800 hover:bg-dark-800/50">
                <td className="py-1.5 pr-3 text-dark-500">{l.ts ? new Date(l.ts * 1000).toLocaleTimeString() : '—'}</td>
                <td className="py-1.5 pr-3"><Badge color={actionBadge(l.action)}>{l.action}</Badge></td>
                <td className="py-1.5 pr-3 font-mono text-dark-300">{l.src}:{l.sp}</td>
                <td className="py-1.5 pr-3 font-mono text-dark-300">{l.dst}:{l.dp}</td>
                <td className="py-1.5 pr-3 text-primary-400">{l.domain || '—'}</td>
                <td className="py-1.5 text-dark-400 truncate max-w-xs">{l.reason || l.detector || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <p className="text-dark-500 text-sm text-center py-8">No verdict logs found</p>}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB: Alerts
// ═══════════════════════════════════════════════════════════════════════════
function AlertsTab() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState(null);
  const [filter, setFilter] = useState('');
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 3000); };

  const load = useCallback(async () => {
    try { const data = await apiFetch('/alerts?limit=100'); setAlerts(data.alerts || []); }
    catch (e) { flash('error', e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const triage = async (id, status) => {
    try {
      await apiFetch(`/alerts/${id}/triage`, { method: 'POST', body: JSON.stringify({ status }) });
      flash('success', `Alert ${id} marked ${status}`);
      load();
    } catch (e) { flash('error', e.message); }
  };

  const severityBadge = (s) => ({ LOW: 'gray', MEDIUM: 'yellow', HIGH: 'red', CRITICAL: 'red' }[s] || 'gray');
  const filtered = alerts.filter(a => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (a.domain || '').toLowerCase().includes(q) || (a.type || '').toLowerCase().includes(q) || (a.details || '').toLowerCase().includes(q);
  });

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      {msg && <Alert type={msg.type}>{msg.text}</Alert>}
      <div className="flex gap-3">
        <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter alerts…"
          className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500" />
        <Btn variant="ghost" onClick={load}>Refresh</Btn>
      </div>
      {filtered.length === 0 ? <Card><p className="text-dark-500 text-sm text-center py-4">No alerts</p></Card> :
        filtered.map(alert => (
          <Card key={alert.id} className={alert.triage_status === 'resolved' ? 'opacity-60' : ''}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <Badge color={severityBadge(alert.severity)}>{alert.severity}</Badge>
                  <span className="text-xs text-dark-400">{alert.type?.replace('_', ' ')}</span>
                  {alert.domain && <span className="text-xs text-primary-400 font-mono">{alert.domain}</span>}
                  {alert.auto_blocked && <Badge color="red">AUTO-BLOCKED</Badge>}
                </div>
                <p className="text-xs text-dark-300">{alert.details}</p>
                <div className="text-xs text-dark-500 mt-1">{new Date(alert.timestamp).toLocaleString()}</div>
              </div>
              <div className="flex gap-2">
                {alert.triage_status !== 'resolved' && (
                  <Btn variant="ghost" size="sm" onClick={() => triage(alert.id, 'resolved')}>Resolve</Btn>
                )}
                {alert.triage_status !== 'false_positive' && (
                  <Btn variant="outline" size="sm" onClick={() => triage(alert.id, 'false_positive')}>FP</Btn>
                )}
              </div>
            </div>
          </Card>
        ))
      }
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Boundary — prevents blank blue screen on tab crashes
// ═══════════════════════════════════════════════════════════════════════════
class TabErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) { console.error('Tab crash:', error, info); }
  componentDidUpdate(prevProps) {
    if (prevProps.tabId !== this.props.tabId) this.setState({ error: null });
  }
  render() {
    if (this.state.error) {
      return (
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-6 text-center">
          <p className="text-red-400 font-semibold mb-2">This tab encountered an error</p>
          <p className="text-dark-400 text-sm mb-4">{this.state.error.message}</p>
          <button onClick={() => this.setState({ error: null })}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg text-sm">
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════
const TAB_COMPONENTS = {
  overview:    OverviewTab,
  domains:     DomainRulesTab,
  ips:         IPRulesTab,
  ratelimit:   RateLimitTab,
  ddos:        DDoSTab,
  bruteforce:  BruteForceTab,
  portscan:    PortScanTab,
  geoip:       GeoIPTab,
  customrules: CustomRulesTab,
  verdicts:    VerdictLogsTab,
  alerts:      AlertsTab,
};

export default function FirewallDashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const TabComponent = TAB_COMPONENTS[activeTab] || OverviewTab;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Firewall Engine</h1>
          <p className="text-dark-400 text-sm mt-1">Comprehensive network security control panel</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs text-dark-400">Engine API: <span className="text-primary-400">:8443</span></span>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-dark-700 overflow-x-auto">
        <div className="flex gap-0 min-w-max">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-400 bg-primary-900/10'
                  : 'border-transparent text-dark-400 hover:text-white hover:border-dark-600'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Active Tab Content */}
      <TabErrorBoundary tabId={activeTab} key={activeTab}>
        <TabComponent />
      </TabErrorBoundary>
    </div>
  );
}
