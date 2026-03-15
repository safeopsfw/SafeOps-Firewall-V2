import { useState, useEffect, useCallback } from 'react';
import { Shield, Wifi, CheckCircle, AlertCircle, RefreshCw, Download, Users, Activity } from 'lucide-react';

const BASE = 'http://localhost:8090';

function StatusBadge({ ok, label }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
      ok ? 'bg-green-500/15 text-green-400 border border-green-500/30'
         : 'bg-red-500/15 text-red-400 border border-red-500/30'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-green-400' : 'bg-red-400'}`} />
      {label}
    </span>
  );
}

function StatCard({ icon: Icon, label, value, sub, color = 'blue' }) {
  const colors = {
    blue:   'bg-blue-500/10 text-blue-400 border-blue-500/20',
    green:  'bg-green-500/10 text-green-400 border-green-500/20',
    yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  };
  return (
    <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 flex items-start gap-4">
      <div className={`p-2.5 rounded-lg border ${colors[color]}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <div className="text-2xl font-bold text-white">{value ?? '—'}</div>
        <div className="text-sm text-dark-400">{label}</div>
        {sub && <div className="text-xs text-dark-500 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

export default function CaptivePortal() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionMsg, setActionMsg] = useState(null);

  const fetchHealth = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(3000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHealth(data);
    } catch (e) {
      setError(`Cannot reach Captive Portal at ${BASE} — is it running?`);
      setHealth(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchHealth(); }, [fetchHealth]);

  const showAction = (msg, isError = false) => {
    setActionMsg({ msg, isError });
    setTimeout(() => setActionMsg(null), 3000);
  };

  const downloadCA = async (fmt) => {
    try {
      const res = await fetch(`${BASE}/api/download-ca/${fmt}`);
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `safeops-ca.${fmt}`;
      a.click();
      URL.revokeObjectURL(url);
      showAction(`Downloaded safeops-ca.${fmt}`);
    } catch (e) {
      showAction(`Download failed: ${e.message}`, true);
    }
  };

  const isOnline = !error && health;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Shield className="w-7 h-7 text-blue-400" />
            Captive Portal
          </h1>
          <p className="text-dark-400 mt-1 text-sm">
            Network access control — redirects unregistered devices for CA certificate installation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge ok={isOnline} label={isOnline ? 'Online' : 'Offline'} />
          <button
            onClick={fetchHealth}
            className="flex items-center gap-2 px-3 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-dark-300 hover:text-white rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Action notification */}
      {actionMsg && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${
          actionMsg.isError ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                           : 'bg-green-500/15 text-green-400 border border-green-500/30'
        }`}>
          {actionMsg.msg}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-5">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-red-300 font-medium">Service Unreachable</div>
              <div className="text-red-400/70 text-sm mt-1">{error}</div>
              <div className="text-dark-400 text-xs mt-2">Start the captive portal from the SafeOps Launcher first.</div>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      {health && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={Activity}
              label="Service Status"
              value={health.status === 'healthy' ? 'Healthy' : 'Degraded'}
              color={health.status === 'healthy' ? 'green' : 'yellow'}
            />
            <StatCard
              icon={Users}
              label="Trusted Devices"
              value={health.trusted_devices ?? '—'}
              sub="in DHCP lease table"
              color="blue"
            />
            <StatCard
              icon={Wifi}
              label="DHCP Leases"
              value={health.dhcp_leases ?? '—'}
              sub="active clients"
              color="purple"
            />
            <StatCard
              icon={Shield}
              label="Step-CA"
              value={health.stepca_connected ? 'Connected' : 'Disconnected'}
              color={health.stepca_connected ? 'green' : 'yellow'}
            />
          </div>

          {/* Portal Info */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Service Details */}
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
              <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4 text-blue-400" />
                Service Details
              </h2>
              <div className="space-y-3">
                {[
                  { label: 'HTTP Port',  value: ':8090' },
                  { label: 'HTTPS Port', value: ':8445' },
                  { label: 'Step-CA',    value: health.stepca_connected ? 'Connected (:9000)' : 'Not connected' },
                  { label: 'Database',   value: health.db_connected ? 'PostgreSQL connected' : 'Not connected' },
                  { label: 'Version',    value: health.version || '—' },
                ].map(({ label, value }) => (
                  <div key={label} className="flex items-center justify-between text-sm">
                    <span className="text-dark-400">{label}</span>
                    <span className="text-dark-200 font-mono">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* CA Certificate Download */}
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
              <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
                <Download className="w-4 h-4 text-green-400" />
                CA Certificate
              </h2>
              <p className="text-sm text-dark-400 mb-4">
                Download the SafeOps root CA certificate to trust internally signed TLS certificates.
              </p>
              <div className="space-y-2">
                {['pem', 'crt', 'der'].map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => downloadCA(fmt)}
                    className="w-full flex items-center justify-between px-4 py-2.5 bg-dark-700 hover:bg-dark-600 border border-dark-600 rounded-lg text-sm text-dark-200 hover:text-white transition-colors"
                  >
                    <span className="font-mono">safeops-ca.{fmt}</span>
                    <Download className="w-4 h-4 text-dark-400" />
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* How it works */}
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
            <h2 className="text-base font-semibold text-white mb-4">How it works</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                {
                  step: '1',
                  title: 'Device Connects',
                  desc: 'New device joins the network. Captive portal detects via DHCP lease table.',
                },
                {
                  step: '2',
                  title: 'Install CA Certificate',
                  desc: 'Device is redirected to the portal page to download and trust the SafeOps root CA.',
                },
                {
                  step: '3',
                  title: 'Full Access',
                  desc: 'Device marked as trusted. TLS certificates from Step-CA are automatically trusted.',
                },
              ].map(({ step, title, desc }) => (
                <div key={step} className="flex gap-3">
                  <div className="w-7 h-7 bg-blue-500/20 border border-blue-500/30 rounded-full flex items-center justify-center text-blue-400 text-sm font-bold flex-shrink-0 mt-0.5">
                    {step}
                  </div>
                  <div>
                    <div className="text-sm font-medium text-white">{title}</div>
                    <div className="text-xs text-dark-400 mt-1">{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* Portal Actions */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
        <h2 className="text-base font-semibold text-white mb-4">Quick Actions</h2>
        <div className="flex flex-wrap gap-3">
          <a
            href="http://localhost:8090"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition-colors"
          >
            <Wifi className="w-4 h-4" />
            Open Portal Page (HTTP)
          </a>
          <a
            href="https://localhost:8445"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded-lg text-sm transition-colors"
          >
            <Shield className="w-4 h-4" />
            Open Portal Page (HTTPS)
          </a>
          <button
            onClick={fetchHealth}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-dark-300 hover:text-white rounded-lg text-sm transition-colors"
          >
            <CheckCircle className="w-4 h-4" />
            Check Trust Status
          </button>
        </div>
      </div>
    </div>
  );
}
