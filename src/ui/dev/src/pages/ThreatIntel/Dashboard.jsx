import { useState, useEffect } from 'react';
import {
  Database,
  RefreshCw,
  Plus,
  Key,
  Trash2,
  ExternalLink,
  Check,
  X,
  Copy,
  AlertCircle,
  Clock,
  Server,
  Globe,
  Shield,
  Hash,
  MapPin,
  Eye,
  EyeOff,
  ChevronDown,
  Download,
  Play,
  Loader2
} from 'lucide-react';
import {
  getDatabaseStats,
  checkHealth,
  getSources,
  addSource,
  removeSource,
  getApiKeys,
  generateApiKey,
  deleteApiKey,
  revokeApiKey,
  DB_CATEGORIES,
  SOURCE_TYPES
} from '../../services/threatIntelService';

// Category icons mapping
const CATEGORY_ICONS = {
  domains: Globe,
  hashes: Hash,
  ip_blacklist: Shield,
  ip_geolocation: MapPin,
  ip_anonymization: Eye
};

export default function ThreatIntelDashboard() {
  const [activeTab, setActiveTab] = useState('domains');
  const [dbStats, setDbStats] = useState(null);
  const [apiHealth, setApiHealth] = useState(null);
  const [sources, setSources] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddSource, setShowAddSource] = useState(false);
  const [showAddApiKey, setShowAddApiKey] = useState(false);
  const [showApiList, setShowApiList] = useState(false);
  const [showUpdateModal, setShowUpdateModal] = useState(false);
  const [pipelineStatus, setPipelineStatus] = useState({ running: false, logs: [] });
  const [newSource, setNewSource] = useState({ name: '', category: 'domains', type: 'url_csv', url: '' });
  const [newApiKeyName, setNewApiKeyName] = useState('');
  const [copiedKey, setCopiedKey] = useState(null);

  // Fetch data on mount
  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [stats, health] = await Promise.all([
        getDatabaseStats(),
        checkHealth()
      ]);
      setDbStats(stats);
      setApiHealth(health);
      setSources(getSources());
      setApiKeys(getApiKeys());
    } catch (error) {
      console.error('Failed to load data:', error);
    }
    setLoading(false);
  }

  // Handle adding a new source
  function handleAddSource() {
    if (!newSource.name || !newSource.url) return;
    const source = addSource(newSource);
    setSources([...sources, source]);
    setNewSource({ name: '', category: 'domains', type: 'url_csv', url: '' });
    setShowAddSource(false);
  }

  // Handle removing a source
  function handleRemoveSource(id) {
    const updated = removeSource(id);
    setSources(updated);
  }

  // Handle generating API key
  function handleGenerateApiKey() {
    if (!newApiKeyName) return;
    const key = generateApiKey(newApiKeyName, ['read', 'lookup']);
    setApiKeys([...apiKeys, key]);
    setNewApiKeyName('');
    setShowAddApiKey(false);
  }

  // Handle revoking API key
  function handleRevokeKey(id) {
    const updated = revokeApiKey(id);
    setApiKeys(updated);
  }

  // Handle deleting API key
  function handleDeleteKey(id) {
    const updated = deleteApiKey(id);
    setApiKeys(updated);
  }

  // Copy API key to clipboard
  function copyToClipboard(key) {
    navigator.clipboard.writeText(key);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }

  // Trigger database update
  async function triggerUpdate() {
    setPipelineStatus({ running: true, logs: ['Starting pipeline...'] });
    setShowUpdateModal(true);

    try {
      const response = await fetch('http://localhost:5050/api/threat-intel/update', {
        method: 'POST'
      });

      if (!response.ok) throw new Error('Failed to start pipeline');

      // Poll for status
      const pollStatus = async () => {
        const statusRes = await fetch('http://localhost:5050/api/threat-intel/pipeline/status');
        const status = await statusRes.json();
        setPipelineStatus(status);

        if (status.running) {
          setTimeout(pollStatus, 1000);
        } else {
          // Refresh stats after completion
          loadData();
        }
      };

      setTimeout(pollStatus, 1000);
    } catch (error) {
      setPipelineStatus({
        running: false,
        logs: [`Error: ${error.message}`],
        lastResult: { success: false, error: error.message }
      });
    }
  }

  // Get sources for current category
  const categorySources = sources.filter(s => s.category === activeTab);

  // Get stats for current category
  const categoryStats = dbStats?.[activeTab] || { row_count: 0, columns: 0 };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Database className="w-7 h-7 text-primary-400" />
            Threat Intelligence Database
          </h1>
          <p className="text-dark-400 mt-1">Manage threat data sources and API access</p>
        </div>

        <div className="flex items-center gap-3">
          {/* API Health Status */}
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${apiHealth?.status === 'ok'
              ? 'bg-green-500/10 text-green-400'
              : 'bg-red-500/10 text-red-400'
            }`}>
            <span className={`w-2 h-2 rounded-full ${apiHealth?.status === 'ok' ? 'bg-green-400' : 'bg-red-400'
              }`} />
            <span className="text-sm font-medium">
              API: {apiHealth?.status === 'ok' ? 'Connected' : 'Offline'}
            </span>
          </div>

          {/* Update Database Button */}
          <button
            onClick={triggerUpdate}
            disabled={pipelineStatus.running}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${pipelineStatus.running
                ? 'bg-yellow-500/20 text-yellow-400 cursor-wait'
                : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
          >
            {pipelineStatus.running ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Updating...
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                Update Database
              </>
            )}
          </button>

          <button
            onClick={loadData}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Database Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
        {Object.entries(DB_CATEGORIES).map(([key, cat]) => {
          const Icon = CATEGORY_ICONS[key];
          const stats = dbStats?.[key];
          const isActive = activeTab === key;

          return (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`p-4 rounded-xl border transition-all duration-200 text-left ${isActive
                  ? 'bg-gradient-to-br ' + cat.color + ' border-transparent text-white shadow-lg scale-[1.02]'
                  : 'bg-dark-800 border-dark-700 hover:border-dark-500 text-dark-200 hover:text-white'
                }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-5 h-5" />
                <span className="text-xl">{cat.icon}</span>
              </div>
              <div className="text-2xl font-bold">
                {stats?.row_count?.toLocaleString() || '0'}
              </div>
              <div className={`text-sm ${isActive ? 'text-white/70' : 'text-dark-400'}`}>
                {cat.name}
              </div>
            </button>
          );
        })}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Category Details & Sources */}
        <div className="lg:col-span-2 space-y-6">
          {/* Category Header */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                  <span className="text-2xl">{DB_CATEGORIES[activeTab].icon}</span>
                  {DB_CATEGORIES[activeTab].name}
                </h2>
                <p className="text-dark-400 mt-1">{DB_CATEGORIES[activeTab].description}</p>
              </div>
              <button
                onClick={() => setShowAddSource(true)}
                className="flex items-center gap-2 px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add Source
              </button>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-dark-700/50 rounded-lg p-4">
                <div className="text-dark-400 text-sm mb-1">Total Records</div>
                <div className="text-2xl font-bold text-white">
                  {categoryStats.row_count?.toLocaleString() || '0'}
                </div>
              </div>
              <div className="bg-dark-700/50 rounded-lg p-4">
                <div className="text-dark-400 text-sm mb-1">Active Sources</div>
                <div className="text-2xl font-bold text-white">
                  {categorySources.filter(s => s.status === 'active').length}
                </div>
              </div>
              <div className="bg-dark-700/50 rounded-lg p-4">
                <div className="text-dark-400 text-sm mb-1">Columns</div>
                <div className="text-2xl font-bold text-white">
                  {categoryStats.columns || '—'}
                </div>
              </div>
            </div>
          </div>

          {/* Sources Table */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-dark-700">
              <h3 className="text-lg font-semibold text-white">Data Sources</h3>
            </div>

            {categorySources.length === 0 ? (
              <div className="p-8 text-center text-dark-400">
                <Database className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No sources configured for {DB_CATEGORIES[activeTab].name}</p>
                <button
                  onClick={() => setShowAddSource(true)}
                  className="mt-4 text-primary-400 hover:text-primary-300"
                >
                  + Add your first source
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-dark-700/50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-dark-400 uppercase">Name</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-dark-400 uppercase">Type</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-dark-400 uppercase">Records</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-dark-400 uppercase">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-dark-400 uppercase">Last Fetch</th>
                      <th className="px-6 py-3 text-right text-xs font-medium text-dark-400 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-700">
                    {categorySources.map(source => (
                      <tr key={source.id} className="hover:bg-dark-700/30">
                        <td className="px-6 py-4">
                          <div className="font-medium text-white">{source.name}</div>
                          <div className="text-xs text-dark-400 truncate max-w-xs">{source.url}</div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-dark-300">
                            {SOURCE_TYPES.find(t => t.id === source.type)?.name || source.type}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-white">
                          {source.records?.toLocaleString() || '—'}
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${source.status === 'active'
                              ? 'bg-green-500/10 text-green-400'
                              : source.status === 'failed'
                                ? 'bg-red-500/10 text-red-400'
                                : 'bg-yellow-500/10 text-yellow-400'
                            }`}>
                            {source.status === 'active' && <Check className="w-3 h-3" />}
                            {source.status === 'failed' && <X className="w-3 h-3" />}
                            {source.status === 'pending' && <Clock className="w-3 h-3" />}
                            {source.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-dark-400 text-sm">
                          {source.lastFetch
                            ? new Date(source.lastFetch).toLocaleDateString()
                            : 'Never'
                          }
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              className="p-1.5 text-dark-400 hover:text-white hover:bg-dark-600 rounded"
                              title="Open URL"
                            >
                              <ExternalLink className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleRemoveSource(source.id)}
                              className="p-1.5 text-dark-400 hover:text-red-400 hover:bg-red-500/10 rounded"
                              title="Remove"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right: API Keys */}
        <div className="space-y-6">
          {/* API Keys */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-dark-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Key className="w-5 h-5 text-primary-400" />
                API Keys
              </h3>
              <button
                onClick={() => setShowAddApiKey(true)}
                className="p-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 space-y-3">
              {apiKeys.length === 0 ? (
                <div className="text-center text-dark-400 py-6">
                  <Key className="w-10 h-10 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No API keys generated</p>
                </div>
              ) : (
                apiKeys.map(apiKey => (
                  <div
                    key={apiKey.id}
                    className={`p-4 rounded-lg border ${apiKey.isActive
                        ? 'bg-dark-700/50 border-dark-600'
                        : 'bg-dark-800 border-dark-700 opacity-50'
                      }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-white">{apiKey.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${apiKey.isActive
                          ? 'bg-green-500/10 text-green-400'
                          : 'bg-red-500/10 text-red-400'
                        }`}>
                        {apiKey.isActive ? 'Active' : 'Revoked'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mb-3">
                      <code className="flex-1 text-xs bg-dark-900 px-3 py-2 rounded text-dark-300 font-mono truncate">
                        {apiKey.key}
                      </code>
                      <button
                        onClick={() => copyToClipboard(apiKey.key)}
                        className="p-2 text-dark-400 hover:text-white hover:bg-dark-600 rounded"
                      >
                        {copiedKey === apiKey.key ? (
                          <Check className="w-4 h-4 text-green-400" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                    <div className="flex items-center justify-between text-xs text-dark-400">
                      <span>Created: {new Date(apiKey.createdAt).toLocaleDateString()}</span>
                      <div className="flex gap-2">
                        {apiKey.isActive && (
                          <button
                            onClick={() => handleRevokeKey(apiKey.id)}
                            className="text-yellow-400 hover:text-yellow-300"
                          >
                            Revoke
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteKey(apiKey.id)}
                          className="text-red-400 hover:text-red-300"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Custom API Builder */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Plus className="w-5 h-5 text-green-400" />
              Create Custom API
            </h3>
            <p className="text-dark-400 text-sm mb-4">
              Create a custom API endpoint for {DB_CATEGORIES[activeTab].name.toLowerCase()}
            </p>

            {/* Quick Create Buttons */}
            <div className="space-y-2">
              <button
                onClick={() => {
                  const endpoint = `/api/custom/${activeTab}/list`;
                  navigator.clipboard.writeText(`http://localhost:5050${endpoint}`);
                  alert(`API Created: ${endpoint}\nCopied to clipboard!`);
                }}
                className="w-full flex items-center justify-between p-3 bg-dark-700/50 hover:bg-dark-600 rounded-lg text-left transition-colors"
              >
                <div>
                  <div className="text-white font-medium">List All</div>
                  <div className="text-xs text-dark-400">GET /api/custom/{activeTab}/list</div>
                </div>
                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">GET</span>
              </button>

              <button
                onClick={() => {
                  const endpoint = `/api/custom/${activeTab}/search`;
                  navigator.clipboard.writeText(`http://localhost:5050${endpoint}`);
                  alert(`API Created: ${endpoint}\nCopied to clipboard!`);
                }}
                className="w-full flex items-center justify-between p-3 bg-dark-700/50 hover:bg-dark-600 rounded-lg text-left transition-colors"
              >
                <div>
                  <div className="text-white font-medium">Search</div>
                  <div className="text-xs text-dark-400">GET /api/custom/{activeTab}/search?q=</div>
                </div>
                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">GET</span>
              </button>

              <button
                onClick={() => {
                  const endpoint = `/api/custom/${activeTab}/bulk`;
                  navigator.clipboard.writeText(`http://localhost:5050${endpoint}`);
                  alert(`API Created: ${endpoint}\nCopied to clipboard!`);
                }}
                className="w-full flex items-center justify-between p-3 bg-dark-700/50 hover:bg-dark-600 rounded-lg text-left transition-colors"
              >
                <div>
                  <div className="text-white font-medium">Bulk Lookup</div>
                  <div className="text-xs text-dark-400">POST /api/custom/{activeTab}/bulk</div>
                </div>
                <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">POST</span>
              </button>

              <button
                onClick={() => {
                  const endpoint = `/api/custom/${activeTab}/export`;
                  navigator.clipboard.writeText(`http://localhost:5050${endpoint}`);
                  alert(`API Created: ${endpoint}\nCopied to clipboard!`);
                }}
                className="w-full flex items-center justify-between p-3 bg-dark-700/50 hover:bg-dark-600 rounded-lg text-left transition-colors"
              >
                <div>
                  <div className="text-white font-medium">Export CSV</div>
                  <div className="text-xs text-dark-400">GET /api/custom/{activeTab}/export</div>
                </div>
                <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">CSV</span>
              </button>
            </div>

            <div className="mt-4 pt-4 border-t border-dark-700">
              <p className="text-dark-500 text-xs">
                Click any button to create the API endpoint and copy to clipboard
              </p>
            </div>
          </div>

          {/* API Endpoints Info - Expandable */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
            <button
              onClick={() => setShowApiList(!showApiList)}
              className="w-full px-6 py-4 flex items-center justify-between hover:bg-dark-700/50 transition-colors"
            >
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Server className="w-5 h-5 text-primary-400" />
                All API Endpoints
              </h3>
              <div className="flex items-center gap-2">
                <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-1 rounded-full">
                  {5 + Object.keys(DB_CATEGORIES).length * 4} endpoints
                </span>
                <ChevronDown className={`w-5 h-5 text-dark-400 transition-transform ${showApiList ? 'rotate-180' : ''}`} />
              </div>
            </button>

            {showApiList && (
              <div className="px-6 pb-6 space-y-4 animate-fade-in">
                {/* Core APIs */}
                <div>
                  <div className="text-xs text-dark-400 font-medium mb-2 uppercase">Core Endpoints</div>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                      <code className="text-dark-300 flex-1">/api/status</code>
                      <span className="text-xs text-dark-500">Database stats</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                      <code className="text-dark-300 flex-1">/api/lookup/ip/{'{ip}'}</code>
                      <span className="text-xs text-dark-500">IP lookup</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                      <code className="text-dark-300 flex-1">/api/lookup/domain/{'{domain}'}</code>
                      <span className="text-xs text-dark-500">Domain lookup</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                      <code className="text-dark-300 flex-1">/api/lookup/hash/{'{hash}'}</code>
                      <span className="text-xs text-dark-500">Hash lookup</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                      <code className="text-dark-300 flex-1">/api/headers</code>
                      <span className="text-xs text-dark-500">Table schema</span>
                    </div>
                    <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                      <code className="text-dark-300 flex-1">/api/health</code>
                      <span className="text-xs text-dark-500">Health check</span>
                    </div>
                  </div>
                </div>

                {/* Category-specific APIs */}
                {Object.entries(DB_CATEGORIES).map(([catKey, catInfo]) => (
                  <div key={catKey}>
                    <div className="text-xs text-dark-400 font-medium mb-2 uppercase flex items-center gap-2">
                      <span>{catInfo.icon}</span> {catInfo.name} APIs
                    </div>
                    <div className="space-y-2 text-sm">
                      <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                        <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                        <code className="text-dark-300 flex-1">/api/custom/{catKey}/list</code>
                        <span className="text-xs text-dark-500">List all</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                        <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-mono">GET</span>
                        <code className="text-dark-300 flex-1">/api/custom/{catKey}/search</code>
                        <span className="text-xs text-dark-500">Search</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                        <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs font-mono">POST</span>
                        <code className="text-dark-300 flex-1">/api/custom/{catKey}/bulk</code>
                        <span className="text-xs text-dark-500">Bulk lookup</span>
                      </div>
                      <div className="flex items-center gap-2 p-2 bg-dark-700/30 rounded-lg">
                        <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs font-mono">GET</span>
                        <code className="text-dark-300 flex-1">/api/custom/{catKey}/export</code>
                        <span className="text-xs text-dark-500">CSV export</span>
                      </div>
                    </div>
                  </div>
                ))}

                <div className="pt-4 border-t border-dark-700">
                  <p className="text-dark-400 text-xs">Base URL: <code className="text-primary-400">http://localhost:5050</code></p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Add Source Modal */}
      {showAddSource && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 w-full max-w-lg mx-4 animate-fade-in">
            <h3 className="text-xl font-bold text-white mb-4">Add New Source</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">Source Name</label>
                <input
                  type="text"
                  value={newSource.name}
                  onChange={e => setNewSource({ ...newSource, name: e.target.value })}
                  placeholder="e.g., Abuse.ch URLhaus"
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white placeholder-dark-400 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block text-sm text-dark-400 mb-1">Category</label>
                <select
                  value={newSource.category}
                  onChange={e => setNewSource({ ...newSource, category: e.target.value })}
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white focus:outline-none focus:border-primary-500"
                >
                  {Object.entries(DB_CATEGORIES).map(([key, cat]) => (
                    <option key={key} value={key}>{cat.icon} {cat.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm text-dark-400 mb-1">Source Type</label>
                <select
                  value={newSource.type}
                  onChange={e => setNewSource({ ...newSource, type: e.target.value })}
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white focus:outline-none focus:border-primary-500"
                >
                  {SOURCE_TYPES.map(type => (
                    <option key={type.id} value={type.id}>{type.icon} {type.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm text-dark-400 mb-1">Feed URL</label>
                <input
                  type="url"
                  value={newSource.url}
                  onChange={e => setNewSource({ ...newSource, url: e.target.value })}
                  placeholder="https://example.com/feed.csv"
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white placeholder-dark-400 focus:outline-none focus:border-primary-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowAddSource(false)}
                className="px-4 py-2 text-dark-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleAddSource}
                className="px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg"
              >
                Add Source
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add API Key Modal */}
      {showAddApiKey && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 w-full max-w-md mx-4 animate-fade-in">
            <h3 className="text-xl font-bold text-white mb-4">Generate API Key</h3>

            <div>
              <label className="block text-sm text-dark-400 mb-1">Key Name</label>
              <input
                type="text"
                value={newApiKeyName}
                onChange={e => setNewApiKeyName(e.target.value)}
                placeholder="e.g., Production App"
                className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white placeholder-dark-400 focus:outline-none focus:border-primary-500"
              />
            </div>

            <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
              <div className="flex items-start gap-2">
                <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-yellow-200">
                  Make sure to copy your API key after creation. You won't be able to see it again!
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowAddApiKey(false)}
                className="px-4 py-2 text-dark-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerateApiKey}
                className="px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg"
              >
                Generate Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Pipeline Progress Modal */}
      {showUpdateModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 w-full max-w-2xl mx-4 animate-fade-in">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white flex items-center gap-2">
                {pipelineStatus.running ? (
                  <>
                    <Loader2 className="w-6 h-6 text-yellow-400 animate-spin" />
                    Updating Database...
                  </>
                ) : pipelineStatus.lastResult?.success ? (
                  <>
                    <Check className="w-6 h-6 text-green-400" />
                    Update Complete
                  </>
                ) : (
                  <>
                    <X className="w-6 h-6 text-red-400" />
                    Update Failed
                  </>
                )}
              </h3>
              {!pipelineStatus.running && (
                <button
                  onClick={() => setShowUpdateModal(false)}
                  className="p-1 text-dark-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              )}
            </div>

            {/* Log Output */}
            <div className="bg-dark-900 rounded-lg p-4 h-80 overflow-y-auto font-mono text-sm">
              {pipelineStatus.logs?.map((log, i) => (
                <div
                  key={i}
                  className={`py-1 ${log.includes('[ERROR]') ? 'text-red-400' :
                      log.includes('[COMPLETE]') ? 'text-green-400' :
                        log.includes('[FETCH]') ? 'text-blue-400' :
                          log.includes('[PROCESS]') ? 'text-purple-400' :
                            log.includes('[CLEANUP]') ? 'text-yellow-400' :
                              'text-dark-300'
                    }`}
                >
                  {log}
                </div>
              ))}
              {pipelineStatus.running && (
                <div className="py-1 text-dark-500 animate-pulse">▌</div>
              )}
            </div>

            {/* Result Summary */}
            {pipelineStatus.lastResult && !pipelineStatus.running && (
              <div className={`mt-4 p-3 rounded-lg ${pipelineStatus.lastResult.success
                  ? 'bg-green-500/10 border border-green-500/20 text-green-400'
                  : 'bg-red-500/10 border border-red-500/20 text-red-400'
                }`}>
                {pipelineStatus.lastResult.success ? (
                  <p>✓ Database updated successfully in {pipelineStatus.lastResult.duration}</p>
                ) : (
                  <p>✗ {pipelineStatus.lastResult.error}</p>
                )}
              </div>
            )}

            {!pipelineStatus.running && (
              <div className="flex justify-end mt-4">
                <button
                  onClick={() => setShowUpdateModal(false)}
                  className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
