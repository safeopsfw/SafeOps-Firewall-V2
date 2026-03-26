import { useState, useEffect, useCallback } from 'react';
import {
  Search,
  Plus,
  Shield,
  CheckCircle,
  XCircle,
  Save,
  Trash2,
  Wand2,
  X,
  ChevronRight,
  ArrowRight,
  Ban,
  Check,
  AlertTriangle,
  Activity,
  RefreshCw,
  Play,
  Pause,
  Edit2,
  Filter
} from 'lucide-react';

const API_BASE = 'http://localhost:5050/api/firewall';

// Rule presets
const rulePresets = [
  { id: 'block_ip', name: 'Block IP Address', description: 'Block traffic from specific IP or range' },
  { id: 'allow_port', name: 'Allow Port', description: 'Allow traffic on specific port' },
  { id: 'block_country', name: 'Block Country', description: 'Block traffic from specific country' },
  { id: 'rate_limit', name: 'Rate Limit', description: 'Limit connections per IP' },
  { id: 'whitelist', name: 'Whitelist IP', description: 'Allow traffic from trusted IP' },
  { id: 'block_port', name: 'Block Port', description: 'Block traffic on specific port' },
];

const actionOptions = ['ALLOW', 'BLOCK', 'LOG', 'REJECT'];
const protocolOptions = ['ANY', 'TCP', 'UDP', 'ICMP'];

export default function FirewallManager() {
  const [rules, setRules] = useState([]);
  const [devices, setDevices] = useState([]);
  const [stats, setStats] = useState({ blocked: 0, allowed: 0, total: 0 });
  const [packetLogs, setPacketLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('rules');
  const [filterStatus, setFilterStatus] = useState('all');
  const [showHelperModal, setShowHelperModal] = useState(false);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [editingRule, setEditingRule] = useState(null);

  // Builder form state
  const [formData, setFormData] = useState({
    name: '',
    action: 'BLOCK',
    protocol: 'ANY',
    srcIp: '',
    dstIp: '',
    srcPort: '',
    dstPort: '',
    deviceMac: '',
    priority: 100,
    enabled: true
  });

  // Fetch firewall rules
  const fetchRules = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/rules`);
      if (res.ok) {
        const data = await res.json();
        setRules(data);
      }
    } catch (error) {
      console.error('Failed to fetch rules:', error);
    }
  }, []);

  // Fetch statistics
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  }, []);

  // Fetch packet logs
  const fetchLogs = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/logs?limit=50`);
      if (res.ok) {
        const data = await res.json();
        setPacketLogs(data);
      }
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    }
  }, []);

  // Fetch devices
  const fetchDevices = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:5050/api/devices');
      if (res.ok) {
        const data = await res.json();
        setDevices(data);
      }
    } catch (error) {
      console.error('Failed to fetch devices:', error);
    }
  }, []);

  // Initial data load
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchRules(), fetchStats(), fetchDevices()]);
      setLoading(false);
    };
    loadData();
  }, [fetchRules, fetchStats, fetchDevices]);

  // Auto-refresh packet logs when on monitor tab
  useEffect(() => {
    if (activeTab === 'monitor') {
      fetchLogs();
      const interval = setInterval(fetchLogs, 3000);
      return () => clearInterval(interval);
    }
  }, [activeTab, fetchLogs]);

  // Add new rule
  const handleAddRule = async () => {
    if (!formData.name) return;

    try {
      const res = await fetch(`${API_BASE}/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (res.ok) {
        await fetchRules();
        setShowRuleModal(false);
        resetForm();
      }
    } catch (error) {
      console.error('Failed to add rule:', error);
    }
  };

  // Update rule
  const handleUpdateRule = async () => {
    if (!editingRule) return;

    try {
      const res = await fetch(`${API_BASE}/rules/${editingRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (res.ok) {
        await fetchRules();
        setShowRuleModal(false);
        setEditingRule(null);
        resetForm();
      }
    } catch (error) {
      console.error('Failed to update rule:', error);
    }
  };

  // Delete rule
  const handleDeleteRule = async (id) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;

    try {
      const res = await fetch(`${API_BASE}/rules/${id}`, {
        method: 'DELETE'
      });

      if (res.ok) {
        await fetchRules();
      }
    } catch (error) {
      console.error('Failed to delete rule:', error);
    }
  };

  // Toggle rule enabled/disabled
  const handleToggleRule = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/rules/${id}/toggle`, {
        method: 'PATCH'
      });

      if (res.ok) {
        await fetchRules();
      }
    } catch (error) {
      console.error('Failed to toggle rule:', error);
    }
  };

  // Edit rule
  const handleEditRule = (rule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      action: rule.action,
      protocol: rule.protocol,
      srcIp: rule.srcIp || '',
      dstIp: rule.dstIp || '',
      srcPort: rule.srcPort || '',
      dstPort: rule.dstPort || '',
      deviceMac: rule.deviceMac || '',
      priority: rule.priority,
      enabled: rule.enabled
    });
    setShowRuleModal(true);
  };

  // Reset form
  const resetForm = () => {
    setFormData({
      name: '',
      action: 'BLOCK',
      protocol: 'ANY',
      srcIp: '',
      dstIp: '',
      srcPort: '',
      dstPort: '',
      deviceMac: '',
      priority: 100,
      enabled: true
    });
  };

  // Apply preset
  const applyPreset = (preset) => {
    const presetDefaults = {
      block_ip: { name: 'Block IP - ', action: 'BLOCK', protocol: 'ANY' },
      allow_port: { name: 'Allow Port - ', action: 'ALLOW', protocol: 'TCP' },
      block_country: { name: 'Block Country - ', action: 'BLOCK', protocol: 'ANY' },
      rate_limit: { name: 'Rate Limit - ', action: 'BLOCK', protocol: 'TCP' },
      whitelist: { name: 'Whitelist - ', action: 'ALLOW', protocol: 'ANY' },
      block_port: { name: 'Block Port - ', action: 'BLOCK', protocol: 'TCP' },
    };

    setFormData(prev => ({
      ...prev,
      ...presetDefaults[preset.id]
    }));
    setShowHelperModal(false);
    setShowRuleModal(true);
  };

  // Filter rules
  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterStatus === 'all' ? true :
      filterStatus === 'enabled' ? rule.enabled :
        !rule.enabled;
    return matchesSearch && matchesFilter;
  });

  // Generate iptables command preview
  const generateIptablesRule = () => {
    const action = formData.action === 'ALLOW' ? 'ACCEPT' :
      formData.action === 'BLOCK' ? 'DROP' :
        formData.action === 'REJECT' ? 'REJECT' : 'LOG';

    let rule = 'iptables -A FORWARD';

    if (formData.protocol !== 'ANY') {
      rule += ` -p ${formData.protocol.toLowerCase()}`;
    }

    if (formData.srcIp && formData.srcIp !== '*') {
      rule += ` -s ${formData.srcIp}`;
    }

    if (formData.dstIp && formData.dstIp !== '*') {
      rule += ` -d ${formData.dstIp}`;
    }

    if (formData.dstPort && formData.dstPort !== '*') {
      rule += ` --dport ${formData.dstPort}`;
    }

    rule += ` -j ${action}`;

    return rule;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="w-8 h-8 border-4 border-primary-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-primary-400" />
          <div>
            <h1 className="text-2xl font-bold text-dark-900 dark:text-white">Firewall Manager</h1>
            <p className="text-dark-400">Real-time packet filtering and rule management</p>
          </div>
        </div>
        <button
          onClick={() => { fetchRules(); fetchStats(); }}
          className="flex items-center gap-2 px-4 py-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white rounded-lg transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-dark-800 rounded-xl p-5 border border-dark-200 dark:border-dark-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Total Packets</p>
              <p className="text-2xl font-bold mt-1 text-dark-900 dark:text-white">{stats.total?.toLocaleString() || 0}</p>
            </div>
            <Activity className="w-10 h-10 text-primary-400 opacity-50" />
          </div>
        </div>

        <div className="bg-white dark:bg-dark-800 rounded-xl p-5 border border-green-900/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Allowed</p>
              <p className="text-2xl font-bold mt-1 text-green-400">{stats.allowed?.toLocaleString() || 0}</p>
            </div>
            <CheckCircle className="w-10 h-10 text-green-400 opacity-50" />
          </div>
        </div>

        <div className="bg-white dark:bg-dark-800 rounded-xl p-5 border border-red-900/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Blocked</p>
              <p className="text-2xl font-bold mt-1 text-red-400">{stats.blocked?.toLocaleString() || 0}</p>
            </div>
            <XCircle className="w-10 h-10 text-red-400 opacity-50" />
          </div>
        </div>

        <div className="bg-white dark:bg-dark-800 rounded-xl p-5 border border-dark-200 dark:border-dark-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Active Rules</p>
              <p className="text-2xl font-bold mt-1 text-dark-900 dark:text-white">{stats.activeRules || 0}</p>
            </div>
            <Shield className="w-10 h-10 text-primary-400 opacity-50" />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-dark-200 dark:border-dark-700">
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-4 py-3 font-medium transition-colors ${activeTab === 'rules'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
            }`}
        >
          <Shield className="w-4 h-4 inline mr-2" />
          Firewall Rules
        </button>
        <button
          onClick={() => setActiveTab('monitor')}
          className={`px-4 py-3 font-medium transition-colors ${activeTab === 'monitor'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
            }`}
        >
          <Activity className="w-4 h-4 inline mr-2" />
          Packet Monitor
        </button>
        <button
          onClick={() => setActiveTab('devices')}
          className={`px-4 py-3 font-medium transition-colors ${activeTab === 'devices'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
            }`}
        >
          <Filter className="w-4 h-4 inline mr-2" />
          Device Policies
        </button>
      </div>

      {/* Rules Tab */}
      {activeTab === 'rules' && (
        <>
          <div className="flex items-center justify-between mb-4">
            <div className="flex gap-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
                <input
                  type="text"
                  placeholder="Search rules..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-4 py-2 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500 w-64"
                />
              </div>
              <div className="flex gap-1 bg-white dark:bg-dark-800 p-1 rounded-lg border border-dark-200 dark:border-dark-700">
                <button
                  onClick={() => setFilterStatus('all')}
                  className={`px-3 py-1.5 rounded text-sm transition ${filterStatus === 'all' ? 'bg-primary-500 text-dark-900 dark:text-white' : 'text-dark-400 hover:text-dark-900 dark:text-white'
                    }`}
                >
                  All
                </button>
                <button
                  onClick={() => setFilterStatus('enabled')}
                  className={`px-3 py-1.5 rounded text-sm transition ${filterStatus === 'enabled' ? 'bg-primary-500 text-dark-900 dark:text-white' : 'text-dark-400 hover:text-dark-900 dark:text-white'
                    }`}
                >
                  Enabled
                </button>
                <button
                  onClick={() => setFilterStatus('disabled')}
                  className={`px-3 py-1.5 rounded text-sm transition ${filterStatus === 'disabled' ? 'bg-primary-500 text-dark-900 dark:text-white' : 'text-dark-400 hover:text-dark-900 dark:text-white'
                    }`}
                >
                  Disabled
                </button>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => setShowHelperModal(true)}
                className="flex items-center gap-2 bg-purple-500 hover:bg-purple-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors"
              >
                <Wand2 className="w-4 h-4" />
                Rule Helper
              </button>
              <button
                onClick={() => { resetForm(); setEditingRule(null); setShowRuleModal(true); }}
                className="flex items-center gap-2 bg-green-500 hover:bg-green-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add Rule
              </button>
            </div>
          </div>

          {/* Rules Table */}
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead className="bg-dark-700">
                <tr>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Priority</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Name</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Action</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Protocol</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Source → Dest</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Port</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Hits</th>
                  <th className="text-left px-4 py-3 text-dark-300 font-medium text-sm">Status</th>
                  <th className="text-right px-4 py-3 text-dark-300 font-medium text-sm">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-dark-400">
                      No rules found. Click "Add Rule" to create one.
                    </td>
                  </tr>
                ) : (
                  filteredRules.map((rule) => (
                    <tr
                      key={rule.id}
                      className={`border-t border-dark-200 dark:border-dark-700 hover:bg-dark-700/50 ${!rule.enabled ? 'opacity-50' : ''}`}
                    >
                      <td className="px-4 py-3 text-dark-900 dark:text-white text-sm">{rule.priority}</td>
                      <td className="px-4 py-3 text-dark-900 dark:text-white font-medium text-sm">{rule.name}</td>
                      <td className="px-4 py-3">
                        <span className={`flex items-center gap-1 text-sm ${rule.action === 'ALLOW' ? 'text-green-400' :
                            rule.action === 'BLOCK' ? 'text-red-400' :
                              'text-yellow-400'
                          }`}>
                          {rule.action === 'ALLOW' ? <Check className="w-4 h-4" /> :
                            rule.action === 'BLOCK' ? <Ban className="w-4 h-4" /> :
                              <AlertTriangle className="w-4 h-4" />}
                          {rule.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-dark-300 uppercase text-xs">{rule.protocol}</td>
                      <td className="px-4 py-3 text-dark-300 font-mono text-xs">
                        <div className="flex items-center gap-1">
                          <span className="truncate max-w-[60px]">{rule.srcIp || '*'}</span>
                          <ArrowRight className="w-3 h-3 text-dark-500" />
                          <span className="truncate max-w-[60px]">{rule.dstIp || '*'}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-dark-300 font-mono text-sm">{rule.dstPort || '*'}</td>
                      <td className="px-4 py-3 text-dark-400 text-sm">{rule.hitCount?.toLocaleString() || 0}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleToggleRule(rule.id)}
                          className={`p-1.5 rounded transition ${rule.enabled ? 'text-green-400 hover:bg-green-900/30' : 'text-dark-500 hover:bg-dark-600'
                            }`}
                        >
                          {rule.enabled ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => handleEditRule(rule)}
                            className="p-1.5 text-primary-400 hover:bg-primary-900/30 rounded transition"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteRule(rule.id)}
                            className="p-1.5 text-red-400 hover:bg-red-900/30 rounded transition"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Packet Monitor Tab */}
      {activeTab === 'monitor' && (
        <div className="bg-white dark:bg-dark-800 rounded-xl border border-dark-200 dark:border-dark-700">
          <div className="p-4 border-b border-dark-200 dark:border-dark-700 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-dark-900 dark:text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-primary-400" />
              Live Packet Stream
            </h3>
            <span className="text-sm text-dark-400 flex items-center gap-1">
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
              Updates every 3 seconds
            </span>
          </div>
          <div className="overflow-auto max-h-[500px]">
            <table className="w-full text-sm">
              <thead className="bg-dark-700 sticky top-0">
                <tr>
                  <th className="px-4 py-2 text-left text-dark-400 font-medium">Time</th>
                  <th className="px-4 py-2 text-left text-dark-400 font-medium">Source IP</th>
                  <th className="px-4 py-2 text-left text-dark-400 font-medium">Destination</th>
                  <th className="px-4 py-2 text-left text-dark-400 font-medium">Protocol</th>
                  <th className="px-4 py-2 text-left text-dark-400 font-medium">Action</th>
                  <th className="px-4 py-2 text-left text-dark-400 font-medium">Rule</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-700">
                {packetLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-dark-400">
                      No packet logs yet. Packets will appear here as they are processed.
                    </td>
                  </tr>
                ) : (
                  packetLogs.map(log => (
                    <tr key={log.id} className="hover:bg-dark-700/50">
                      <td className="px-4 py-2 text-dark-300">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-2 font-mono text-dark-300">{log.srcIp}</td>
                      <td className="px-4 py-2 font-mono text-dark-300">{log.dstIp}:{log.dstPort}</td>
                      <td className="px-4 py-2">
                        <span className="px-2 py-0.5 bg-dark-600 rounded text-xs">{log.protocol}</span>
                      </td>
                      <td className="px-4 py-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${log.action === 'ALLOW' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
                          }`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-dark-400">{log.rule}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Device Policies Tab */}
      {activeTab === 'devices' && (
        <div className="bg-white dark:bg-dark-800 rounded-xl border border-dark-200 dark:border-dark-700">
          <div className="p-4 border-b border-dark-200 dark:border-dark-700">
            <h3 className="text-lg font-semibold text-dark-900 dark:text-white">Device-Specific Policies</h3>
            <p className="text-sm text-dark-400 mt-1">Apply firewall rules based on device trust level</p>
          </div>
          <div className="overflow-auto">
            <table className="w-full">
              <thead className="bg-dark-700">
                <tr>
                  <th className="px-4 py-3 text-left text-dark-300 font-medium text-sm">MAC Address</th>
                  <th className="px-4 py-3 text-left text-dark-300 font-medium text-sm">IP Address</th>
                  <th className="px-4 py-3 text-left text-dark-300 font-medium text-sm">Hostname</th>
                  <th className="px-4 py-3 text-left text-dark-300 font-medium text-sm">Trust Level</th>
                  <th className="px-4 py-3 text-left text-dark-300 font-medium text-sm">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-700">
                {devices.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-dark-400">
                      No devices found. Devices will appear here when they connect.
                    </td>
                  </tr>
                ) : (
                  devices.map(device => (
                    <tr key={device.mac} className="hover:bg-dark-700/50">
                      <td className="px-4 py-3 font-mono text-sm text-dark-300">{device.mac}</td>
                      <td className="px-4 py-3 font-mono text-sm text-dark-300">{device.ip}</td>
                      <td className="px-4 py-3 text-sm text-dark-900 dark:text-white">{device.hostname || 'Unknown'}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${device.trustStatus === 'TRUSTED' ? 'bg-green-900/50 text-green-300' :
                            device.trustStatus === 'UNTRUSTED' ? 'bg-yellow-900/50 text-yellow-300' :
                              'bg-red-900/50 text-red-300'
                          }`}>
                          {device.trustStatus}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button className="px-3 py-1.5 bg-primary-500 hover:bg-primary-600 rounded text-sm transition text-dark-900 dark:text-white">
                          Configure Policy
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Rule Helper Modal */}
      {showHelperModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-2xl w-full max-w-2xl">
            <div className="flex items-center justify-between p-6 border-b border-dark-200 dark:border-dark-700">
              <div>
                <h2 className="text-xl font-bold text-dark-900 dark:text-white">Rule Helper</h2>
                <p className="text-dark-400 text-sm">Choose a template to get started</p>
              </div>
              <button onClick={() => setShowHelperModal(false)} className="p-2 text-dark-400 hover:text-dark-900 dark:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 grid grid-cols-2 gap-4">
              {rulePresets.map((preset) => (
                <button
                  key={preset.id}
                  onClick={() => applyPreset(preset)}
                  className="text-left p-4 bg-dark-700 hover:bg-dark-600 border border-dark-300 dark:border-dark-600 hover:border-primary-500/50 rounded-xl transition-all"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-dark-900 dark:text-white font-medium">{preset.name}</span>
                    <ChevronRight className="w-4 h-4 text-dark-400" />
                  </div>
                  <p className="text-dark-400 text-sm">{preset.description}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Add/Edit Rule Modal */}
      {showRuleModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-auto">
            <div className="flex items-center justify-between p-6 border-b border-dark-200 dark:border-dark-700">
              <h2 className="text-xl font-bold text-dark-900 dark:text-white">
                {editingRule ? 'Edit Rule' : 'Add New Rule'}
              </h2>
              <button
                onClick={() => { setShowRuleModal(false); setEditingRule(null); resetForm(); }}
                className="p-2 text-dark-400 hover:text-dark-900 dark:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 grid grid-cols-2 gap-6">
              {/* Form Fields */}
              <div className="space-y-4">
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Rule Name *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                    placeholder="e.g., Block Malicious IPs"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Action</label>
                    <select
                      value={formData.action}
                      onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                    >
                      {actionOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Protocol</label>
                    <select
                      value={formData.protocol}
                      onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                    >
                      {protocolOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Source IP / CIDR</label>
                    <input
                      type="text"
                      value={formData.srcIp}
                      onChange={(e) => setFormData({ ...formData, srcIp: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                      placeholder="* or 192.168.1.0/24"
                    />
                  </div>
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Source Port</label>
                    <input
                      type="text"
                      value={formData.srcPort}
                      onChange={(e) => setFormData({ ...formData, srcPort: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                      placeholder="* or 1024-65535"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Destination IP / CIDR</label>
                    <input
                      type="text"
                      value={formData.dstIp}
                      onChange={(e) => setFormData({ ...formData, dstIp: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                      placeholder="* or 10.0.0.1"
                    />
                  </div>
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Destination Port</label>
                    <input
                      type="text"
                      value={formData.dstPort}
                      onChange={(e) => setFormData({ ...formData, dstPort: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                      placeholder="* or 80,443"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Device MAC (optional)</label>
                    <input
                      type="text"
                      value={formData.deviceMac}
                      onChange={(e) => setFormData({ ...formData, deviceMac: e.target.value })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                      placeholder="* or AA:BB:CC:DD:EE:FF"
                    />
                  </div>
                  <div>
                    <label className="block text-dark-400 text-sm mb-2">Priority (1-1000)</label>
                    <input
                      type="number"
                      value={formData.priority}
                      onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
                      className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                      min="1"
                      max="1000"
                    />
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="enabled"
                    checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                    className="w-4 h-4 rounded border-dark-300 dark:border-dark-600 bg-dark-50 dark:bg-dark-900 text-primary-500 focus:ring-primary-500"
                  />
                  <label htmlFor="enabled" className="text-dark-300 text-sm">Enable rule immediately</label>
                </div>
              </div>

              {/* Preview */}
              <div className="space-y-4">
                <div className="bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg p-4">
                  <div className="text-dark-400 text-sm mb-2">Generated Command:</div>
                  <pre className="text-green-400 font-mono text-sm whitespace-pre-wrap break-all">
                    {generateIptablesRule()}
                  </pre>
                </div>

                <div className="bg-dark-700/50 rounded-lg p-4">
                  <div className="text-dark-400 text-sm mb-3">Rule Summary:</div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-dark-400">Action:</span>
                      <span className={`font-medium ${formData.action === 'ALLOW' ? 'text-green-400' : 'text-red-400'
                        }`}>{formData.action}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-dark-400">Protocol:</span>
                      <span className="text-dark-900 dark:text-white">{formData.protocol}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-dark-400">Source:</span>
                      <span className="text-dark-900 dark:text-white font-mono">{formData.srcIp || '*'}:{formData.srcPort || '*'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-dark-400">Destination:</span>
                      <span className="text-dark-900 dark:text-white font-mono">{formData.dstIp || '*'}:{formData.dstPort || '*'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-dark-400">Priority:</span>
                      <span className="text-dark-900 dark:text-white">{formData.priority}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-dark-200 dark:border-dark-700 flex gap-3">
              <button
                onClick={editingRule ? handleUpdateRule : handleAddRule}
                disabled={!formData.name}
                className="flex-1 py-3 bg-primary-500 hover:bg-primary-600 disabled:bg-dark-600 disabled:cursor-not-allowed text-dark-900 dark:text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <Save className="w-4 h-4" />
                {editingRule ? 'Update Rule' : 'Create Rule'}
              </button>
              <button
                onClick={() => { setShowRuleModal(false); setEditingRule(null); resetForm(); }}
                className="flex-1 py-3 bg-dark-700 hover:bg-dark-600 text-dark-900 dark:text-white font-medium rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
