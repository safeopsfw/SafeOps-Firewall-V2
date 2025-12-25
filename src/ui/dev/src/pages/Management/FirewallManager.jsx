import { useState } from 'react';
import { 
  Search, 
  Plus, 
  Shield,
  CheckCircle,
  Save,
  Trash2,
  Wand2,
  X,
  ChevronRight,
  ArrowRight,
  ArrowLeft,
  Ban,
  Check,
  AlertTriangle
} from 'lucide-react';

// Mock firewall rules
const mockRules = [
  { id: 1, name: 'Block Malicious IPs', action: 'drop', proto: 'any', src: 'blacklist_ips', dst: 'any', port: 'any', status: 'active', hits: 45231 },
  { id: 2, name: 'Allow SSH from Admin', action: 'accept', proto: 'tcp', src: '10.0.0.0/24', dst: 'any', port: '22', status: 'active', hits: 1234 },
  { id: 3, name: 'Block TOR Exit Nodes', action: 'drop', proto: 'any', src: 'tor_exit_nodes', dst: 'any', port: 'any', status: 'active', hits: 5678 },
  { id: 4, name: 'Allow HTTP/HTTPS', action: 'accept', proto: 'tcp', src: 'any', dst: '$WEB_SERVERS', port: '80,443', status: 'active', hits: 892345 },
  { id: 5, name: 'Block Suspicious Ports', action: 'drop', proto: 'tcp', src: 'any', dst: 'any', port: '4444,5555,6666', status: 'staging', hits: 0 },
];

// Rule presets
const rulePresets = [
  { id: 'block_ip', name: 'Block IP Address', description: 'Block traffic from specific IP or range' },
  { id: 'allow_port', name: 'Allow Port', description: 'Allow traffic on specific port' },
  { id: 'block_country', name: 'Block Country', description: 'Block traffic from specific country' },
  { id: 'rate_limit', name: 'Rate Limit', description: 'Limit connections per IP' },
  { id: 'whitelist', name: 'Whitelist IP', description: 'Allow traffic from trusted IP' },
  { id: 'block_port', name: 'Block Port', description: 'Block traffic on specific port' },
];

const actionOptions = ['accept', 'drop', 'reject', 'log'];
const protocolOptions = ['any', 'tcp', 'udp', 'icmp'];

export default function FirewallManager() {
  const [rules, setRules] = useState(mockRules);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('rules'); // 'rules' | 'builder'
  const [showHelperModal, setShowHelperModal] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  
  // Builder form state
  const [builderForm, setBuilderForm] = useState({
    name: '',
    action: 'drop',
    protocol: 'any',
    sourceType: 'ip', // 'ip', 'cidr', 'list'
    source: '',
    destType: 'any',
    dest: '',
    port: 'any',
    description: ''
  });

  const filteredRules = rules.filter(rule => 
    rule.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const applyPreset = (preset) => {
    const presetDefaults = {
      block_ip: { name: 'Block IP - ', action: 'drop', protocol: 'any', port: 'any' },
      allow_port: { name: 'Allow Port - ', action: 'accept', protocol: 'tcp', port: '' },
      block_country: { name: 'Block Country - ', action: 'drop', protocol: 'any', sourceType: 'list' },
      rate_limit: { name: 'Rate Limit - ', action: 'drop', protocol: 'tcp' },
      whitelist: { name: 'Whitelist - ', action: 'accept', protocol: 'any', port: 'any' },
      block_port: { name: 'Block Port - ', action: 'drop', protocol: 'tcp', port: '' },
    };
    
    setBuilderForm(prev => ({
      ...prev,
      ...presetDefaults[preset.id]
    }));
    setShowHelperModal(false);
    setActiveTab('builder');
  };

  const generateIptablesRule = () => {
    const action = builderForm.action === 'accept' ? 'ACCEPT' : 
                   builderForm.action === 'drop' ? 'DROP' : 
                   builderForm.action === 'reject' ? 'REJECT' : 'LOG';
    
    let rule = 'iptables -A INPUT';
    
    if (builderForm.protocol !== 'any') {
      rule += ` -p ${builderForm.protocol}`;
    }
    
    if (builderForm.source && builderForm.source !== 'any') {
      rule += ` -s ${builderForm.source}`;
    }
    
    if (builderForm.dest && builderForm.dest !== 'any') {
      rule += ` -d ${builderForm.dest}`;
    }
    
    if (builderForm.port && builderForm.port !== 'any') {
      rule += ` --dport ${builderForm.port}`;
    }
    
    rule += ` -j ${action}`;
    
    if (builderForm.name) {
      rule += ` -m comment --comment "${builderForm.name}"`;
    }
    
    return rule;
  };

  const addRule = () => {
    if (!builderForm.name) return;
    
    const newRule = {
      id: Date.now(),
      name: builderForm.name,
      action: builderForm.action,
      proto: builderForm.protocol,
      src: builderForm.source || 'any',
      dst: builderForm.dest || 'any',
      port: builderForm.port || 'any',
      status: 'staging',
      hits: 0
    };
    
    setRules([...rules, newRule]);
    setBuilderForm({
      name: '', action: 'drop', protocol: 'any', sourceType: 'ip',
      source: '', destType: 'any', dest: '', port: 'any', description: ''
    });
    setActiveTab('rules');
  };

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Firewall Manager</h1>
          <p className="text-dark-400">iptables-compatible firewall rules</p>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => setShowHelperModal(true)}
            className="flex items-center gap-2 bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded-lg transition-colors"
          >
            <Wand2 className="w-4 h-4" />
            Rule Helper
          </button>
          <button 
            onClick={() => setActiveTab('builder')}
            className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-white px-4 py-2 rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Custom Rule
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-dark-700">
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'rules'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-white'
          }`}
        >
          <Shield className="w-4 h-4 inline mr-2" />
          Active Rules
        </button>
        <button
          onClick={() => setActiveTab('builder')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'builder'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-white'
          }`}
        >
          <Wand2 className="w-4 h-4 inline mr-2" />
          Rule Builder
        </button>
      </div>

      {activeTab === 'rules' && (
        <>
          {/* Search */}
          <div className="relative mb-4 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input
              type="text"
              placeholder="Search rules..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>

          {/* Rules Table */}
          <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead className="bg-dark-700">
                <tr>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Rule Name</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Action</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Protocol</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Source → Dest</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Port</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Status</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Hits</th>
                  <th className="text-right px-6 py-4 text-dark-300 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule) => (
                  <tr key={rule.id} className="border-t border-dark-700 hover:bg-dark-700/50">
                    <td className="px-6 py-4 text-white font-medium">{rule.name}</td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-1 text-sm ${
                        rule.action === 'accept' ? 'text-green-400' :
                        rule.action === 'drop' ? 'text-red-400' :
                        'text-yellow-400'
                      }`}>
                        {rule.action === 'accept' ? <Check className="w-4 h-4" /> : 
                         rule.action === 'drop' ? <Ban className="w-4 h-4" /> :
                         <AlertTriangle className="w-4 h-4" />}
                        {rule.action.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-dark-300 uppercase text-sm">{rule.proto}</td>
                    <td className="px-6 py-4 text-dark-300 font-mono text-sm">
                      <div className="flex items-center gap-2">
                        <span className="truncate max-w-[80px]">{rule.src}</span>
                        <ArrowRight className="w-4 h-4 text-dark-500" />
                        <span className="truncate max-w-[80px]">{rule.dst}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-dark-300 font-mono">{rule.port}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        rule.status === 'active' ? 'bg-green-500/20 text-green-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {rule.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-dark-400">{rule.hits.toLocaleString()}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button className="p-2 text-dark-400 hover:text-white hover:bg-dark-600 rounded-lg">
                          <Shield className="w-4 h-4" />
                        </button>
                        <button className="p-2 text-dark-400 hover:text-red-400 hover:bg-dark-600 rounded-lg">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === 'builder' && (
        <div className="grid grid-cols-2 gap-6">
          {/* Builder Form */}
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-6">Rule Builder</h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-dark-400 text-sm mb-2">Rule Name *</label>
                <input 
                  type="text"
                  value={builderForm.name}
                  onChange={(e) => setBuilderForm({...builderForm, name: e.target.value})}
                  className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:ring-2 focus:ring-primary-500"
                  placeholder="Block Malicious IPs"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Action</label>
                  <select 
                    value={builderForm.action}
                    onChange={(e) => setBuilderForm({...builderForm, action: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:ring-2 focus:ring-primary-500"
                  >
                    {actionOptions.map(opt => <option key={opt} value={opt}>{opt.toUpperCase()}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Protocol</label>
                  <select 
                    value={builderForm.protocol}
                    onChange={(e) => setBuilderForm({...builderForm, protocol: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:ring-2 focus:ring-primary-500"
                  >
                    {protocolOptions.map(opt => <option key={opt} value={opt}>{opt.toUpperCase()}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-dark-400 text-sm mb-2">Source IP / CIDR</label>
                <input 
                  type="text"
                  value={builderForm.source}
                  onChange={(e) => setBuilderForm({...builderForm, source: e.target.value})}
                  className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:ring-2 focus:ring-primary-500"
                  placeholder="192.168.1.0/24 or any"
                />
              </div>

              <div>
                <label className="block text-dark-400 text-sm mb-2">Destination IP / CIDR</label>
                <input 
                  type="text"
                  value={builderForm.dest}
                  onChange={(e) => setBuilderForm({...builderForm, dest: e.target.value})}
                  className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:ring-2 focus:ring-primary-500"
                  placeholder="10.0.0.0/8 or any"
                />
              </div>

              <div>
                <label className="block text-dark-400 text-sm mb-2">Port(s)</label>
                <input 
                  type="text"
                  value={builderForm.port}
                  onChange={(e) => setBuilderForm({...builderForm, port: e.target.value})}
                  className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:ring-2 focus:ring-primary-500"
                  placeholder="80,443 or 1024:65535 or any"
                />
              </div>

              <button
                onClick={addRule}
                className="w-full py-3 bg-primary-500 hover:bg-primary-600 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <Save className="w-4 h-4" />
                Add Rule
              </button>
            </div>
          </div>

          {/* Preview */}
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-6">Generated Command</h2>
            
            <div className="bg-dark-900 border border-dark-600 rounded-lg p-4 mb-4">
              <div className="text-dark-400 text-sm mb-2">iptables Rule:</div>
              <pre className="text-green-400 font-mono text-sm whitespace-pre-wrap break-all">
                {generateIptablesRule()}
              </pre>
            </div>

            <div className="bg-dark-700/50 rounded-lg p-4">
              <div className="text-dark-400 text-sm mb-3">Quick Info:</div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-dark-400">Action:</span>
                  <span className={`font-medium ${
                    builderForm.action === 'accept' ? 'text-green-400' : 'text-red-400'
                  }`}>{builderForm.action.toUpperCase()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-dark-400">Protocol:</span>
                  <span className="text-white">{builderForm.protocol.toUpperCase()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-dark-400">Source:</span>
                  <span className="text-white font-mono">{builderForm.source || 'any'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-dark-400">Destination:</span>
                  <span className="text-white font-mono">{builderForm.dest || 'any'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-dark-400">Port:</span>
                  <span className="text-white font-mono">{builderForm.port || 'any'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Helper Modal */}
      {showHelperModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-dark-800 border border-dark-700 rounded-2xl w-full max-w-2xl">
            <div className="flex items-center justify-between p-6 border-b border-dark-700">
              <div>
                <h2 className="text-xl font-bold text-white">Rule Helper</h2>
                <p className="text-dark-400 text-sm">Choose a template</p>
              </div>
              <button onClick={() => setShowHelperModal(false)} className="p-2 text-dark-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 grid grid-cols-2 gap-4">
              {rulePresets.map((preset) => (
                <button
                  key={preset.id}
                  onClick={() => applyPreset(preset)}
                  className="text-left p-4 bg-dark-700 hover:bg-dark-600 border border-dark-600 hover:border-primary-500/50 rounded-xl transition-all"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">{preset.name}</span>
                    <ChevronRight className="w-4 h-4 text-dark-400" />
                  </div>
                  <p className="text-dark-400 text-sm">{preset.description}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
