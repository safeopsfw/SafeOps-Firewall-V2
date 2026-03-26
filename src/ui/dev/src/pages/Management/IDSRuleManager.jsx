import { useState } from 'react';
import { 
  Search, 
  Plus, 
  Play, 
  AlertTriangle, 
  CheckCircle,
  FileCode,
  FolderTree,
  Save,
  TestTube,
  History,
  Copy,
  Trash2,
  Wand2,
  X,
  ChevronRight,
  Info
} from 'lucide-react';

// Mock rule data
const mockRules = [
  { sid: '2019233', rev: 3, msg: 'ET MALWARE Cobalt Strike Beacon', category: 'custom', status: 'active', priority: 1, hits: 1234 },
  { sid: '2024897', rev: 1, msg: 'ET TROJAN Win32/Emotet CnC Activity', category: 'emerging-threats', status: 'staging', priority: 1, hits: 567 },
  { sid: '2100498', rev: 5, msg: 'GPL ATTACK_RESPONSE id check returned root', category: 'talos', status: 'active', priority: 2, hits: 89 },
  { sid: '2019876', rev: 2, msg: 'ET SCAN Suspicious inbound to Oracle SQL port', category: 'custom', status: 'disabled', priority: 3, hits: 2345 },
];

const ruleTree = {
  custom: { label: 'Custom Rules', count: 45 },
  'emerging-threats': { label: 'Emerging Threats', count: 1234 },
  'talos': { label: 'Talos', count: 892 },
  'abuse-ch': { label: 'Abuse.ch', count: 156 },
};

// Rule Helper Presets
const rulePresets = [
  { id: 'malware_c2', name: 'Malware C2 Detection', description: 'Detect command & control traffic' },
  { id: 'brute_force', name: 'Brute Force Attack', description: 'Detect login brute force attempts' },
  { id: 'sql_injection', name: 'SQL Injection', description: 'Detect SQL injection attempts' },
  { id: 'xss_attack', name: 'XSS Attack', description: 'Detect cross-site scripting' },
  { id: 'data_exfil', name: 'Data Exfiltration', description: 'Detect large outbound transfers' },
  { id: 'port_scan', name: 'Port Scan', description: 'Detect port scanning activity' },
];

const protocolOptions = ['tcp', 'udp', 'icmp', 'ip', 'http', 'dns', 'tls', 'ssh', 'ftp'];
const actionOptions = ['alert', 'drop', 'reject', 'pass', 'log'];
const classificationOptions = [
  'trojan-activity', 'web-application-attack', 'attempted-recon', 
  'attempted-admin', 'policy-violation', 'misc-activity', 'bad-unknown'
];

export default function IDSRuleManager() {
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedRule, setSelectedRule] = useState(mockRules[0]);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('editor'); // 'editor' | 'helper'
  const [showHelperModal, setShowHelperModal] = useState(false);
  
  // Helper form state
  const [helperForm, setHelperForm] = useState({
    preset: '',
    action: 'alert',
    protocol: 'tcp',
    sourceIP: 'any',
    sourcePort: 'any',
    destIP: '$HOME_NET',
    destPort: 'any',
    msg: '',
    content: '',
    contentModifiers: 'nocase',
    flowDirection: 'to_server',
    classification: 'trojan-activity',
    priority: 1,
    reference: ''
  });

  const [ruleContent, setRuleContent] = useState(
`alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET MALWARE Cobalt Strike Beacon";
  flow:established,to_server;
  content:"|00 00 00|";
  depth:3;
  content:"|00 04 00|";
  distance:0;
  within:3;
  classtype:trojan-activity;
  sid:2019233;
  rev:3;
  metadata:affected_product Any;
)`);

  const filteredRules = mockRules.filter(rule => {
    const matchesSearch = rule.msg.toLowerCase().includes(searchTerm.toLowerCase()) || 
      rule.sid.includes(searchTerm);
    const matchesCategory = selectedCategory === 'all' || rule.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Generate Suricata rule from helper form
  const generateRule = () => {
    const sid = Math.floor(9000000 + Math.random() * 1000000);
    const parts = [
      `${helperForm.action} ${helperForm.protocol} ${helperForm.sourceIP} ${helperForm.sourcePort} -> ${helperForm.destIP} ${helperForm.destPort} (`,
      `  msg:"${helperForm.msg}";`,
    ];
    
    if (helperForm.flowDirection) {
      parts.push(`  flow:established,${helperForm.flowDirection};`);
    }
    
    if (helperForm.content) {
      parts.push(`  content:"${helperForm.content}"; ${helperForm.contentModifiers};`);
    }
    
    parts.push(`  classtype:${helperForm.classification};`);
    parts.push(`  priority:${helperForm.priority};`);
    
    if (helperForm.reference) {
      parts.push(`  reference:cve,${helperForm.reference};`);
    }
    
    parts.push(`  sid:${sid};`);
    parts.push(`  rev:1;`);
    parts.push(`)`)
    
    return parts.join('\n');
  };

  const applyHelperRule = () => {
    const generatedRule = generateRule();
    setRuleContent(generatedRule);
    setShowHelperModal(false);
    setActiveTab('editor');
  };

  const selectPreset = (preset) => {
    const presetDefaults = {
      malware_c2: {
        msg: 'CUSTOM Malware C2 Communication Detected',
        protocol: 'tcp',
        destPort: 'any',
        content: '',
        classification: 'trojan-activity',
        priority: 1
      },
      brute_force: {
        msg: 'CUSTOM Brute Force Login Attempt',
        protocol: 'tcp',
        destPort: '22,23,3389',
        content: '',
        classification: 'attempted-admin',
        priority: 2
      },
      sql_injection: {
        msg: 'CUSTOM SQL Injection Attempt',
        protocol: 'http',
        destPort: '80,443,8080',
        content: 'SELECT',
        contentModifiers: 'nocase; http_uri',
        classification: 'web-application-attack',
        priority: 1
      },
      xss_attack: {
        msg: 'CUSTOM XSS Attack Attempt',
        protocol: 'http',
        destPort: '80,443',
        content: '<script>',
        contentModifiers: 'nocase; http_client_body',
        classification: 'web-application-attack',
        priority: 2
      },
      data_exfil: {
        msg: 'CUSTOM Large Outbound Data Transfer',
        protocol: 'tcp',
        sourceIP: '$HOME_NET',
        destIP: '$EXTERNAL_NET',
        flowDirection: 'to_server',
        classification: 'policy-violation',
        priority: 2
      },
      port_scan: {
        msg: 'CUSTOM Port Scan Detected',
        protocol: 'tcp',
        sourceIP: '$EXTERNAL_NET',
        destIP: '$HOME_NET',
        classification: 'attempted-recon',
        priority: 3
      }
    };
    
    setHelperForm(prev => ({
      ...prev,
      preset: preset.id,
      ...presetDefaults[preset.id]
    }));
  };

  return (
    <div className="animate-fade-in h-[calc(100vh-8rem)]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-dark-900 dark:text-white">IDS/IPS Rule Manager</h1>
          <p className="text-dark-400">Suricata-compatible detection rules</p>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => setShowHelperModal(true)}
            className="flex items-center gap-2 bg-purple-500 hover:bg-purple-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors"
          >
            <Wand2 className="w-4 h-4" />
            Rule Helper
          </button>
          <button className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors">
            <Plus className="w-4 h-4" />
            Custom Rule
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4 h-full">
        {/* Left Panel: Rule Library (30%) */}
        <div className="col-span-3 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden flex flex-col">
          {/* Search */}
          <div className="p-4 border-b border-dark-200 dark:border-dark-700">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
              <input
                type="text"
                placeholder="Search rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white text-sm placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>
          </div>

          {/* Tree View */}
          <div className="p-4 border-b border-dark-200 dark:border-dark-700">
            <div className="flex items-center gap-2 mb-3">
              <FolderTree className="w-4 h-4 text-dark-400" />
              <span className="text-dark-400 text-sm font-medium">Sources</span>
            </div>
            <div className="space-y-1">
              <button
                onClick={() => setSelectedCategory('all')}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm ${
                  selectedCategory === 'all' ? 'bg-primary-500/20 text-primary-400' : 'text-dark-300 hover:bg-dark-700'
                }`}
              >
                <span>All Rules</span>
                <span className="text-xs text-dark-500">{mockRules.length}</span>
              </button>
              {Object.entries(ruleTree).map(([key, value]) => (
                <button
                  key={key}
                  onClick={() => setSelectedCategory(key)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm ${
                    selectedCategory === key ? 'bg-primary-500/20 text-primary-400' : 'text-dark-300 hover:bg-dark-700'
                  }`}
                >
                  <span>{value.label}</span>
                  <span className="text-xs text-dark-500">{value.count}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Rule List */}
          <div className="flex-1 overflow-auto">
            {filteredRules.map((rule) => (
              <button
                key={rule.sid}
                onClick={() => setSelectedRule(rule)}
                className={`w-full text-left px-4 py-3 border-b border-dark-200 dark:border-dark-700 transition-colors ${
                  selectedRule?.sid === rule.sid ? 'bg-dark-700' : 'hover:bg-dark-700/50'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-dark-900 dark:text-white font-mono text-sm">SID:{rule.sid}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    rule.status === 'active' ? 'bg-green-500/20 text-green-400' :
                    rule.status === 'staging' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-dark-600 text-dark-400'
                  }`}>
                    {rule.status}
                  </span>
                </div>
                <div className="text-dark-300 text-sm truncate">{rule.msg}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Center Panel: Rule Editor (55%) */}
        <div className="col-span-7 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden flex flex-col">
          {/* Tabs */}
          <div className="flex border-b border-dark-200 dark:border-dark-700">
            <button
              onClick={() => setActiveTab('editor')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'editor' ? 'text-primary-400 border-b-2 border-primary-400 bg-dark-700/50' : 'text-dark-400 hover:text-dark-900 dark:text-white'
              }`}
            >
              <FileCode className="w-4 h-4 inline mr-2" />
              Rule Editor
            </button>
            <button
              onClick={() => setActiveTab('helper')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'helper' ? 'text-primary-400 border-b-2 border-primary-400 bg-dark-700/50' : 'text-dark-400 hover:text-dark-900 dark:text-white'
              }`}
            >
              <Wand2 className="w-4 h-4 inline mr-2" />
              Quick Builder
            </button>
          </div>

          {activeTab === 'editor' && (
            <>
              {/* Editor Header */}
              <div className="p-4 border-b border-dark-200 dark:border-dark-700 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-dark-900 dark:text-white font-semibold">SID: {selectedRule?.sid}</span>
                    <span className="text-dark-500 text-sm">rev:{selectedRule?.rev}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button className="p-2 text-dark-400 hover:text-dark-900 dark:text-white hover:bg-dark-700 rounded-lg">
                    <History className="w-4 h-4" />
                  </button>
                  <button className="p-2 text-dark-400 hover:text-dark-900 dark:text-white hover:bg-dark-700 rounded-lg">
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Code Editor */}
              <div className="flex-1 p-4">
                <textarea
                  value={ruleContent}
                  onChange={(e) => setRuleContent(e.target.value)}
                  className="w-full h-full bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg p-4 text-green-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
                  spellCheck={false}
                />
              </div>
            </>
          )}

          {activeTab === 'helper' && (
            <div className="flex-1 p-6 overflow-auto">
              {/* Quick Builder Form */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Action</label>
                  <select 
                    value={helperForm.action}
                    onChange={(e) => setHelperForm({...helperForm, action: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  >
                    {actionOptions.map(opt => <option key={opt} value={opt}>{opt.toUpperCase()}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Protocol</label>
                  <select 
                    value={helperForm.protocol}
                    onChange={(e) => setHelperForm({...helperForm, protocol: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  >
                    {protocolOptions.map(opt => <option key={opt} value={opt}>{opt.toUpperCase()}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Source IP</label>
                  <input 
                    type="text"
                    value={helperForm.sourceIP}
                    onChange={(e) => setHelperForm({...helperForm, sourceIP: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                    placeholder="$EXTERNAL_NET or any"
                  />
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Source Port</label>
                  <input 
                    type="text"
                    value={helperForm.sourcePort}
                    onChange={(e) => setHelperForm({...helperForm, sourcePort: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                    placeholder="any"
                  />
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Destination IP</label>
                  <input 
                    type="text"
                    value={helperForm.destIP}
                    onChange={(e) => setHelperForm({...helperForm, destIP: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                    placeholder="$HOME_NET"
                  />
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Destination Port</label>
                  <input 
                    type="text"
                    value={helperForm.destPort}
                    onChange={(e) => setHelperForm({...helperForm, destPort: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                    placeholder="80,443 or any"
                  />
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-dark-400 text-sm mb-2">Alert Message</label>
                <input 
                  type="text"
                  value={helperForm.msg}
                  onChange={(e) => setHelperForm({...helperForm, msg: e.target.value})}
                  className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  placeholder="CUSTOM Suspicious Activity Detected"
                />
              </div>

              <div className="mb-4">
                <label className="block text-dark-400 text-sm mb-2">Content Match (optional)</label>
                <input 
                  type="text"
                  value={helperForm.content}
                  onChange={(e) => setHelperForm({...helperForm, content: e.target.value})}
                  className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  placeholder="String to match in payload"
                />
              </div>

              <div className="grid grid-cols-2 gap-4 mb-6">
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Classification</label>
                  <select 
                    value={helperForm.classification}
                    onChange={(e) => setHelperForm({...helperForm, classification: e.target.value})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  >
                    {classificationOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-dark-400 text-sm mb-2">Priority</label>
                  <select 
                    value={helperForm.priority}
                    onChange={(e) => setHelperForm({...helperForm, priority: parseInt(e.target.value)})}
                    className="w-full px-3 py-2 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white focus:ring-2 focus:ring-primary-500"
                  >
                    <option value={1}>1 - Critical</option>
                    <option value={2}>2 - High</option>
                    <option value={3}>3 - Medium</option>
                    <option value={4}>4 - Low</option>
                  </select>
                </div>
              </div>

              {/* Preview */}
              <div className="bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg p-4 mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <Info className="w-4 h-4 text-primary-400" />
                  <span className="text-dark-400 text-sm">Generated Suricata Rule</span>
                </div>
                <pre className="text-green-400 font-mono text-sm whitespace-pre-wrap">{generateRule()}</pre>
              </div>

              <button
                onClick={applyHelperRule}
                className="w-full py-3 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white font-medium rounded-lg transition-colors"
              >
                Apply to Editor
              </button>
            </div>
          )}
        </div>

        {/* Right Panel: Actions (15%) */}
        <div className="col-span-2 space-y-4">
          {/* Status */}
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-4">
            <h3 className="text-dark-900 dark:text-white font-medium mb-3">Status</h3>
            <div className="space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="radio" name="status" defaultChecked className="accent-primary-500" />
                <span className="text-dark-300 text-sm">Staging</span>
              </label>
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="radio" name="status" className="accent-primary-500" />
                <span className="text-dark-300 text-sm">Production</span>
              </label>
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="radio" name="status" className="accent-primary-500" />
                <span className="text-dark-300 text-sm">Disabled</span>
              </label>
            </div>
          </div>

          {/* Actions */}
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-4 space-y-3">
            <button className="w-full flex items-center justify-center gap-2 bg-green-500 hover:bg-green-600 text-dark-900 dark:text-white py-2 rounded-lg">
              <CheckCircle className="w-4 h-4" />
              Validate
            </button>
            <button className="w-full flex items-center justify-center gap-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white py-2 rounded-lg">
              <Save className="w-4 h-4" />
              Save
            </button>
            <button className="w-full flex items-center justify-center gap-2 bg-dark-700 hover:bg-dark-600 text-dark-300 py-2 rounded-lg">
              <TestTube className="w-4 h-4" />
              Test
            </button>
          </div>

          {/* Validation */}
          <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center gap-2 text-green-400 mb-1">
              <CheckCircle className="w-4 h-4" />
              <span className="font-medium text-sm">Valid</span>
            </div>
            <p className="text-green-300/70 text-xs">Rule compiles OK</p>
          </div>
        </div>
      </div>

      {/* Rule Helper Modal */}
      {showHelperModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-2xl w-full max-w-2xl max-h-[80vh] overflow-auto">
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
                  onClick={() => { selectPreset(preset); setShowHelperModal(false); setActiveTab('helper'); }}
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
    </div>
  );
}
