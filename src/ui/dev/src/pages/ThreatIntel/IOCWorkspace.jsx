import { useState } from 'react';
import { 
  Shield, 
  Upload, 
  Play, 
  AlertCircle, 
  CheckCircle, 
  HelpCircle,
  Download,
  Database,
  Loader2
} from 'lucide-react';

// Available databases for comparison
const availableDatabases = [
  { id: 'ip_blacklist', name: 'IP Blacklist', records: '95,847', type: 'internal' },
  { id: 'domain_blocklist', name: 'Domain Blocklist', records: '45,231', type: 'internal' },
  { id: 'hash_database', name: 'Hash Database', records: '102,456', type: 'internal' },
  { id: 'tor_exit_nodes', name: 'TOR Exit Nodes', records: '1,247', type: 'internal' },
  { id: 'proxy_vpn', name: 'Proxy/VPN IPs', records: '12,385', type: 'internal' },
  { id: 'geo_data', name: 'GeoIP Database', records: '4.2M', type: 'internal' },
  { id: 'custom_db', name: 'Custom Database', records: '-', type: 'custom', placeholder: true },
];

// Mock comparison results
const mockResults = [
  { ioc: '192.168.1.100', type: 'ip', status: 'malicious', score: 95, severity: 'critical', sources: ['IP Blacklist', 'TOR Exit'], description: 'Known C2 Server' },
  { ioc: 'malware-c2.evil.com', type: 'domain', status: 'malicious', score: 88, severity: 'high', sources: ['Domain Blocklist'], description: 'Malware distribution' },
  { ioc: 'google.com', type: 'domain', status: 'clean', score: 0, severity: null, sources: [], description: null },
  { ioc: '8.8.8.8', type: 'ip', status: 'clean', score: 0, severity: null, sources: [], description: null },
  { ioc: 'unknown-hash-123', type: 'hash', status: 'unknown', score: null, severity: null, sources: [], description: null },
];

export default function IOCWorkspace() {
  const [input, setInput] = useState('');
  const [selectedDatabases, setSelectedDatabases] = useState(['ip_blacklist', 'domain_blocklist', 'hash_database']);
  const [customDbName, setCustomDbName] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCompare = async () => {
    if (!input.trim()) return;
    
    setLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500));
    setResults({
      items: mockResults,
      summary: {
        total: 5,
        malicious: 2,
        clean: 2,
        unknown: 1,
      }
    });
    setLoading(false);
  };

  const toggleDatabase = (id) => {
    setSelectedDatabases(prev => 
      prev.includes(id) ? prev.filter(d => d !== id) : [...prev, id]
    );
  };

  const maliciousCount = results?.summary?.malicious || 0;

  return (
    <div>
      <h1 className="text-2xl font-bold text-dark-900 dark:text-white mb-6">IOC Workspace</h1>

      {/* Alert Banner */}
      {maliciousCount > 0 && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-6 flex items-center gap-3 animate-fade-in">
          <AlertCircle className="w-6 h-6 text-red-400" />
          <div>
            <div className="font-bold text-red-400">
              {maliciousCount} malicious indicator{maliciousCount > 1 ? 's' : ''} detected!
            </div>
            <div className="text-red-300/70 text-sm">
              Review the results below for details
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Input Panel */}
        <div className="lg:col-span-2 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-dark-900 dark:text-white mb-4">Input IOCs</h2>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste IOCs here (one per line)&#10;Supports: IPs, Domains, URLs, Hashes (MD5, SHA1, SHA256)&#10;&#10;Example:&#10;192.168.1.100&#10;malware-c2.evil.com&#10;d41d8cd98f00b204e9800998ecf8427e"
            className="w-full h-48 px-4 py-3 bg-dark-50 dark:bg-dark-900 border border-dark-300 dark:border-dark-600 rounded-lg text-dark-900 dark:text-white font-mono text-sm placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
          />
          <div className="flex items-center gap-4 mt-4">
            <button className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-300 rounded-lg transition-colors">
              <Upload className="w-4 h-4" />
              Upload File
            </button>
            <span className="text-dark-500 text-sm">
              Supports .txt, .csv files
            </span>
          </div>
        </div>

        {/* Database Selection */}
        <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-dark-900 dark:text-white mb-4 flex items-center gap-2">
            <Database className="w-5 h-5" />
            Select Databases
          </h2>
          <div className="space-y-3">
            {availableDatabases.map((db) => (
              <label
                key={db.id}
                className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                  db.placeholder ? 'bg-dark-700/50 border border-dashed border-dark-300 dark:border-dark-600' : 'hover:bg-dark-700'
                }`}
              >
                {db.placeholder ? (
                  <input
                    type="text"
                    placeholder="Enter database name..."
                    value={customDbName}
                    onChange={(e) => setCustomDbName(e.target.value)}
                    className="flex-1 bg-transparent border-none text-dark-900 dark:text-white placeholder-dark-500 focus:outline-none text-sm"
                  />
                ) : (
                  <>
                    <input
                      type="checkbox"
                      checked={selectedDatabases.includes(db.id)}
                      onChange={() => toggleDatabase(db.id)}
                      className="w-4 h-4 rounded border-dark-500 bg-dark-50 dark:bg-dark-900 text-primary-500 focus:ring-primary-500"
                    />
                    <div className="flex-1">
                      <div className="text-dark-900 dark:text-white text-sm">{db.name}</div>
                      <div className="text-dark-500 text-xs">{db.records} records</div>
                    </div>
                  </>
                )}
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* Run Button */}
      <button
        onClick={handleCompare}
        disabled={loading || !input.trim()}
        className="w-full py-4 bg-primary-500 hover:bg-primary-600 disabled:bg-primary-500/50 disabled:cursor-not-allowed text-dark-900 dark:text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2 mb-6"
      >
        {loading ? (
          <>
            <Loader2 className="w-5 h-5 animate-spin" />
            Comparing...
          </>
        ) : (
          <>
            <Play className="w-5 h-5" />
            Run Comparison
          </>
        )}
      </button>

      {/* Results */}
      {results && (
        <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden animate-fade-in">
          {/* Summary */}
          <div className="px-6 py-4 border-b border-dark-200 dark:border-dark-700 flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-red-400" />
                <span className="text-red-400 font-medium">{results.summary.malicious} Malicious</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span className="text-green-400 font-medium">{results.summary.clean} Clean</span>
              </div>
              <div className="flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-dark-400" />
                <span className="text-dark-400 font-medium">{results.summary.unknown} Unknown</span>
              </div>
            </div>
            <button className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-300 rounded-lg transition-colors">
              <Download className="w-4 h-4" />
              Export
            </button>
          </div>

          {/* Results Table */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-dark-700/50">
                <tr>
                  <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">IOC</th>
                  <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Type</th>
                  <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Status</th>
                  <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Score</th>
                  <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Matched Sources</th>
                </tr>
              </thead>
              <tbody>
                {results.items.map((item, idx) => (
                  <tr key={idx} className="border-t border-dark-200 dark:border-dark-700 hover:bg-dark-700/50">
                    <td className="px-6 py-4">
                      <code className="text-dark-900 dark:text-white font-mono text-sm">{item.ioc}</code>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-dark-300 uppercase text-xs">{item.type}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        item.status === 'malicious' ? 'bg-red-500/20 text-red-400' :
                        item.status === 'clean' ? 'bg-green-500/20 text-green-400' :
                        'bg-dark-600 text-dark-400'
                      }`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {item.score !== null ? (
                        <span className={`font-medium ${
                          item.score >= 80 ? 'text-red-400' :
                          item.score >= 60 ? 'text-orange-400' :
                          item.score >= 40 ? 'text-yellow-400' :
                          'text-green-400'
                        }`}>
                          {item.score}
                        </span>
                      ) : (
                        <span className="text-dark-500">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-dark-300">
                      {item.sources.length > 0 ? item.sources.join(', ') : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
