import { useState } from 'react';
import { Search, Filter, Download, ChevronLeft, ChevronRight } from 'lucide-react';

const mockIndicators = [
  { id: 1, type: 'ip', value: '192.168.1.100', score: 95, severity: 'critical', source: 'AlienVault OTX', firstSeen: '2024-01-10', lastSeen: '2024-01-15', active: true },
  { id: 2, type: 'domain', value: 'malware-c2.evil.com', score: 88, severity: 'high', source: 'Abuse.ch', firstSeen: '2024-01-08', lastSeen: '2024-01-15', active: true },
  { id: 3, type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e', score: 75, severity: 'medium', source: 'VirusTotal', firstSeen: '2024-01-05', lastSeen: '2024-01-12', active: true },
  { id: 4, type: 'ip', value: '10.0.0.50', score: 62, severity: 'medium', source: 'Emerging Threats', firstSeen: '2024-01-01', lastSeen: '2024-01-14', active: true },
  { id: 5, type: 'url', value: 'http://evil.com/malware.exe', score: 92, severity: 'critical', source: 'URLhaus', firstSeen: '2024-01-12', lastSeen: '2024-01-15', active: true },
  { id: 6, type: 'domain', value: 'phishing-site.example', score: 45, severity: 'low', source: 'PhishTank', firstSeen: '2024-01-02', lastSeen: '2024-01-10', active: false },
];

const typeFilters = ['All', 'IP', 'Domain', 'Hash', 'URL'];
const severityFilters = ['All', 'Critical', 'High', 'Medium', 'Low'];

export default function Indicators() {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('All');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [currentPage, setCurrentPage] = useState(1);

  const filteredIndicators = mockIndicators.filter(ind => {
    const matchesSearch = ind.value.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === 'All' || ind.type.toUpperCase() === typeFilter.toUpperCase();
    const matchesSeverity = severityFilter === 'All' || ind.severity.toLowerCase() === severityFilter.toLowerCase();
    return matchesSearch && matchesType && matchesSeverity;
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Indicators</h1>
        <button className="flex items-center gap-2 bg-dark-700 hover:bg-dark-600 text-dark-300 px-4 py-2 rounded-lg transition-colors">
          <Download className="w-4 h-4" />
          Export
        </button>
      </div>

      {/* Filters */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 mb-6">
        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input
              type="text"
              placeholder="Search indicators..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>

          {/* Type Filter */}
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-dark-400" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              {typeFilters.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            {severityFilters.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* Results Count */}
      <div className="text-dark-400 text-sm mb-4">
        Showing {filteredIndicators.length} of {mockIndicators.length} indicators
      </div>

      {/* Table */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-dark-700">
              <tr>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">Type</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">Value</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">Severity</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">Score</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">Source</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">First Seen</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium text-sm">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredIndicators.map((ind) => (
                <tr key={ind.id} className="border-t border-dark-700 hover:bg-dark-700/50 cursor-pointer">
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      ind.type === 'ip' ? 'bg-blue-500/20 text-blue-400' :
                      ind.type === 'domain' ? 'bg-purple-500/20 text-purple-400' :
                      ind.type === 'hash' ? 'bg-green-500/20 text-green-400' :
                      'bg-orange-500/20 text-orange-400'
                    }`}>
                      {ind.type.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <code className="text-white font-mono text-sm">{ind.value}</code>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      ind.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      ind.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      ind.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {ind.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-2 bg-dark-600 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${
                            ind.score >= 80 ? 'bg-red-500' :
                            ind.score >= 60 ? 'bg-orange-500' :
                            ind.score >= 40 ? 'bg-yellow-500' :
                            'bg-green-500'
                          }`}
                          style={{ width: `${ind.score}%` }}
                        />
                      </div>
                      <span className="text-white text-sm w-6">{ind.score}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-dark-300">{ind.source}</td>
                  <td className="px-6 py-4 text-dark-400">{ind.firstSeen}</td>
                  <td className="px-6 py-4">
                    <span className={`flex items-center gap-2 ${ind.active ? 'text-green-400' : 'text-dark-500'}`}>
                      <span className={`w-2 h-2 rounded-full ${ind.active ? 'bg-green-400' : 'bg-dark-500'}`} />
                      {ind.active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-6 py-4 border-t border-dark-700 flex items-center justify-between">
          <span className="text-dark-400 text-sm">Page {currentPage} of 1</span>
          <div className="flex items-center gap-2">
            <button 
              disabled
              className="p-2 text-dark-500 rounded-lg"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button 
              disabled
              className="p-2 text-dark-500 rounded-lg"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
