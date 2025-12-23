import { 
  Shield, 
  Globe, 
  Hash, 
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Activity
} from 'lucide-react';

const stats = [
  { label: 'Total IPs', value: '95,847', change: '+12.5%', positive: true, icon: Globe, color: 'blue' },
  { label: 'Total Domains', value: '45,231', change: '+8.2%', positive: true, icon: Globe, color: 'purple' },
  { label: 'Total Hashes', value: '102,456', change: '+15.1%', positive: true, icon: Hash, color: 'green' },
  { label: 'Active Threats', value: '17,225', change: '-5.3%', positive: true, icon: AlertTriangle, color: 'red' },
];

const recentThreats = [
  { id: 1, type: 'ip', value: '192.168.1.100', severity: 'critical', score: 95, source: 'AlienVault OTX', firstSeen: '2h ago' },
  { id: 2, type: 'domain', value: 'malware-c2.evil.com', severity: 'high', score: 88, source: 'Abuse.ch', firstSeen: '4h ago' },
  { id: 3, type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e', severity: 'medium', score: 65, source: 'VirusTotal', firstSeen: '6h ago' },
  { id: 4, type: 'ip', value: '10.0.0.50', severity: 'low', score: 35, source: 'Emerging Threats', firstSeen: '12h ago' },
];

export default function ThreatIntelDashboard() {
  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Threat Intelligence Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.label}
              className="bg-dark-800 border border-dark-700 rounded-xl p-5"
            >
              <div className="flex items-center justify-between mb-3">
                <div className={`p-2 rounded-lg bg-${stat.color}-500/20`}>
                  <Icon className={`w-5 h-5 text-${stat.color}-400`} />
                </div>
                <div className={`flex items-center gap-1 text-sm ${stat.positive ? 'text-green-400' : 'text-red-400'}`}>
                  {stat.positive ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
                  {stat.change}
                </div>
              </div>
              <div className="text-2xl font-bold text-white mb-1">{stat.value}</div>
              <div className="text-dark-400 text-sm">{stat.label}</div>
            </div>
          );
        })}
      </div>

      {/* Recent Threats Table */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl">
        <div className="px-6 py-4 border-b border-dark-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Recent Threats</h2>
          <Activity className="w-5 h-5 text-green-400 animate-pulse" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-dark-700/50">
              <tr>
                <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Type</th>
                <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Value</th>
                <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Severity</th>
                <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Score</th>
                <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">Source</th>
                <th className="text-left px-6 py-3 text-dark-300 font-medium text-sm">First Seen</th>
              </tr>
            </thead>
            <tbody>
              {recentThreats.map((threat) => (
                <tr key={threat.id} className="border-t border-dark-700 hover:bg-dark-700/50">
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      threat.type === 'ip' ? 'bg-blue-500/20 text-blue-400' :
                      threat.type === 'domain' ? 'bg-purple-500/20 text-purple-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {threat.type.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <code className="text-white font-mono text-sm">{threat.value}</code>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      threat.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      threat.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      threat.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {threat.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-dark-600 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${
                            threat.score >= 80 ? 'bg-red-500' :
                            threat.score >= 60 ? 'bg-orange-500' :
                            threat.score >= 40 ? 'bg-yellow-500' :
                            'bg-green-500'
                          }`}
                          style={{ width: `${threat.score}%` }}
                        />
                      </div>
                      <span className="text-white text-sm">{threat.score}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-dark-300">{threat.source}</td>
                  <td className="px-6 py-4 text-dark-400">{threat.firstSeen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
