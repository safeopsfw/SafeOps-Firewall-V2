import { useState } from 'react';
import { 
  Plus, 
  Play, 
  Pause, 
  RefreshCw, 
  Trash2, 
  Edit,
  CheckCircle,
  XCircle,
  Clock,
  ExternalLink
} from 'lucide-react';

const mockFeeds = [
  { 
    id: 1, 
    name: 'AlienVault OTX', 
    url: 'https://otx.alienvault.com/api/v1/pulses/subscribed',
    category: 'IOC',
    format: 'JSON',
    status: 'active',
    lastUpdate: '2024-01-15T10:30:00Z',
    records: 45231,
    reliability: 95,
    enabled: true
  },
  { 
    id: 2, 
    name: 'Abuse.ch URLhaus', 
    url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    category: 'URL',
    format: 'CSV',
    status: 'active',
    lastUpdate: '2024-01-15T09:15:00Z',
    records: 12847,
    reliability: 92,
    enabled: true
  },
  { 
    id: 3, 
    name: 'Feodo Tracker', 
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    category: 'IP',
    format: 'CSV',
    status: 'failed',
    lastUpdate: '2024-01-14T18:00:00Z',
    records: 5231,
    reliability: 88,
    enabled: true,
    error: 'Connection timeout'
  },
  { 
    id: 4, 
    name: 'Emerging Threats', 
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    category: 'IP',
    format: 'TXT',
    status: 'pending',
    lastUpdate: null,
    records: 0,
    reliability: 85,
    enabled: false
  },
];

export default function Feeds() {
  const [feeds, setFeeds] = useState(mockFeeds);
  const [showAddModal, setShowAddModal] = useState(false);

  const toggleFeed = (id) => {
    setFeeds(feeds.map(f => f.id === id ? { ...f, enabled: !f.enabled } : f));
  };

  const triggerFeed = (id) => {
    // Would trigger a feed update
    console.log('Triggering feed:', id);
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Feed Management</h1>
        <button 
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-white px-4 py-2 rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Feed
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Total Feeds</div>
          <div className="text-2xl font-bold text-white">{feeds.length}</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Active</div>
          <div className="text-2xl font-bold text-green-400">{feeds.filter(f => f.status === 'active').length}</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Failed</div>
          <div className="text-2xl font-bold text-red-400">{feeds.filter(f => f.status === 'failed').length}</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Total Records</div>
          <div className="text-2xl font-bold text-white">{feeds.reduce((a, f) => a + f.records, 0).toLocaleString()}</div>
        </div>
      </div>

      {/* Feeds Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {feeds.map((feed) => (
          <div
            key={feed.id}
            className={`bg-dark-800 border rounded-xl p-5 ${
              feed.status === 'failed' ? 'border-red-500/30' : 'border-dark-700'
            }`}
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-white font-semibold">{feed.name}</h3>
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    feed.status === 'active' ? 'bg-green-500/20 text-green-400' :
                    feed.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                    'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {feed.status}
                  </span>
                </div>
                <a 
                  href={feed.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-dark-400 text-sm hover:text-primary-400 flex items-center gap-1 truncate max-w-xs"
                >
                  {feed.url.substring(0, 40)}...
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Toggle */}
              <button
                onClick={() => toggleFeed(feed.id)}
                className={`relative w-12 h-6 rounded-full transition-colors ${
                  feed.enabled ? 'bg-primary-500' : 'bg-dark-600'
                }`}
              >
                <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  feed.enabled ? 'left-7' : 'left-1'
                }`} />
              </button>
            </div>

            {/* Meta */}
            <div className="grid grid-cols-3 gap-4 mb-4 text-sm">
              <div>
                <span className="text-dark-500">Category</span>
                <div className="text-white">{feed.category}</div>
              </div>
              <div>
                <span className="text-dark-500">Format</span>
                <div className="text-white">{feed.format}</div>
              </div>
              <div>
                <span className="text-dark-500">Records</span>
                <div className="text-white">{feed.records.toLocaleString()}</div>
              </div>
            </div>

            {/* Error */}
            {feed.error && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4 text-sm text-red-400">
                {feed.error}
              </div>
            )}

            {/* Footer */}
            <div className="flex items-center justify-between pt-4 border-t border-dark-700">
              <div className="flex items-center gap-2 text-dark-400 text-sm">
                <Clock className="w-4 h-4" />
                {feed.lastUpdate ? new Date(feed.lastUpdate).toLocaleString() : 'Never'}
              </div>
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => triggerFeed(feed.id)}
                  className="p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
                <button className="p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors">
                  <Edit className="w-4 h-4" />
                </button>
                <button className="p-2 text-dark-400 hover:text-red-400 hover:bg-dark-700 rounded-lg transition-colors">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
