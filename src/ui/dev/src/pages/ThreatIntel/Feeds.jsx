import { useState, useEffect } from 'react';
import { 
  Plus, 
  RefreshCw, 
  Trash2, 
  Edit,
  Clock,
  ExternalLink,
  Database,
  Check,
  X,
  AlertCircle
} from 'lucide-react';
import {
  getSources,
  addSource,
  removeSource,
  updateSource,
  DB_CATEGORIES,
  SOURCE_TYPES
} from '../../services/threatIntelService';

export default function Feeds() {
  const [feeds, setFeeds] = useState([]);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newFeed, setNewFeed] = useState({
    name: '',
    category: 'domains',
    type: 'url_csv',
    url: '',
    schedule: 'daily'
  });
  const [refreshing, setRefreshing] = useState(null);

  // Load feeds from service
  useEffect(() => {
    setFeeds(getSources());
  }, []);

  const handleAddFeed = () => {
    if (!newFeed.name || !newFeed.url) return;
    const source = addSource(newFeed);
    setFeeds([...feeds, source]);
    setNewFeed({ name: '', category: 'domains', type: 'url_csv', url: '', schedule: 'daily' });
    setShowAddModal(false);
  };

  const handleRemoveFeed = (id) => {
    const updated = removeSource(id);
    setFeeds(updated);
  };

  const handleRefreshFeed = async (id) => {
    setRefreshing(id);
    // Simulate refresh
    await new Promise(r => setTimeout(r, 2000));
    const updated = updateSource(id, {
      lastFetch: new Date().toISOString(),
      status: 'active'
    });
    setFeeds(updated);
    setRefreshing(null);
  };

  const toggleFeed = (id) => {
    const feed = feeds.find(f => f.id === id);
    const newStatus = feed.status === 'active' ? 'disabled' : 'active';
    const updated = updateSource(id, { status: newStatus });
    setFeeds(updated);
  };

  // Group feeds by category
  const feedsByCategory = {};
  Object.keys(DB_CATEGORIES).forEach(cat => {
    feedsByCategory[cat] = feeds.filter(f => f.category === cat);
  });

  const totalRecords = feeds.reduce((a, f) => a + (f.records || 0), 0);
  const activeFeeds = feeds.filter(f => f.status === 'active').length;
  const failedFeeds = feeds.filter(f => f.status === 'failed').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Feed Management</h1>
          <p className="text-dark-400 mt-1">Configure and manage threat intelligence sources</p>
        </div>
        <button 
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-white px-4 py-2 rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Feed
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Total Feeds</div>
          <div className="text-2xl font-bold text-white">{feeds.length}</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Active</div>
          <div className="text-2xl font-bold text-green-400">{activeFeeds}</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Failed</div>
          <div className="text-2xl font-bold text-red-400">{failedFeeds}</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
          <div className="text-dark-400 text-sm">Total Records</div>
          <div className="text-2xl font-bold text-white">{totalRecords.toLocaleString()}</div>
        </div>
      </div>

      {/* Feeds by Category */}
      {Object.entries(DB_CATEGORIES).map(([catKey, catInfo]) => {
        const catFeeds = feedsByCategory[catKey] || [];
        if (catFeeds.length === 0) return null;

        return (
          <div key={catKey} className="space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <span className="text-xl">{catInfo.icon}</span>
              {catInfo.name}
              <span className="text-sm text-dark-400 font-normal">({catFeeds.length} feeds)</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {catFeeds.map((feed) => (
                <div
                  key={feed.id}
                  className={`bg-dark-800 border rounded-xl p-5 ${
                    feed.status === 'failed' ? 'border-red-500/30' : 'border-dark-700'
                  }`}
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-white font-semibold truncate">{feed.name}</h3>
                        <span className={`px-2 py-0.5 rounded text-xs flex-shrink-0 ${
                          feed.status === 'active' ? 'bg-green-500/20 text-green-400' :
                          feed.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                          feed.status === 'pending' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-dark-600 text-dark-400'
                        }`}>
                          {feed.status}
                        </span>
                      </div>
                      <a 
                        href={feed.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-dark-400 text-sm hover:text-primary-400 flex items-center gap-1 truncate"
                      >
                        {feed.url?.substring(0, 50)}...
                        <ExternalLink className="w-3 h-3 flex-shrink-0" />
                      </a>
                    </div>

                    {/* Toggle */}
                    <button
                      onClick={() => toggleFeed(feed.id)}
                      className={`relative w-12 h-6 rounded-full transition-colors flex-shrink-0 ${
                        feed.status === 'active' ? 'bg-primary-500' : 'bg-dark-600'
                      }`}
                    >
                      <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                        feed.status === 'active' ? 'left-7' : 'left-1'
                      }`} />
                    </button>
                  </div>

                  {/* Meta */}
                  <div className="grid grid-cols-3 gap-4 mb-4 text-sm">
                    <div>
                      <span className="text-dark-500">Type</span>
                      <div className="text-white">
                        {SOURCE_TYPES.find(t => t.id === feed.type)?.name || feed.type}
                      </div>
                    </div>
                    <div>
                      <span className="text-dark-500">Schedule</span>
                      <div className="text-white capitalize">{feed.schedule || 'Manual'}</div>
                    </div>
                    <div>
                      <span className="text-dark-500">Records</span>
                      <div className="text-white">{(feed.records || 0).toLocaleString()}</div>
                    </div>
                  </div>

                  {/* Error */}
                  {feed.error && (
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4 text-sm text-red-400 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 flex-shrink-0" />
                      {feed.error}
                    </div>
                  )}

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-4 border-t border-dark-700">
                    <div className="flex items-center gap-2 text-dark-400 text-sm">
                      <Clock className="w-4 h-4" />
                      {feed.lastFetch ? new Date(feed.lastFetch).toLocaleString() : 'Never'}
                    </div>
                    <div className="flex items-center gap-1">
                      <button 
                        onClick={() => handleRefreshFeed(feed.id)}
                        disabled={refreshing === feed.id}
                        className="p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors disabled:opacity-50"
                        title="Refresh now"
                      >
                        <RefreshCw className={`w-4 h-4 ${refreshing === feed.id ? 'animate-spin' : ''}`} />
                      </button>
                      <button 
                        className="p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                        title="Edit"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button 
                        onClick={() => handleRemoveFeed(feed.id)}
                        className="p-2 text-dark-400 hover:text-red-400 hover:bg-dark-700 rounded-lg transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {/* Empty State */}
      {feeds.length === 0 && (
        <div className="text-center py-12">
          <Database className="w-16 h-16 mx-auto text-dark-600 mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">No Feeds Configured</h3>
          <p className="text-dark-400 mb-6">Add your first threat intelligence feed to get started</p>
          <button 
            onClick={() => setShowAddModal(true)}
            className="bg-primary-500 hover:bg-primary-600 text-white px-6 py-3 rounded-lg transition-colors"
          >
            Add Your First Feed
          </button>
        </div>
      )}

      {/* Add Feed Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 w-full max-w-lg mx-4 animate-fade-in">
            <h3 className="text-xl font-bold text-white mb-4">Add New Feed</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">Feed Name</label>
                <input
                  type="text"
                  value={newFeed.name}
                  onChange={e => setNewFeed({...newFeed, name: e.target.value})}
                  placeholder="e.g., Abuse.ch Malware Hashes"
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white placeholder-dark-400 focus:outline-none focus:border-primary-500"
                />
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-dark-400 mb-1">Category</label>
                  <select
                    value={newFeed.category}
                    onChange={e => setNewFeed({...newFeed, category: e.target.value})}
                    className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white focus:outline-none focus:border-primary-500"
                  >
                    {Object.entries(DB_CATEGORIES).map(([key, cat]) => (
                      <option key={key} value={key}>{cat.icon} {cat.name}</option>
                    ))}
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm text-dark-400 mb-1">Feed Type</label>
                  <select
                    value={newFeed.type}
                    onChange={e => setNewFeed({...newFeed, type: e.target.value})}
                    className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white focus:outline-none focus:border-primary-500"
                  >
                    {SOURCE_TYPES.map(type => (
                      <option key={type.id} value={type.id}>{type.icon} {type.name}</option>
                    ))}
                  </select>
                </div>
              </div>
              
              <div>
                <label className="block text-sm text-dark-400 mb-1">Feed URL</label>
                <input
                  type="url"
                  value={newFeed.url}
                  onChange={e => setNewFeed({...newFeed, url: e.target.value})}
                  placeholder="https://example.com/threat-feed.csv"
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white placeholder-dark-400 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block text-sm text-dark-400 mb-1">Update Schedule</label>
                <select
                  value={newFeed.schedule}
                  onChange={e => setNewFeed({...newFeed, schedule: e.target.value})}
                  className="w-full px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-white focus:outline-none focus:border-primary-500"
                >
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="manual">Manual Only</option>
                </select>
              </div>
            </div>
            
            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-dark-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleAddFeed}
                disabled={!newFeed.name || !newFeed.url}
                className="px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Add Feed
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
