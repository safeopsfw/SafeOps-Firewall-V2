import { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, 
  Database, 
  Palette, 
  User, 
  Shield, 
  Bell,
  Save,
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
  Loader2,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';

const mockDatabases = [
  { id: 1, name: 'Threat Intelligence DB', host: 'localhost', port: 5432, database: 'threat_intel_db', isDefault: true, status: 'connected' },
  { id: 2, name: 'User Database', host: 'localhost', port: 5432, database: 'safeops_users', isDefault: false, status: 'connected' },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('general');
  const [dataSource, setDataSource] = useState(() => localStorage.getItem('safeops_data_source') || 'dummy');
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [saving, setSaving] = useState(false);
  const [theme, setTheme] = useState('dark');
  const [databases, setDatabases] = useState(mockDatabases);
  const [newDb, setNewDb] = useState({ name: '', host: 'localhost', port: '5432', database: '', username: '', password: '' });
  const [testing, setTesting] = useState(false);
  
  // Track if data source changed
  const handleDataSourceChange = (value) => {
    setDataSource(value);
    setHasUnsavedChanges(true);
  };
  
  // Save and reload
  const saveAndReload = async () => {
    setSaving(true);
    
    // Save to localStorage
    localStorage.setItem('safeops_data_source', dataSource);
    
    // Simulate API call to save settings
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Reload the page to reflect database data
    window.location.reload();
  };

  const tabs = [
    { id: 'general', label: 'General', icon: SettingsIcon },
    { id: 'database', label: 'Database', icon: Database },
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'security', label: 'Security', icon: Shield },
  ];

  const testConnection = async () => {
    setTesting(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    setTesting(false);
    alert('Connection successful!');
  };

  const addDatabase = () => {
    if (!newDb.name || !newDb.database) return;
    setDatabases([...databases, {
      id: Date.now(),
      name: newDb.name,
      host: newDb.host,
      port: parseInt(newDb.port),
      database: newDb.database,
      isDefault: false,
      status: 'pending'
    }]);
    setNewDb({ name: '', host: 'localhost', port: '5432', database: '', username: '', password: '' });
  };

  return (
    <div className="animate-fade-in">
      <h1 className="text-3xl font-bold text-white mb-6">Settings</h1>

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-64 shrink-0">
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    activeTab === tab.id
                      ? 'bg-primary-500/20 text-primary-400'
                      : 'text-dark-300 hover:bg-dark-700 hover:text-white'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1">
          {/* General */}
          {activeTab === 'general' && (
            <div className="space-y-6">
              {/* Data Source Toggle */}
              <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Data Source</h2>
                <p className="text-dark-400 text-sm mb-4">
                  Choose between demo data for development or connect to real database.
                </p>
                <div className="flex gap-4 mb-4">
                  <label className={`flex-1 flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-all ${
                    dataSource === 'dummy' 
                      ? 'border-primary-500 bg-primary-500/10' 
                      : 'border-dark-600 hover:border-dark-500'
                  }`}>
                    <input
                      type="radio"
                      name="dataSource"
                      value="dummy"
                      checked={dataSource === 'dummy'}
                      onChange={(e) => handleDataSourceChange(e.target.value)}
                      className="accent-primary-500"
                    />
                    <div>
                      <div className="text-white font-medium">Demo Data</div>
                      <div className="text-dark-400 text-sm">Use mock data for development</div>
                    </div>
                  </label>
                  <label className={`flex-1 flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-all ${
                    dataSource === 'database' 
                      ? 'border-primary-500 bg-primary-500/10' 
                      : 'border-dark-600 hover:border-dark-500'
                  }`}>
                    <input
                      type="radio"
                      name="dataSource"
                      value="database"
                      checked={dataSource === 'database'}
                      onChange={(e) => handleDataSourceChange(e.target.value)}
                      className="accent-primary-500"
                    />
                    <div>
                      <div className="text-white font-medium">Database</div>
                      <div className="text-dark-400 text-sm">Connect to PostgreSQL</div>
                    </div>
                  </label>
                </div>
                
                {/* Save & Reload Section */}
                {hasUnsavedChanges && (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 animate-fade-in">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="w-5 h-5 text-yellow-400" />
                        <div>
                          <div className="text-yellow-400 font-medium">Unsaved Changes</div>
                          <div className="text-yellow-300/70 text-sm">
                            {dataSource === 'database' 
                              ? 'Switching to database mode will reload the app to fetch real data.'
                              : 'Switching to demo mode will reload the app with mock data.'
                            }
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={saveAndReload}
                        disabled={saving}
                        className="flex items-center gap-2 px-4 py-2 bg-yellow-500 hover:bg-yellow-600 disabled:bg-yellow-500/50 text-black font-medium rounded-lg transition-colors"
                      >
                        {saving ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin" />
                            Saving...
                          </>
                        ) : (
                          <>
                            <RefreshCw className="w-4 h-4" />
                            Save & Reload
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                )}
                
                {/* Current Mode Indicator */}
                <div className={`mt-4 flex items-center gap-2 text-sm ${
                  localStorage.getItem('safeops_data_source') === 'database' ? 'text-green-400' : 'text-blue-400'
                }`}>
                  <Database className="w-4 h-4" />
                  <span>Current: {localStorage.getItem('safeops_data_source') === 'database' ? 'Database Mode' : 'Demo Mode'}</span>
                </div>
              </div>

              {/* Account Info */}
              <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Account</h2>
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-16 h-16 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
                    <span className="text-white text-2xl font-bold">S</span>
                  </div>
                  <div>
                    <div className="text-white font-medium">SafeOps Admin</div>
                    <div className="text-dark-400">admin@safeops.com</div>
                    <div className="text-primary-400 text-sm">superadmin</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Database */}
          {activeTab === 'database' && (
            <div className="space-y-6">
              {/* Current Databases */}
              <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Database Connections</h2>
                <div className="space-y-3">
                  {databases.map((db) => (
                    <div
                      key={db.id}
                      className={`flex items-center justify-between p-4 rounded-lg border ${
                        db.isDefault ? 'border-primary-500/30 bg-primary-500/5' : 'border-dark-600'
                      }`}
                    >
                      <div className="flex items-center gap-4">
                        <Database className="w-8 h-8 text-primary-400" />
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-white font-medium">{db.name}</span>
                            {db.isDefault && (
                              <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded">Default</span>
                            )}
                          </div>
                          <div className="text-dark-400 text-sm">
                            {db.host}:{db.port}/{db.database}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`flex items-center gap-1 text-sm ${
                          db.status === 'connected' ? 'text-green-400' : 'text-yellow-400'
                        }`}>
                          {db.status === 'connected' ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                          {db.status}
                        </span>
                        {!db.isDefault && (
                          <button className="p-2 text-dark-400 hover:text-red-400 hover:bg-dark-700 rounded-lg">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add New Database */}
              <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Add Database Connection</h2>
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div>
                    <label className="block text-sm text-dark-300 mb-2">Connection Name</label>
                    <input
                      type="text"
                      value={newDb.name}
                      onChange={(e) => setNewDb({...newDb, name: e.target.value})}
                      placeholder="My Database"
                      className="w-full px-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-300 mb-2">Database Name</label>
                    <input
                      type="text"
                      value={newDb.database}
                      onChange={(e) => setNewDb({...newDb, database: e.target.value})}
                      placeholder="my_database"
                      className="w-full px-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-300 mb-2">Host</label>
                    <input
                      type="text"
                      value={newDb.host}
                      onChange={(e) => setNewDb({...newDb, host: e.target.value})}
                      placeholder="localhost"
                      className="w-full px-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-300 mb-2">Port</label>
                    <input
                      type="text"
                      value={newDb.port}
                      onChange={(e) => setNewDb({...newDb, port: e.target.value})}
                      placeholder="5432"
                      className="w-full px-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-300 mb-2">Username</label>
                    <input
                      type="text"
                      value={newDb.username}
                      onChange={(e) => setNewDb({...newDb, username: e.target.value})}
                      placeholder="postgres"
                      className="w-full px-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-300 mb-2">Password</label>
                    <input
                      type="password"
                      value={newDb.password}
                      onChange={(e) => setNewDb({...newDb, password: e.target.value})}
                      placeholder="••••••••"
                      className="w-full px-4 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    />
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={testConnection}
                    disabled={testing}
                    className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-300 rounded-lg transition-colors"
                  >
                    {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                    Test Connection
                  </button>
                  <button
                    onClick={addDatabase}
                    className="flex items-center gap-2 px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    Add Database
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Appearance */}
          {activeTab === 'appearance' && (
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Theme</h2>
              <div className="flex gap-4">
                <label className={`flex-1 flex items-center gap-3 p-4 rounded-lg border cursor-pointer ${
                  theme === 'dark' ? 'border-primary-500 bg-primary-500/10' : 'border-dark-600'
                }`}>
                  <input
                    type="radio"
                    name="theme"
                    value="dark"
                    checked={theme === 'dark'}
                    onChange={(e) => setTheme(e.target.value)}
                    className="accent-primary-500"
                  />
                  <div>
                    <div className="text-white font-medium">Dark Mode</div>
                    <div className="text-dark-400 text-sm">Easier on the eyes</div>
                  </div>
                </label>
                <label className={`flex-1 flex items-center gap-3 p-4 rounded-lg border cursor-pointer ${
                  theme === 'light' ? 'border-primary-500 bg-primary-500/10' : 'border-dark-600'
                }`}>
                  <input
                    type="radio"
                    name="theme"
                    value="light"
                    checked={theme === 'light'}
                    onChange={(e) => setTheme(e.target.value)}
                    className="accent-primary-500"
                  />
                  <div>
                    <div className="text-white font-medium">Light Mode</div>
                    <div className="text-dark-400 text-sm">Better for daylight</div>
                  </div>
                </label>
              </div>
            </div>
          )}

          {/* Other tabs - placeholder */}
          {(activeTab === 'notifications' || activeTab === 'security') && (
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
              <h2 className="text-lg font-semibold text-white mb-4">
                {activeTab === 'notifications' ? 'Notifications' : 'Security'}
              </h2>
              <p className="text-dark-400">Settings for {activeTab} will be available here.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
