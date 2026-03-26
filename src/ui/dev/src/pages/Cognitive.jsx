import { useState } from 'react';
import { 
  Database, 
  Users, 
  FileText, 
  Search, 
  Plus, 
  Edit, 
  Trash2,
  Shield,
  Globe,
  Hash,
  Link,
  Server,
  ChevronRight
} from 'lucide-react';

// Entity categories similar to the reference image
const entityCategories = {
  A: [
    { name: 'AccountInfo', icon: Users, description: 'User account information' },
    { name: 'Acronyms', icon: FileText, description: 'System acronyms and abbreviations' },
    { name: 'APIThrottleProcesses', icon: Server, description: 'API rate limiting configurations' },
    { name: 'AssetNetworkAttributes', icon: Globe, description: 'Network asset properties' },
    { name: 'AuditLog', icon: FileText, description: 'System audit trail' },
  ],
  C: [
    { name: 'ClientHistory', icon: FileText, description: 'Client interaction history' },
    { name: 'CveVendors', icon: Shield, description: 'CVE vendor mappings' },
    { name: 'CyberStatusReports', icon: FileText, description: 'Cyber security status reports' },
  ],
  D: [
    { name: 'DatabaseConnections', icon: Database, description: 'Database connection configs', badge: 'New' },
    { name: 'DataSourceKinds', icon: Server, description: 'Data source type definitions' },
    { name: 'DNSEventTypes', icon: Globe, description: 'DNS event classifications' },
  ],
  I: [
    { name: 'IPBlacklist', icon: Shield, description: 'Blocked IP addresses' },
    { name: 'IOCIndicators', icon: Shield, description: 'Indicators of Compromise' },
  ],
  U: [
    { name: 'Users', icon: Users, description: 'System users', badge: 'Admin' },
    { name: 'UserPreferences', icon: Users, description: 'User settings and preferences' },
  ],
};

// User management mock data
const mockUsers = [
  { id: 1, email: 'admin@safeops.com', name: 'SafeOps Admin', role: 'superadmin', isActive: true, lastLogin: '2024-01-15T10:30:00Z' },
  { id: 2, email: 'analyst@safeops.com', name: 'Security Analyst', role: 'analyst', isActive: true, lastLogin: '2024-01-14T15:20:00Z' },
  { id: 3, email: 'viewer@safeops.com', name: 'Report Viewer', role: 'viewer', isActive: false, lastLogin: '2024-01-10T08:00:00Z' },
];

export default function Cognitive() {
  const [activeTab, setActiveTab] = useState('entities');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEntity, setSelectedEntity] = useState(null);

  const filteredCategories = Object.entries(entityCategories).reduce((acc, [letter, entities]) => {
    const filtered = entities.filter(e => 
      e.name.toLowerCase().includes(searchTerm.toLowerCase())
    );
    if (filtered.length > 0) {
      acc[letter] = filtered;
    }
    return acc;
  }, {});

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-dark-900 dark:text-white mb-2">Cognitive Library</h1>
          <p className="text-dark-500 dark:text-dark-400">Entity management and data models</p>
        </div>
        <button className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors">
          <Plus className="w-4 h-4" />
          Import Entities
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-dark-200 dark:border-dark-700">
        <button
          onClick={() => setActiveTab('entities')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'entities'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
          }`}
        >
          <Database className="w-4 h-4 inline mr-2" />
          Entities
        </button>
        <button
          onClick={() => setActiveTab('users')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'users'
              ? 'text-primary-500 dark:text-primary-400 border-b-2 border-primary-500 dark:border-primary-400'
              : 'text-dark-500 dark:text-dark-400 hover:text-dark-900 dark:hover:text-dark-900 dark:text-white'
          }`}
        >
          <Users className="w-4 h-4 inline mr-2" />
          User Management
        </button>
      </div>

      {activeTab === 'entities' && (
        <>
          {/* Search */}
          <div className="relative mb-6">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-400" />
            <input
              type="text"
              placeholder="Filter entities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white placeholder-dark-400 dark:placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>

          {/* Entity Grid */}
          <div className="space-y-8">
            {Object.entries(filteredCategories).map(([letter, entities]) => (
              <div key={letter}>
                <h2 className="text-xl font-bold text-dark-900 dark:text-white mb-4">{letter}</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {entities.map((entity) => {
                    const Icon = entity.icon;
                    return (
                      <button
                        key={entity.name}
                        onClick={() => setSelectedEntity(entity)}
                        className="flex items-start gap-4 p-4 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-lg hover:bg-dark-50 dark:hover:bg-dark-700 hover:border-dark-300 dark:hover:border-dark-300 dark:border-dark-600 transition-all text-left group"
                      >
                        <div className="p-2 bg-primary-500/20 rounded-lg">
                          <Icon className="w-5 h-5 text-primary-400" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-primary-400 font-medium">{entity.name}</span>
                            {entity.badge && (
                              <span className="text-xs bg-primary-500/20 text-primary-300 px-2 py-0.5 rounded">
                                {entity.badge}
                              </span>
                            )}
                          </div>
                          <p className="text-dark-500 dark:text-dark-400 text-sm mt-1">{entity.description}</p>
                        </div>
                        <ChevronRight className="w-4 h-4 text-dark-500 group-hover:text-primary-400 transition-colors" />
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {activeTab === 'users' && (
        <div className="space-y-6">
          {/* Add User Button */}
          <div className="flex justify-end">
            <button className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors">
              <Plus className="w-4 h-4" />
              Add User
            </button>
          </div>

          {/* Users Table */}
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead className="bg-dark-100 dark:bg-dark-700">
                <tr>
                  <th className="text-left px-6 py-4 text-dark-600 dark:text-dark-300 font-medium">User</th>
                  <th className="text-left px-6 py-4 text-dark-600 dark:text-dark-300 font-medium">Role</th>
                  <th className="text-left px-6 py-4 text-dark-600 dark:text-dark-300 font-medium">Status</th>
                  <th className="text-left px-6 py-4 text-dark-600 dark:text-dark-300 font-medium">Last Login</th>
                  <th className="text-right px-6 py-4 text-dark-600 dark:text-dark-300 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {mockUsers.map((user) => (
                  <tr key={user.id} className="border-t border-dark-200 dark:border-dark-700 hover:bg-dark-50 dark:hover:bg-dark-700/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
                          <span className="text-dark-900 dark:text-white font-medium">{user.name.charAt(0)}</span>
                        </div>
                        <div>
                          <div className="text-dark-900 dark:text-white font-medium">{user.name}</div>
                          <div className="text-dark-500 dark:text-dark-400 text-sm">{user.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        user.role === 'superadmin' ? 'bg-purple-500/20 text-purple-400' :
                        user.role === 'admin' ? 'bg-blue-500/20 text-blue-400' :
                        user.role === 'analyst' ? 'bg-green-500/20 text-green-400' :
                        'bg-dark-600 text-dark-300'
                      }`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-2 ${user.isActive ? 'text-green-400' : 'text-dark-500'}`}>
                        <span className={`w-2 h-2 rounded-full ${user.isActive ? 'bg-green-400' : 'bg-dark-500'}`} />
                        {user.isActive ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-dark-500 dark:text-dark-400">
                      {new Date(user.lastLogin).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button className="p-2 text-dark-400 hover:text-dark-900 dark:hover:text-dark-900 dark:text-white hover:bg-dark-100 dark:hover:bg-dark-600 rounded-lg transition-colors">
                          <Edit className="w-4 h-4" />
                        </button>
                        <button className="p-2 text-dark-400 hover:text-red-500 dark:hover:text-red-400 hover:bg-dark-100 dark:hover:bg-dark-600 rounded-lg transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
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
