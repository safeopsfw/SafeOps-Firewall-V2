import { useState } from 'react';
import { 
  Users, 
  Plus, 
  Search, 
  Edit, 
  Trash2, 
  Shield, 
  Eye, 
  EyeOff,
  Key,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Monitor,
  LogOut
} from 'lucide-react';

// Mock users
const mockUsers = [
  { id: 1, email: 'admin@safeops.com', name: 'SafeOps Admin', role: 'superadmin', isActive: true, lastLogin: '2024-01-15T10:30:00Z', ip: '192.168.1.100', mfa: true },
  { id: 2, email: 'jane.doe@company.com', name: 'Jane Doe', role: 'admin', isActive: true, lastLogin: '2024-01-15T09:15:00Z', ip: '10.0.0.50', mfa: true },
  { id: 3, email: 'analyst@company.com', name: 'Security Analyst', role: 'analyst', isActive: true, lastLogin: '2024-01-14T15:20:00Z', ip: '10.0.0.51', mfa: false },
  { id: 4, email: 'viewer@company.com', name: 'Report Viewer', role: 'viewer', isActive: false, lastLogin: '2024-01-10T08:00:00Z', ip: '10.0.0.52', mfa: false },
];

// Active sessions
const activeSessions = [
  { id: 1, user: 'admin@safeops.com', ip: '192.168.1.100', started: '10:30 AM', lastAction: 'Viewing Dashboard', status: 'active' },
  { id: 2, user: 'jane.doe@company.com', ip: '10.0.0.50', started: '9:15 AM', lastAction: 'Editing Rule SID:2019233', status: 'active' },
];

// Permission matrix
const permissions = {
  dashboards: ['Dashboard', 'IDS Rule Editor', 'Intel Feed Manager', 'Asset Manager', 'Audit Logs'],
  levels: ['View', 'Edit', 'Deploy', 'None'],
};

const rolePermissions = {
  superadmin: { 'Dashboard': 'Deploy', 'IDS Rule Editor': 'Deploy', 'Intel Feed Manager': 'Deploy', 'Asset Manager': 'Deploy', 'Audit Logs': 'Deploy' },
  admin: { 'Dashboard': 'Deploy', 'IDS Rule Editor': 'Edit', 'Intel Feed Manager': 'Deploy', 'Asset Manager': 'Edit', 'Audit Logs': 'View' },
  analyst: { 'Dashboard': 'View', 'IDS Rule Editor': 'Edit', 'Intel Feed Manager': 'View', 'Asset Manager': 'None', 'Audit Logs': 'View' },
  viewer: { 'Dashboard': 'View', 'IDS Rule Editor': 'View', 'Intel Feed Manager': 'View', 'Asset Manager': 'None', 'Audit Logs': 'None' },
};

export default function UserManagement() {
  const [activeTab, setActiveTab] = useState('users');
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);

  const filteredUsers = mockUsers.filter(u => 
    u.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
    u.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-dark-900 dark:text-white">User & Role Management</h1>
          <p className="text-dark-400">Manage access control and permissions</p>
        </div>
        <button 
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-dark-200 dark:border-dark-700">
        <button
          onClick={() => setActiveTab('users')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'users'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
          }`}
        >
          <Users className="w-4 h-4 inline mr-2" />
          Users
        </button>
        <button
          onClick={() => setActiveTab('roles')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'roles'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
          }`}
        >
          <Shield className="w-4 h-4 inline mr-2" />
          Role Permissions
        </button>
        <button
          onClick={() => setActiveTab('sessions')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'sessions'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
          }`}
        >
          <Monitor className="w-4 h-4 inline mr-2" />
          Active Sessions
        </button>
        <button
          onClick={() => setActiveTab('apikeys')}
          className={`px-4 py-3 font-medium transition-colors ${
            activeTab === 'apikeys'
              ? 'text-primary-400 border-b-2 border-primary-400'
              : 'text-dark-400 hover:text-dark-900 dark:text-white'
          }`}
        >
          <Key className="w-4 h-4 inline mr-2" />
          API Keys
        </button>
      </div>

      {/* Users Tab */}
      {activeTab === 'users' && (
        <>
          {/* Search */}
          <div className="relative mb-4 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input
              type="text"
              placeholder="Search users..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-lg text-dark-900 dark:text-white placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>

          {/* Users Table */}
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead className="bg-dark-700">
                <tr>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">User</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Role</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">MFA</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Status</th>
                  <th className="text-left px-6 py-4 text-dark-300 font-medium">Last Login</th>
                  <th className="text-right px-6 py-4 text-dark-300 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((user) => (
                  <tr key={user.id} className="border-t border-dark-200 dark:border-dark-700 hover:bg-dark-700/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
                          <span className="text-dark-900 dark:text-white font-medium">{user.name.charAt(0)}</span>
                        </div>
                        <div>
                          <div className="text-dark-900 dark:text-white font-medium">{user.name}</div>
                          <div className="text-dark-400 text-sm">{user.email}</div>
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
                      {user.mfa ? (
                        <CheckCircle className="w-5 h-5 text-green-400" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-yellow-400" />
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-2 ${user.isActive ? 'text-green-400' : 'text-dark-500'}`}>
                        <span className={`w-2 h-2 rounded-full ${user.isActive ? 'bg-green-400' : 'bg-dark-500'}`} />
                        {user.isActive ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-dark-400 text-sm">
                      <div>{new Date(user.lastLogin).toLocaleDateString()}</div>
                      <div className="text-dark-500">{user.ip}</div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button className="p-2 text-dark-400 hover:text-dark-900 dark:text-white hover:bg-dark-600 rounded-lg transition-colors" title="Impersonate">
                          <Eye className="w-4 h-4" />
                        </button>
                        <button className="p-2 text-dark-400 hover:text-dark-900 dark:text-white hover:bg-dark-600 rounded-lg transition-colors">
                          <Edit className="w-4 h-4" />
                        </button>
                        <button className="p-2 text-dark-400 hover:text-red-400 hover:bg-dark-600 rounded-lg transition-colors">
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

      {/* Role Permissions Tab */}
      {activeTab === 'roles' && (
        <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden">
          <table className="w-full">
            <thead className="bg-dark-700">
              <tr>
                <th className="text-left px-6 py-4 text-dark-300 font-medium">Dashboard / Action</th>
                {Object.keys(rolePermissions).map(role => (
                  <th key={role} className="text-center px-6 py-4 text-dark-300 font-medium capitalize">{role}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {permissions.dashboards.map((dashboard) => (
                <tr key={dashboard} className="border-t border-dark-200 dark:border-dark-700">
                  <td className="px-6 py-4 text-dark-900 dark:text-white">{dashboard}</td>
                  {Object.keys(rolePermissions).map(role => (
                    <td key={role} className="text-center px-6 py-4">
                      <select 
                        defaultValue={rolePermissions[role][dashboard]}
                        className={`px-2 py-1 rounded text-xs font-medium border-0 ${
                          rolePermissions[role][dashboard] === 'Deploy' ? 'bg-green-500/20 text-green-400' :
                          rolePermissions[role][dashboard] === 'Edit' ? 'bg-blue-500/20 text-blue-400' :
                          rolePermissions[role][dashboard] === 'View' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-dark-600 text-dark-400'
                        }`}
                      >
                        {permissions.levels.map(level => (
                          <option key={level} value={level}>{level}</option>
                        ))}
                      </select>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Active Sessions Tab */}
      {activeTab === 'sessions' && (
        <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl overflow-hidden">
          <table className="w-full">
            <thead className="bg-dark-700">
              <tr>
                <th className="text-left px-6 py-4 text-dark-300 font-medium">User</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium">IP Address</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium">Started</th>
                <th className="text-left px-6 py-4 text-dark-300 font-medium">Last Action</th>
                <th className="text-right px-6 py-4 text-dark-300 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {activeSessions.map((session) => (
                <tr key={session.id} className="border-t border-dark-200 dark:border-dark-700 hover:bg-dark-700/50">
                  <td className="px-6 py-4 text-dark-900 dark:text-white">{session.user}</td>
                  <td className="px-6 py-4 text-dark-300 font-mono">{session.ip}</td>
                  <td className="px-6 py-4 text-dark-400">{session.started}</td>
                  <td className="px-6 py-4 text-dark-300">{session.lastAction}</td>
                  <td className="px-6 py-4 text-right">
                    <button className="flex items-center gap-2 px-3 py-1 bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded-lg transition-colors ml-auto">
                      <LogOut className="w-4 h-4" />
                      Terminate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* API Keys Tab */}
      {activeTab === 'apikeys' && (
        <div className="space-y-6">
          <button className="flex items-center gap-2 bg-primary-500 hover:bg-primary-600 text-dark-900 dark:text-white px-4 py-2 rounded-lg transition-colors">
            <Plus className="w-4 h-4" />
            Generate New Key
          </button>
          <div className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-dark-900 dark:text-white font-medium">Intel Feed Read-Only</div>
                <div className="text-dark-400 text-sm">Created: Jan 10, 2024</div>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-yellow-400 text-sm flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  Expires in 7 days
                </span>
                <button className="text-red-400 hover:text-red-300">Revoke</button>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-dark-50 dark:bg-dark-900 px-4 py-2 rounded-lg text-dark-400 font-mono text-sm">
                sk_live_••••••••••••••••••••••••4a2b
              </code>
              <button className="p-2 text-dark-400 hover:text-dark-900 dark:text-white">
                <Eye className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
