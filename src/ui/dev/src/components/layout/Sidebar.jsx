import { NavLink, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Shield, 
  Globe, 
  Database, 
  Settings,
  Lock,
  AlertTriangle,
  Network,
  Users,
  Activity,
  Wrench,
  FileCode,
  Server,
  Key,
  ClipboardList
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

// Operations navigation
const operationsNav = [
  { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { name: 'Threat Intel', path: '/threat-intel', icon: Shield },
  { name: 'IOC Workspace', path: '/threat-intel/ioc', icon: Activity },
];

// Module navigation
const moduleNav = [
  { name: 'IDS/IPS Rules', path: '/ids', icon: FileCode },
  { name: 'DNS Server', path: '/dns', icon: Globe, badge: 'Soon' },
  { name: 'Firewall', path: '/firewall', icon: Lock, badge: 'Soon' },
  { name: 'Network', path: '/network', icon: Network, badge: 'Soon' },
  { name: 'Cognitive', path: '/cognitive', icon: Database },
];

// Management navigation (admin only)
const managementNav = [
  { name: 'User Management', path: '/manage/users', icon: Users },
  { name: 'Feed Management', path: '/manage/feeds', icon: Database },
  { name: 'Database Config', path: '/manage/databases', icon: Server },
  { name: 'API Keys', path: '/manage/apikeys', icon: Key, badge: 'Soon' },
  { name: 'Audit Logs', path: '/manage/audit', icon: ClipboardList, badge: 'Soon' },
  { name: 'System Settings', path: '/settings', icon: Settings },
];

export default function Sidebar({ isOpen, onClose }) {
  const location = useLocation();
  const { user } = useAuth();
  
  const isAdmin = user?.role === 'superadmin' || user?.role === 'admin';

  const NavItem = ({ item }) => {
    const Icon = item.icon;
    const isActive = location.pathname === item.path || 
      (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
    
    return (
      <NavLink
        to={item.badge ? '#' : item.path}
        onClick={item.badge ? (e) => e.preventDefault() : onClose}
        className={`flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 ${
          isActive
            ? 'bg-primary-500/20 text-primary-400'
            : 'text-dark-300 hover:bg-dark-700 hover:text-white'
        } ${item.badge ? 'opacity-50 cursor-not-allowed' : ''}`}
      >
        <Icon className="w-5 h-5 flex-shrink-0" />
        <span className="flex-1 text-sm">{item.name}</span>
        {item.badge && (
          <span className="text-xs bg-dark-600 text-dark-400 px-1.5 py-0.5 rounded">
            {item.badge}
          </span>
        )}
      </NavLink>
    );
  };

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/50 lg:hidden z-40"
          onClick={onClose}
        />
      )}
      
      {/* Sidebar */}
      <aside className={`
        fixed lg:static inset-y-0 left-0 z-50
        w-64 bg-dark-800 border-r border-dark-700
        transform ${isOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0
        transition-transform duration-300 ease-in-out
        flex flex-col
      `}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-dark-700">
          <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-primary-600 rounded-xl flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">SafeOps</h1>
            <p className="text-xs text-primary-400">Management Console</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          {/* Operations */}
          <div className="mb-6">
            <div className="px-4 py-2 text-xs font-semibold text-dark-500 uppercase tracking-wider">
              Operations
            </div>
            <div className="space-y-1">
              {operationsNav.map((item) => (
                <NavItem key={item.path} item={item} />
              ))}
            </div>
          </div>

          {/* Modules */}
          <div className="mb-6">
            <div className="px-4 py-2 text-xs font-semibold text-dark-500 uppercase tracking-wider">
              Modules
            </div>
            <div className="space-y-1">
              {moduleNav.map((item) => (
                <NavItem key={item.path} item={item} />
              ))}
            </div>
          </div>

          {/* Management (Admin Only) */}
          {isAdmin && (
            <div className="mb-6">
              <div className="px-4 py-2 text-xs font-semibold text-dark-500 uppercase tracking-wider flex items-center gap-2">
                <Wrench className="w-3 h-3" />
                Management
              </div>
              <div className="space-y-1">
                {managementNav.map((item) => (
                  <NavItem key={item.path} item={item} />
                ))}
              </div>
            </div>
          )}
        </nav>

        {/* User Info */}
        <div className="px-3 py-4 border-t border-dark-700">
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-dark-700/50">
            <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-semibold">
                {user?.name?.charAt(0) || 'A'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-white truncate">{user?.name || 'User'}</div>
              <div className="text-xs text-dark-400">{user?.role || 'user'}</div>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
