import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  Database,
  Settings,
  Lock,
  Network,
  Users,
  Wrench,
  FileCode,
  Server,
  Wifi,
  Radio,
  ScrollText
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

// Operations navigation
const operationsNav = [
  { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { name: 'Threat Intel', path: '/threat-intel', icon: Shield },
];

// Module navigation
const moduleNav = [
  { name: 'Firewall', path: '/firewall', icon: Lock },
  { name: 'IDS/IPS Rule Helper', path: '/ids', icon: FileCode },
  { name: 'Network', path: '/network', icon: Network },
  { name: 'DHCP Monitor', path: '/dhcp-monitor', icon: Wifi },
  { name: 'Captive Portal', path: '/captive-portal', icon: Radio },
  { name: 'Network Logger', path: '/network-logger', icon: ScrollText },
  { name: 'Certificates', path: '/certificates', icon: Server },
  { name: 'Cognitive', path: '/cognitive', icon: Database },
];

// Management navigation (admin only)
const managementNav = [
  { name: 'User Management', path: '/manage/users', icon: Users },
  { name: 'Feed Management', path: '/manage/feeds', icon: Database },
  { name: 'Database Config', path: '/manage/databases', icon: Server },
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
        className={`flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 ${isActive
          ? 'bg-primary-500/20 text-primary-600 dark:text-primary-400'
          : 'text-dark-600 dark:text-dark-300 hover:bg-dark-100 dark:hover:bg-dark-700 hover:text-dark-900 dark:hover:text-white'
          } ${item.badge ? 'opacity-50 cursor-not-allowed' : ''}`}
      >
        <Icon className="w-5 h-5 flex-shrink-0" />
        <span className="flex-1 text-sm">{item.name}</span>
        {item.badge && (
          <span className="text-xs bg-dark-200 dark:bg-dark-600 text-dark-500 dark:text-dark-400 px-1.5 py-0.5 rounded">
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
        w-64 bg-white dark:bg-dark-800 border-r border-dark-200 dark:border-dark-700
        transform ${isOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0
        transition-all duration-300 ease-in-out
        flex flex-col
      `}>
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-dark-200 dark:border-dark-700">
          <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-primary-600 rounded-xl flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-dark-900 dark:text-white">SafeOps</h1>
            <p className="text-xs text-primary-600 dark:text-primary-400">Management Console</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          {/* Operations */}
          <div className="mb-6">
            <div className="px-4 py-2 text-xs font-semibold text-dark-400 dark:text-dark-500 uppercase tracking-wider">
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
            <div className="px-4 py-2 text-xs font-semibold text-dark-400 dark:text-dark-500 uppercase tracking-wider">
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
              <div className="px-4 py-2 text-xs font-semibold text-dark-400 dark:text-dark-500 uppercase tracking-wider flex items-center gap-2">
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
        <div className="px-3 py-4 border-t border-dark-200 dark:border-dark-700">
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-dark-50 dark:bg-dark-700/50">
            <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-semibold">
                {user?.name?.charAt(0) || 'A'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-dark-900 dark:text-white truncate">{user?.name || 'User'}</div>
              <div className="text-xs text-dark-500 dark:text-dark-400">{user?.role || 'user'}</div>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
