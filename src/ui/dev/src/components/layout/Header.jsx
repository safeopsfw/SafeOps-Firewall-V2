import { useState, useEffect } from 'react';
import {
  Menu,
  Bell,
  User,
  LogOut,
  Settings,
  ChevronDown,
  CheckCircle,
  Download,
  X,
  Info,
  AlertCircle,
  Sun,
  Moon
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useNavigate } from 'react-router-dom';

export default function Header({ onMenuClick }) {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  // Real notifications (will be fetched from backend later)
  const [notifications] = useState([]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (!e.target.closest('.dropdown-container')) {
        setShowUserMenu(false);
        setShowNotifications(false);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <>
      <header className="bg-white dark:bg-dark-800 border-b border-dark-200 dark:border-dark-700 px-4 lg:px-6 py-3 relative z-40 transition-colors">
        <div className="flex items-center justify-between">
          {/* Left: Menu */}
          <div className="flex items-center gap-4">
            <button
              onClick={onMenuClick}
              className="lg:hidden p-2 text-dark-500 dark:text-dark-400 hover:text-dark-900 dark:hover:text-white hover:bg-dark-100 dark:hover:bg-dark-700 rounded-lg transition-colors"
            >
              <Menu className="w-6 h-6" />
            </button>
          </div>

          {/* Right: Theme Toggle + Notifications + User */}
          <div className="flex items-center gap-2 ml-auto">
            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="theme-toggle"
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              id="theme-toggle-btn"
            >
              {theme === 'dark' ? (
                <Sun className="w-5 h-5" />
              ) : (
                <Moon className="w-5 h-5" />
              )}
            </button>

            {/* Notifications */}
            <div className="relative dropdown-container">
              <button
                onClick={(e) => { e.stopPropagation(); setShowNotifications(!showNotifications); setShowUserMenu(false); }}
                className="relative p-2 text-dark-500 dark:text-dark-400 hover:text-dark-900 dark:hover:text-white hover:bg-dark-100 dark:hover:bg-dark-700 rounded-lg transition-all"
              >
                <Bell className="w-5 h-5" />
                {notifications.length > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                )}
              </button>

              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-600 rounded-xl shadow-2xl py-2 z-[100] animate-slide-down">
                  <div className="px-4 py-2 border-b border-dark-200 dark:border-dark-700 flex items-center justify-between">
                    <span className="text-sm font-medium text-dark-900 dark:text-white">Notifications</span>
                    <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded-full">{notifications.length}</span>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="px-4 py-8 text-center text-dark-400">
                        <Bell className="w-8 h-8 mx-auto mb-2 opacity-50" />
                        <p className="text-sm">No notifications</p>
                      </div>
                    ) : (
                      notifications.map((notif) => (
                        <div key={notif.id} className="px-4 py-3 hover:bg-dark-50 dark:hover:bg-dark-700 transition-colors border-b border-dark-100 dark:border-dark-700/50 last:border-0">
                          <div className="flex items-start gap-3">
                            <div className={`mt-1 p-1 rounded ${notif.type === 'success' ? 'bg-green-500/20' :
                                notif.type === 'warning' ? 'bg-yellow-500/20' :
                                  'bg-blue-500/20'
                              }`}>
                              {notif.type === 'success' && <CheckCircle className="w-4 h-4 text-green-400" />}
                              {notif.type === 'warning' && <AlertCircle className="w-4 h-4 text-yellow-400" />}
                              {notif.type === 'info' && <Info className="w-4 h-4 text-blue-400" />}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-dark-900 dark:text-white">{notif.title}</div>
                              <div className="text-xs text-dark-500 dark:text-dark-400 truncate">{notif.message}</div>
                              <div className="text-xs text-dark-400 dark:text-dark-500 mt-1">{notif.time}</div>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* User menu */}
            <div className="relative dropdown-container">
              <button
                onClick={(e) => { e.stopPropagation(); setShowUserMenu(!showUserMenu); setShowNotifications(false); }}
                className="flex items-center gap-3 p-2 hover:bg-dark-100 dark:hover:bg-dark-700 rounded-lg transition-all"
              >
                <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-semibold">
                    {user?.name?.charAt(0) || 'A'}
                  </span>
                </div>
                <div className="hidden md:block text-left">
                  <div className="text-sm font-medium text-dark-900 dark:text-white">{user?.name || 'Admin'}</div>
                  <div className="text-xs text-dark-500 dark:text-dark-400">{user?.role || 'superadmin'}</div>
                </div>
              </button>

              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-600 rounded-xl shadow-2xl py-2 z-[100] animate-slide-down">
                  <div className="px-4 py-3 border-b border-dark-200 dark:border-dark-700">
                    <div className="text-sm font-medium text-dark-900 dark:text-white">{user?.name}</div>
                    <div className="text-xs text-dark-500 dark:text-dark-400">{user?.email}</div>
                  </div>

                  <button
                    onClick={() => { navigate('/settings'); setShowUserMenu(false); }}
                    className="w-full flex items-center gap-3 px-4 py-3 text-dark-600 dark:text-dark-300 hover:bg-dark-50 dark:hover:bg-dark-700 hover:text-dark-900 dark:hover:text-white transition-all"
                  >
                    <Settings className="w-4 h-4" />
                    Settings
                  </button>

                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-3 px-4 py-3 text-red-500 dark:text-red-400 hover:bg-dark-50 dark:hover:bg-dark-700 transition-all"
                  >
                    <LogOut className="w-4 h-4" />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      <style jsx>{`
        @keyframes slide-down {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-slide-down {
          animation: slide-down 0.2s ease-out;
        }
      `}</style>
    </>
  );
}
