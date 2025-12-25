import { useState, useEffect } from 'react';
import { 
  Menu, 
  Bell, 
  User, 
  LogOut, 
  Settings, 
  Play,
  FlaskConical,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  Clock,
  Upload,
  RotateCcw,
  Trash2,
  Download,
  X,
  Zap,
  Info,
  AlertCircle
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Header({ onMenuClick }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showQuickActions, setShowQuickActions] = useState(false);
  const [showModeModal, setShowModeModal] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  
  // Mock notifications
  const [notifications] = useState([
    { id: 1, type: 'success', title: 'Feed Updated', message: 'AlienVault OTX sync completed', time: '2 min ago' },
    { id: 2, type: 'warning', title: 'High Traffic', message: 'Unusual spike in IP lookups', time: '15 min ago' },
    { id: 3, type: 'info', title: 'System Update', message: 'New threat intel sources available', time: '1 hr ago' },
  ]);
  
  // Global Mode State
  const [mode, setMode] = useState('simulation');
  const [pendingChanges, setPendingChanges] = useState({ rules: 3, feeds: 2 });
  
  // System Health
  const [health, setHealth] = useState({
    ingestionLag: '2.3s',
    ruleLatency: '15ms',
    activeRules: 1234,
    maxRules: 10000,
    feedFreshness: '5 min ago'
  });

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (!e.target.closest('.dropdown-container')) {
        setShowQuickActions(false);
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

  const toggleMode = () => {
    setShowModeModal(true);
  };

  const confirmModeChange = () => {
    const newMode = mode === 'simulation' ? 'production' : 'simulation';
    setMode(newMode);
    setShowModeModal(false);
  };

  return (
    <>
      <header className={`border-b px-4 lg:px-6 py-3 relative z-40 ${
        mode === 'production' 
          ? 'bg-red-950/30 border-red-500/30' 
          : 'bg-dark-800 border-dark-700'
      }`}>
        <div className="flex items-center justify-between">
          {/* Left: Menu + Mode Toggle */}
          <div className="flex items-center gap-4">
            <button
              onClick={onMenuClick}
              className="lg:hidden p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
            >
              <Menu className="w-6 h-6" />
            </button>
            
            {/* MODE TOGGLE */}
            <button
              onClick={toggleMode}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all transform hover:scale-105 ${
                mode === 'production'
                  ? 'bg-red-500/20 text-red-400 border border-red-500/50 hover:bg-red-500/30'
                  : 'bg-blue-500/20 text-blue-400 border border-blue-500/50 hover:bg-blue-500/30'
              }`}
            >
              {mode === 'production' ? (
                <>
                  <Play className="w-4 h-4" />
                  PRODUCTION
                </>
              ) : (
                <>
                  <FlaskConical className="w-4 h-4" />
                  SIMULATION
                </>
              )}
            </button>

            {/* Pending Changes Indicator */}
            {(pendingChanges.rules > 0 || pendingChanges.feeds > 0) && (
              <button 
                onClick={() => navigate('/staging')}
                className="flex items-center gap-2 px-3 py-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm hover:bg-yellow-500/20 transition-colors"
              >
                <Clock className="w-4 h-4" />
                <span>Unpublished: {pendingChanges.rules} rules, {pendingChanges.feeds} feeds</span>
              </button>
            )}
          </div>

          {/* Center: System Health */}
          <div className="hidden xl:flex items-center gap-6 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-dark-500">Ingestion:</span>
              <span className={`font-mono ${parseFloat(health.ingestionLag) < 5 ? 'text-green-400' : 'text-red-400'}`}>
                {health.ingestionLag}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-dark-500">Rules:</span>
              <span className="text-white font-mono">{health.activeRules.toLocaleString()}/{health.maxRules.toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-dark-500">Feed:</span>
              <span className="text-green-400">{health.feedFreshness}</span>
            </div>
          </div>

          {/* Right: Actions + User */}
          <div className="flex items-center gap-2">
            {/* Quick Actions */}
            <div className="relative dropdown-container">
              <button
                onClick={(e) => { e.stopPropagation(); setShowQuickActions(!showQuickActions); setShowNotifications(false); setShowUserMenu(false); }}
                className="flex items-center gap-2 px-3 py-2 bg-dark-700 hover:bg-dark-600 text-dark-300 rounded-lg transition-all hover:text-white"
              >
                Quick Actions
                <ChevronDown className={`w-4 h-4 transition-transform ${showQuickActions ? 'rotate-180' : ''}`} />
              </button>
              
              {showQuickActions && (
                <div className="absolute right-0 mt-2 w-64 border border-dark-600 rounded-xl shadow-2xl py-2 z-[100] animate-slide-down" style={{backgroundColor: '#111111'}}>
                  <div className="px-4 py-2 border-b border-dark-700">
                    <span className="text-xs text-dark-400 font-medium">QUICK ACTIONS</span>
                  </div>
                  <button 
                    onClick={() => { alert('Deploying staging config...'); setShowQuickActions(false); }}
                    className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-all"
                  >
                    <Upload className="w-4 h-4 text-green-400" />
                    Deploy Staging Config
                  </button>
                  <button 
                    onClick={() => { alert('Rolling back to last known good...'); setShowQuickActions(false); }}
                    className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-all"
                  >
                    <RotateCcw className="w-4 h-4 text-yellow-400" />
                    Rollback to Last Known Good
                  </button>
                  <button 
                    onClick={() => { alert('Flushing simulation cache...'); setShowQuickActions(false); }}
                    className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-all"
                  >
                    <Trash2 className="w-4 h-4 text-red-400" />
                    Flush Simulation Cache
                  </button>
                  <button 
                    onClick={() => { alert('Exporting system snapshot...'); setShowQuickActions(false); }}
                    className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-all"
                  >
                    <Download className="w-4 h-4 text-blue-400" />
                    Export System Snapshot
                  </button>
                </div>
              )}
            </div>

            {/* Notifications */}
            <div className="relative dropdown-container">
              <button 
                onClick={(e) => { e.stopPropagation(); setShowNotifications(!showNotifications); setShowQuickActions(false); setShowUserMenu(false); }}
                className="relative p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-all"
              >
                <Bell className="w-5 h-5" />
                {notifications.length > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                )}
              </button>

              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 border border-dark-600 rounded-xl shadow-2xl py-2 z-[100] animate-slide-down" style={{backgroundColor: '#111111'}}>
                  <div className="px-4 py-2 border-b border-dark-700 flex items-center justify-between">
                    <span className="text-sm font-medium text-white">Notifications</span>
                    <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded-full">{notifications.length}</span>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {notifications.map((notif) => (
                      <div key={notif.id} className="px-4 py-3 hover:bg-dark-700 transition-colors border-b border-dark-700/50 last:border-0">
                        <div className="flex items-start gap-3">
                          <div className={`mt-1 p-1 rounded ${
                            notif.type === 'success' ? 'bg-green-500/20' :
                            notif.type === 'warning' ? 'bg-yellow-500/20' :
                            'bg-blue-500/20'
                          }`}>
                            {notif.type === 'success' && <CheckCircle className="w-4 h-4 text-green-400" />}
                            {notif.type === 'warning' && <AlertCircle className="w-4 h-4 text-yellow-400" />}
                            {notif.type === 'info' && <Info className="w-4 h-4 text-blue-400" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-white">{notif.title}</div>
                            <div className="text-xs text-dark-400 truncate">{notif.message}</div>
                            <div className="text-xs text-dark-500 mt-1">{notif.time}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="px-4 py-2 border-t border-dark-700">
                    <button className="text-sm text-primary-400 hover:text-primary-300 w-full text-center">
                      View All Notifications
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* User menu */}
            <div className="relative dropdown-container">
              <button
                onClick={(e) => { e.stopPropagation(); setShowUserMenu(!showUserMenu); setShowQuickActions(false); setShowNotifications(false); }}
                className="flex items-center gap-3 p-2 hover:bg-dark-700 rounded-lg transition-all"
              >
                <div className="w-8 h-8 bg-gradient-to-br from-primary-500 to-primary-600 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-semibold">
                    {user?.name?.charAt(0) || 'A'}
                  </span>
                </div>
                <div className="hidden md:block text-left">
                  <div className="text-sm font-medium text-white">{user?.name || 'Admin'}</div>
                  <div className="text-xs text-dark-400">{user?.role || 'superadmin'}</div>
                </div>
              </button>

              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-56 border border-dark-600 rounded-xl shadow-2xl py-2 z-[100] animate-slide-down" style={{backgroundColor: '#111111'}}>
                  <div className="px-4 py-3 border-b border-dark-700">
                    <div className="text-sm font-medium text-white">{user?.name}</div>
                    <div className="text-xs text-dark-400">{user?.email}</div>
                  </div>
                  
                  <button
                    onClick={() => { navigate('/settings'); setShowUserMenu(false); }}
                    className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-all"
                  >
                    <Settings className="w-4 h-4" />
                    Settings
                  </button>
                  
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-3 px-4 py-3 text-red-400 hover:bg-dark-700 transition-all"
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

      {/* Mode Switch Modal */}
      {showModeModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[200]">
          <div className="bg-dark-900 rounded-xl border border-dark-600 p-6 w-full max-w-md mx-4 animate-scale-in shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white flex items-center gap-2">
                <Zap className="w-6 h-6 text-yellow-400" />
                Switch Mode
              </h3>
              <button 
                onClick={() => setShowModeModal(false)}
                className="p-1 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="space-y-4">
              {/* Current Mode */}
              <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
                <div className="text-sm text-dark-400 mb-1">Current Mode</div>
                <div className={`text-lg font-semibold ${mode === 'simulation' ? 'text-blue-400' : 'text-red-400'}`}>
                  {mode === 'simulation' ? '🧪 SIMULATION' : '🚀 PRODUCTION'}
                </div>
              </div>

              {/* Target Mode */}
              <div className={`p-4 rounded-lg border-2 ${
                mode === 'simulation' 
                  ? 'bg-red-500/10 border-red-500/30' 
                  : 'bg-blue-500/10 border-blue-500/30'
              }`}>
                <div className="text-sm text-dark-400 mb-1">Switch To</div>
                <div className={`text-lg font-semibold ${mode === 'simulation' ? 'text-red-400' : 'text-blue-400'}`}>
                  {mode === 'simulation' ? '🚀 PRODUCTION' : '🧪 SIMULATION'}
                </div>
                <p className={`text-sm mt-2 ${mode === 'simulation' ? 'text-red-300' : 'text-blue-300'}`}>
                  {mode === 'simulation' 
                    ? '⚠️ All actions will affect LIVE systems!' 
                    : '✓ Actions will be tested in sandbox environment'}
                </p>
              </div>

              {/* What changes */}
              <div className="p-3 bg-dark-800 rounded-lg text-sm text-dark-300 border border-dark-700">
                <div className="font-medium mb-2 text-white">What happens:</div>
                <ul className="space-y-1">
                  {mode === 'simulation' ? (
                    <>
                      <li>• Rules will be applied to live traffic</li>
                      <li>• Feed updates will affect production database</li>
                      <li>• Firewall rules will block real connections</li>
                    </>
                  ) : (
                    <>
                      <li>• Rules will only be tested, not applied</li>
                      <li>• Feed updates go to staging database</li>
                      <li>• No real connections will be blocked</li>
                    </>
                  )}
                </ul>
              </div>
            </div>
            
            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowModeModal(false)}
                className="px-4 py-2 text-dark-300 hover:text-white hover:bg-dark-700 rounded-lg transition-all"
              >
                Cancel
              </button>
              <button
                onClick={confirmModeChange}
                className={`px-4 py-2 rounded-lg font-medium transition-all transform hover:scale-105 ${
                  mode === 'simulation'
                    ? 'bg-red-500 hover:bg-red-600 text-white'
                    : 'bg-blue-500 hover:bg-blue-600 text-white'
                }`}
              >
                {mode === 'simulation' ? 'Switch to Production' : 'Switch to Simulation'}
              </button>
            </div>
          </div>
        </div>
      )}

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
        @keyframes scale-in {
          from {
            opacity: 0;
            transform: scale(0.95);
          }
          to {
            opacity: 1;
            transform: scale(1);
          }
        }
        .animate-slide-down {
          animation: slide-down 0.2s ease-out;
        }
        .animate-scale-in {
          animation: scale-in 0.2s ease-out;
        }
      `}</style>
    </>
  );
}
