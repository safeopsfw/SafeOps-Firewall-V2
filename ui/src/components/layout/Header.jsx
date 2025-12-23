import { useState, useEffect } from 'react';
import { 
  Menu, 
  Bell, 
  User, 
  LogOut, 
  Settings, 
  Sun, 
  Moon,
  Play,
  FlaskConical,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  Clock,
  Upload,
  RotateCcw,
  Trash2,
  Download
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Header({ onMenuClick }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showQuickActions, setShowQuickActions] = useState(false);
  
  // Global Mode State
  const [mode, setMode] = useState('simulation'); // 'simulation' | 'production'
  const [pendingChanges, setPendingChanges] = useState({ rules: 3, feeds: 2 });
  
  // System Health
  const [health, setHealth] = useState({
    ingestionLag: '2.3s',
    ruleLatency: '15ms',
    activeRules: 1234,
    maxRules: 10000,
    feedFreshness: '5 min ago'
  });

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const toggleMode = () => {
    const newMode = mode === 'simulation' ? 'production' : 'simulation';
    if (newMode === 'production') {
      if (!confirm('Switch to PRODUCTION mode? All actions will affect live systems.')) {
        return;
      }
    }
    setMode(newMode);
  };

  return (
    <header className={`border-b px-4 lg:px-6 py-3 ${
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
          
          {/* MODE TOGGLE - Key Feature */}
          <button
            onClick={toggleMode}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
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
          <div className="relative">
            <button
              onClick={() => setShowQuickActions(!showQuickActions)}
              className="flex items-center gap-2 px-3 py-2 bg-dark-700 hover:bg-dark-600 text-dark-300 rounded-lg transition-colors"
            >
              Quick Actions
              <ChevronDown className="w-4 h-4" />
            </button>
            
            {showQuickActions && (
              <div className="absolute right-0 mt-2 w-64 bg-dark-800 border border-dark-600 rounded-xl shadow-xl py-2 z-50 animate-fade-in">
                <button className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-colors">
                  <Upload className="w-4 h-4" />
                  Deploy Staging Config
                </button>
                <button className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-colors">
                  <RotateCcw className="w-4 h-4" />
                  Rollback to Last Known Good
                </button>
                <button className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-colors">
                  <Trash2 className="w-4 h-4" />
                  Flush Simulation Cache
                </button>
                <button className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-colors">
                  <Download className="w-4 h-4" />
                  Export System Snapshot
                </button>
              </div>
            )}
          </div>

          {/* Notifications */}
          <button className="relative p-2 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors">
            <Bell className="w-5 h-5" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
          </button>

          {/* User menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-3 p-2 hover:bg-dark-700 rounded-lg transition-colors"
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
              <div className="absolute right-0 mt-2 w-56 bg-dark-800 border border-dark-600 rounded-xl shadow-xl py-2 z-50 animate-fade-in">
                <div className="px-4 py-3 border-b border-dark-700">
                  <div className="text-sm font-medium text-white">{user?.name}</div>
                  <div className="text-xs text-dark-400">{user?.email}</div>
                </div>
                
                <button
                  onClick={() => { navigate('/settings'); setShowUserMenu(false); }}
                  className="w-full flex items-center gap-3 px-4 py-3 text-dark-300 hover:bg-dark-700 hover:text-white transition-colors"
                >
                  <Settings className="w-4 h-4" />
                  Settings
                </button>
                
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-3 px-4 py-3 text-red-400 hover:bg-dark-700 transition-colors"
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
  );
}
