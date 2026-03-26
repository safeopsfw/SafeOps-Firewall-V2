import { Link, Outlet, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Shield, 
  Database,
  Search,
  BarChart3,
  Settings
} from 'lucide-react';

const subNavigation = [
  { name: 'Dashboard', path: '/threat-intel', icon: LayoutDashboard },
  { name: 'Feeds', path: '/threat-intel/feeds', icon: Database },
  { name: 'Indicators', path: '/threat-intel/indicators', icon: Search },
  { name: 'Analytics', path: '/threat-intel/analytics', icon: BarChart3 },
];

export default function ThreatIntelLayout() {
  const location = useLocation();

  return (
    <div className="animate-fade-in">
      {/* Sub Navigation */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        {subNavigation.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg whitespace-nowrap transition-colors ${
                isActive
                  ? 'bg-primary-500 text-dark-900 dark:text-white'
                  : 'bg-white dark:bg-dark-800 text-dark-600 dark:text-dark-300 hover:bg-dark-100 dark:hover:bg-dark-700 hover:text-dark-900 dark:hover:text-dark-900 dark:text-white shadow-sm'
              }`}
            >
              <Icon className="w-4 h-4" />
              {item.name}
            </Link>
          );
        })}
      </div>

      {/* Page Content */}
      <Outlet />
    </div>
  );
}
