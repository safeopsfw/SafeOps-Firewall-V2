import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  Server,
  Database,
  Settings,
  Activity,
  AlertTriangle,
  Zap,
  Network,
  Lock,
  RefreshCw,
  FlaskConical,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { dataService, isDbMode, getDataSource } from "../services/api";

const modules = [
  {
    id: "threat-intel",
    name: "Threat Intelligence",
    description: "IOC analysis, threat feeds, and intelligence data",
    icon: Shield,
    color: "from-blue-500 to-blue-600",
    path: "/threat-intel",
    statsKey: "activeIOCs",
    statsLabel: "Active IOCs",
    status: "active",
  },
  {
    id: "firewall",
    name: "Firewall",
    description: "Network firewall rules and policies",
    icon: Lock,
    color: "from-orange-500 to-orange-600",
    path: "/firewall",
    statsKey: "firewallRules",
    statsLabel: "Active Rules",
    status: "active",
  },
  {
    id: "ids",
    name: "IDS/IPS",
    description: "Intrusion detection and prevention",
    icon: AlertTriangle,
    color: "from-red-500 to-red-600",
    path: "/ids",
    statsKey: "idsAlerts",
    statsLabel: "Alerts Today",
    status: "active",
  },
  {
    id: "network",
    name: "Network Monitor",
    description: "Network traffic analysis and monitoring",
    icon: Network,
    color: "from-purple-500 to-purple-600",
    path: "/network",
    statsKey: "connections",
    statsLabel: "Connections",
    status: "active",
  },
  {
    id: "cognitive",
    name: "Cognitive Library",
    description: "Entity management and data models",
    icon: Database,
    color: "from-indigo-500 to-indigo-600",
    path: "/cognitive",
    statsKey: "entities",
    statsLabel: "Entities",
    status: "active",
  },
];

export default function Dashboard() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    totalThreatsBlocked: 0,
    activeFeeds: 0,
    systemHealth: 0,
    openAlerts: 0,
    activeIOCs: 0,
    dnsQueries: 0,
    firewallRules: 0,
    idsAlerts: 0,
    connections: 0,
    entities: 0,
  });

  const dbMode = isDbMode();

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const dashboardStats = await dataService.getDashboardStats();
      setStats({
        totalThreatsBlocked: dashboardStats.totalThreatsBlocked || 0,
        activeFeeds: dashboardStats.activeFeeds || 0,
        systemHealth: dashboardStats.systemHealth || 100,
        openAlerts: dashboardStats.openAlerts || 0,
        activeIOCs: dashboardStats.activeIOCs || 0,
        dnsQueries: dashboardStats.dnsQueries || 0,
        firewallRules: dashboardStats.firewallRules || 0,
        idsAlerts: dashboardStats.idsAlerts || 0,
        connections: dashboardStats.connections || 0,
        entities: dashboardStats.entities || 0,
      });
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  const quickStats = [
    {
      label: "Total Threats Blocked",
      value: stats.totalThreatsBlocked.toLocaleString(),
      change: null,
      positive: true,
    },
    {
      label: "Active Feeds",
      value: stats.activeFeeds.toString(),
      change: null,
      positive: true,
    },
    {
      label: "System Health",
      value: `${stats.systemHealth}%`,
      change: null,
      positive: true,
    },
    {
      label: "Open Alerts",
      value: stats.openAlerts.toString(),
      change: null,
      positive: stats.openAlerts === 0,
    },
  ];

  return (
    <div className="animate-fade-in">
      {/* Data Source Indicator */}
      <div
        className={`mb-4 flex items-center gap-2 text-sm ${dbMode ? "text-green-500 dark:text-green-400" : "text-blue-500 dark:text-blue-400"
          }`}
      >
        {dbMode ? (
          <>
            <Database className="w-4 h-4" />
            <span>Database Mode - Fetching real data</span>
            {loading && <RefreshCw className="w-4 h-4 animate-spin ml-2" />}
          </>
        ) : (
          <>
            <FlaskConical className="w-4 h-4" />
            <span>Demo Mode - Using mock data</span>
          </>
        )}
      </div>

      {/* Welcome Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-dark-900 dark:text-white mb-2">
          Welcome back, {user?.name?.split(" ")[0] || "Admin"}
        </h1>
        <p className="text-dark-500 dark:text-dark-400">
          Here's what's happening with your security infrastructure
        </p>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {quickStats.map((stat) => (
          <div
            key={stat.label}
            className="bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-5 transition-colors"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-dark-500 dark:text-dark-400 text-sm">{stat.label}</span>
              {stat.change && (
                <span
                  className={`text-xs px-2 py-1 rounded-full ${stat.positive
                    ? "bg-green-500/20 text-green-500 dark:text-green-400"
                    : "bg-red-500/20 text-red-500 dark:text-red-400"
                    }`}
                >
                  {stat.change}
                </span>
              )}
            </div>
            <div className="text-2xl font-bold text-dark-900 dark:text-white">{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Modules Grid */}
      <h2 className="text-xl font-semibold text-dark-900 dark:text-white mb-4">
        Security Modules
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {modules.map((module) => {
          const Icon = module.icon;
          const isActive = module.status === "active";
          const statValue = stats[module.statsKey] || 0;

          return (
            <Link
              key={module.id}
              to={isActive ? module.path : "#"}
              className={`group relative bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-6 transition-all duration-300 ${isActive
                ? "hover:bg-dark-50 dark:hover:bg-dark-700 hover:border-dark-300 dark:hover:border-dark-300 dark:border-dark-600 cursor-pointer"
                : "opacity-60 cursor-not-allowed"
                }`}
            >
              {/* Status Badge */}
              {!isActive && (
                <div className="absolute top-4 right-4 text-xs bg-dark-200 dark:bg-dark-600 text-dark-500 dark:text-dark-300 px-2 py-1 rounded-full">
                  Coming Soon
                </div>
              )}

              {/* Icon */}
              <div
                className={`inline-flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br ${module.color} mb-4`}
              >
                <Icon className="w-6 h-6 text-dark-900 dark:text-white" />
              </div>

              {/* Content */}
              <h3 className="text-lg font-semibold text-dark-900 dark:text-white mb-2">
                {module.name}
              </h3>
              <p className="text-dark-500 dark:text-dark-400 text-sm mb-4">{module.description}</p>

              {/* Stats */}
              <div className="flex items-center justify-between pt-4 border-t border-dark-200 dark:border-dark-700">
                <span className="text-dark-400 dark:text-dark-500 text-sm">
                  {module.statsLabel}
                </span>
                <span className="text-dark-900 dark:text-white font-semibold">
                  {typeof statValue === "number"
                    ? statValue.toLocaleString()
                    : statValue}
                </span>
              </div>

              {/* Hover Arrow */}
              {isActive && (
                <div className="absolute bottom-6 right-6 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Zap className="w-5 h-5 text-primary-400" />
                </div>
              )}
            </Link>
          );
        })}
      </div>

      {/* System Status */}
      <div className="mt-8 bg-white dark:bg-dark-800 border border-dark-200 dark:border-dark-700 rounded-xl p-6 transition-colors">
        <div className="flex items-center gap-3 mb-4">
          <Activity className="w-5 h-5 text-green-500 dark:text-green-400" />
          <h3 className="text-lg font-semibold text-dark-900 dark:text-white">System Status</h3>
          <span className="text-xs bg-green-500/20 text-green-500 dark:text-green-400 px-2 py-1 rounded-full">
            All Systems Operational
          </span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full ${dbMode ? "bg-green-400" : "bg-yellow-400"
                }`}
            />
            <span className="text-dark-600 dark:text-dark-300 text-sm">
              Database {dbMode ? "" : "(Demo)"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-400 rounded-full" />
            <span className="text-dark-600 dark:text-dark-300 text-sm">API Server</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-400 rounded-full" />
            <span className="text-dark-600 dark:text-dark-300 text-sm">Feed Fetcher</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-400 rounded-full" />
            <span className="text-dark-600 dark:text-dark-300 text-sm">Background Worker</span>
          </div>
        </div>
      </div>
    </div>
  );
}
