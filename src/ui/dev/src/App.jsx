import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Cognitive from './pages/Cognitive';
import SettingsPage from './pages/Settings';
import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';

// Threat Intel Module
import ThreatIntelLayout from './pages/ThreatIntel/Layout';
import ThreatIntelDashboard from './pages/ThreatIntel/Dashboard';
import Feeds from './pages/ThreatIntel/Feeds';
import Indicators from './pages/ThreatIntel/Indicators';
import Analytics from './pages/ThreatIntel/Analytics';

// Management Module
import IDSRuleManager from './pages/Management/IDSRuleManager';
import UserManagement from './pages/Management/UserManagement';
import FirewallManager from './pages/Management/FirewallManager';

// Network Management Module
import NetworkLayout from './pages/Network/Layout';
import NICManagement from './pages/NICManagement';
import NICSearch from './pages/Network/NICSearch';
import NetworkTopology from './pages/Network/NetworkTopology';
import NICDetail from './pages/Network/NICDetail';
import StepCAManager from './pages/StepCAManager';
import DHCPMonitor from './pages/DHCPMonitor';

// Protected Route wrapper
function ProtectedRoute() {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-900">
        <div className="w-8 h-8 border-4 border-primary-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

// Main Layout with Sidebar
function MainLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-dark-900">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="flex-1 flex flex-col min-h-screen lg:ml-0">
        <Header onMenuClick={() => setSidebarOpen(true)} />
        <main className="flex-1 p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// Placeholder pages
function ComingSoon({ title }) {
  return (
    <div className="flex flex-col items-center justify-center h-[60vh] text-center animate-fade-in">
      <div className="text-6xl mb-4">🚧</div>
      <h1 className="text-2xl font-bold text-white mb-2">{title}</h1>
      <p className="text-dark-400">This module is coming soon</p>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />

          {/* Protected routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<MainLayout />}>
              {/* Main Dashboard */}
              <Route path="/dashboard" element={<Dashboard />} />

              {/* Threat Intelligence Module */}
              <Route path="/threat-intel" element={<ThreatIntelLayout />}>
                <Route index element={<ThreatIntelDashboard />} />
                <Route path="feeds" element={<Feeds />} />
                <Route path="indicators" element={<Indicators />} />
                <Route path="analytics" element={<Analytics />} />
              </Route>

              {/* Management Routes */}
              <Route path="/manage/users" element={<UserManagement />} />
              <Route path="/manage/feeds" element={<Feeds />} />
              <Route path="/manage/databases" element={<SettingsPage />} />
              <Route path="/manage/ids-rules" element={<IDSRuleManager />} />

              {/* Other Modules */}
              <Route path="/dns" element={<ComingSoon title="DNS Server" />} />
              <Route path="/firewall" element={<FirewallManager />} />
              <Route path="/ids" element={<IDSRuleManager />} />
              {/* Network Management Module */}
              <Route path="/network" element={<NetworkLayout />}>
                <Route index element={<NICManagement />} />
                <Route path="search" element={<NICSearch />} />
                <Route path="topology" element={<NetworkTopology />} />
                <Route path=":nicId" element={<NICDetail />} />
              </Route>
              <Route path="/cognitive" element={<Cognitive />} />
              <Route path="/dhcp-monitor" element={<DHCPMonitor />} />
              <Route path="/certificates" element={<StepCAManager />} />
              <Route path="/step-ca" element={<StepCAManager />} />

              {/* Settings */}
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/staging" element={<ComingSoon title="Staging Config" />} />
            </Route>
          </Route>

          {/* Default redirect */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
