import { useState } from 'react';
import { Dashboard } from '@/sections/Dashboard';
import { Alerts } from '@/sections/Alerts';
import { Flows } from '@/sections/Flows';
import { Rules } from '@/sections/Rules';
import { IPS } from '@/sections/IPS';
import { Button } from '@/components/ui/button';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Network, 
  FileText, 
  Shield,
  Menu,
  X,
  Activity
} from 'lucide-react';

type Tab = 'dashboard' | 'alerts' | 'flows' | 'rules' | 'ips';

function Sidebar({ 
  activeTab, 
  onTabChange, 
  collapsed, 
  onToggle 
}: { 
  activeTab: Tab; 
  onTabChange: (tab: Tab) => void;
  collapsed: boolean;
  onToggle: () => void;
}) {
  const navItems: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
    { id: 'flows', label: 'Flows', icon: Network },
    { id: 'rules', label: 'Rules', icon: FileText },
    { id: 'ips', label: 'IPS', icon: Shield },
  ];

  return (
    <div 
      className={`bg-card border-r flex flex-col transition-all duration-300 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Activity className="h-6 w-6 text-primary" />
            <span className="font-bold text-lg">IDS Engine</span>
          </div>
        )}
        <Button 
          variant="ghost" 
          size="icon" 
          onClick={onToggle}
          className="ml-auto"
        >
          {collapsed ? <Menu className="h-5 w-5" /> : <X className="h-5 w-5" />}
        </Button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                isActive 
                  ? 'bg-primary text-primary-foreground' 
                  : 'hover:bg-muted text-muted-foreground hover:text-foreground'
              }`}
              title={collapsed ? item.label : undefined}
            >
              <Icon className="h-5 w-5 flex-shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      {!collapsed && (
        <div className="p-4 border-t">
          <div className="text-xs text-muted-foreground">
            <div>IDS Engine v1.0.0</div>
            <div className="mt-1">Suricata-compatible</div>
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'alerts':
        return <Alerts />;
      case 'flows':
        return <Flows />;
      case 'rules':
        return <Rules />;
      case 'ips':
        return <IPS />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar 
        activeTab={activeTab} 
        onTabChange={setActiveTab}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      
      <main className="flex-1 overflow-auto">
        <div className="p-6 max-w-7xl mx-auto">
          {renderContent()}
        </div>
      </main>
    </div>
  );
}

export default App;
