import { useStats, useStatus } from '@/hooks/useApi';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Activity,
  Shield,
  AlertTriangle,
  Network,
  FileText,
  Clock,
  CheckCircle,
  XCircle
} from 'lucide-react';

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'blue',
  trend
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ElementType;
  color?: 'blue' | 'green' | 'red' | 'yellow' | 'purple';
  trend?: { value: number; positive: boolean };
}) {
  const colorClasses = {
    blue: 'bg-blue-500/10 text-blue-500',
    green: 'bg-green-500/10 text-green-500',
    red: 'bg-red-500/10 text-red-500',
    yellow: 'bg-yellow-500/10 text-yellow-500',
    purple: 'bg-purple-500/10 text-purple-500',
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
        <div className={`p-2 rounded-lg ${colorClasses[color]}`}>
          <Icon className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {subtitle && (
          <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>
        )}
        {trend && (
          <div className={`flex items-center mt-2 text-xs ${trend.positive ? 'text-green-500' : 'text-red-500'}`}>
            {trend.positive ? '+' : '-'}{trend.value}%
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function StatusBadge({ status, text }: { status: 'success' | 'warning' | 'error'; text: string }) {
  const variants = {
    success: 'bg-green-500/10 text-green-500 border-green-500/20',
    warning: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    error: 'bg-red-500/10 text-red-500 border-red-500/20',
  };

  return (
    <Badge variant="outline" className={variants[status]}>
      {status === 'success' && <CheckCircle className="w-3 h-3 mr-1" />}
      {status === 'warning' && <AlertTriangle className="w-3 h-3 mr-1" />}
      {status === 'error' && <XCircle className="w-3 h-3 mr-1" />}
      {text}
    </Badge>
  );
}

export function Dashboard() {
  const { stats } = useStats();
  const { status } = useStatus();

  const formatNumber = (num: number) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1099511627776) return (bytes / 1099511627776).toFixed(1) + ' TB';
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  };

  const uptime = status?.uptime ? Math.floor(status.uptime / 3600) + 'h ' +
    Math.floor((status.uptime % 3600) / 60) + 'm' : '-';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Real-time IDS/IPS monitoring and statistics
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-sm text-muted-foreground">System Status</div>
            <div className="font-medium">{status?.status || 'Unknown'}</div>
          </div>
          <StatusBadge
            status={status?.capture_status ? 'success' : 'error'}
            text={status?.capture_status ? 'Running' : 'Stopped'}
          />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Packets Processed"
          value={formatNumber(stats?.detection.packets_processed || 0)}
          subtitle="Total packets analyzed"
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Alerts Generated"
          value={formatNumber(stats?.detection.alerts_generated || 0)}
          subtitle="Security events detected"
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="Active Flows"
          value={formatNumber(stats?.flow.flows_active || 0)}
          subtitle="Current network sessions"
          icon={Network}
          color="purple"
        />
        <StatCard
          title="Packets Blocked"
          value={formatNumber(stats?.ips.packets_blocked || 0)}
          subtitle="Blocked by IPS"
          icon={Shield}
          color="green"
        />
      </div>

      {/* Secondary Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <FileText className="h-5 w-5" />
              JSONL Reader Statistics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Packets Read</span>
              <span className="font-medium">{formatNumber(stats?.capture.packets_read || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Packets Dropped</span>
              <span className="font-medium">{formatNumber(stats?.capture.packets_dropped || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Bytes Read</span>
              <span className="font-medium">{formatBytes(stats?.capture.bytes_read || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Files Processed</span>
              <span className="font-medium">{stats?.capture.files_processed || 0}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Shield className="h-5 w-5" />
              IPS Statistics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Packets Blocked</span>
              <span className="font-medium text-red-500">{formatNumber(stats?.ips.packets_blocked || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Packets Passed</span>
              <span className="font-medium text-green-500">{formatNumber(stats?.ips.packets_passed || 0)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Flows Blocked</span>
              <span className="font-medium">{stats?.ips.flows_blocked || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">IPs Blocked</span>
              <span className="font-medium">{stats?.ips.ips_blocked || 0}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Clock className="h-5 w-5" />
              System Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Version</span>
              <span className="font-medium">{status?.version || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Uptime</span>
              <span className="font-medium">{uptime}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Rules Loaded</span>
              <span className="font-medium">{status?.rules_loaded || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Flows Active</span>
              <span className="font-medium">{status?.flows_active || 0}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Detection Stats */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Detection Engine Statistics
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="text-center p-4 bg-muted rounded-lg">
              <div className="text-2xl font-bold">{formatNumber(stats?.detection.packets_processed || 0)}</div>
              <div className="text-xs text-muted-foreground mt-1">Packets Processed</div>
            </div>
            <div className="text-center p-4 bg-muted rounded-lg">
              <div className="text-2xl font-bold">{formatNumber(stats?.detection.alerts_generated || 0)}</div>
              <div className="text-xs text-muted-foreground mt-1">Alerts Generated</div>
            </div>
            <div className="text-center p-4 bg-muted rounded-lg">
              <div className="text-2xl font-bold">{stats?.detection.rules_loaded || 0}</div>
              <div className="text-xs text-muted-foreground mt-1">Rules Loaded</div>
            </div>
            <div className="text-center p-4 bg-muted rounded-lg">
              <div className="text-2xl font-bold">{formatNumber(stats?.detection.rules_evaluated || 0)}</div>
              <div className="text-xs text-muted-foreground mt-1">Rules Evaluated</div>
            </div>
            <div className="text-center p-4 bg-muted rounded-lg">
              <div className="text-2xl font-bold">{formatNumber(stats?.detection.rules_matched || 0)}</div>
              <div className="text-xs text-muted-foreground mt-1">Rules Matched</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
