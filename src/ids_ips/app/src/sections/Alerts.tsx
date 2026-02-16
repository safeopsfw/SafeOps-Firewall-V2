import { useState } from 'react';
import { useAlerts } from '@/hooks/useApi';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table';
import { 
  AlertTriangle, 
  Shield, 
  Search, 
  Filter,
  Download,
  RefreshCw
} from 'lucide-react';
import type { Alert } from '@/types';

function PriorityBadge({ priority }: { priority: number }) {
  const variants: Record<number, { class: string; label: string }> = {
    1: { class: 'bg-red-500/10 text-red-500 border-red-500/20', label: 'Critical' },
    2: { class: 'bg-orange-500/10 text-orange-500 border-orange-500/20', label: 'High' },
    3: { class: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20', label: 'Medium' },
    4: { class: 'bg-blue-500/10 text-blue-500 border-blue-500/20', label: 'Low' },
  };

  const variant = variants[priority] || variants[4];

  return (
    <Badge variant="outline" className={variant.class}>
      {variant.label}
    </Badge>
  );
}

function ActionBadge({ action }: { action: string }) {
  const variants: Record<string, string> = {
    alert: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    drop: 'bg-red-500/10 text-red-500 border-red-500/20',
    pass: 'bg-green-500/10 text-green-500 border-green-500/20',
    reject: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  };

  return (
    <Badge variant="outline" className={variants[action] || variants.alert}>
      {action.toUpperCase()}
    </Badge>
  );
}

export function Alerts() {
  const { alerts, loading } = useAlerts(100);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterPriority, setFilterPriority] = useState<number | null>(null);

  const filteredAlerts = alerts.filter((alert: Alert) => {
    const matchesSearch = 
      alert.message?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.src_ip?.includes(searchTerm) ||
      alert.dst_ip?.includes(searchTerm) ||
      alert.category?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesPriority = filterPriority ? alert.priority === filterPriority : true;
    
    return matchesSearch && matchesPriority;
  });

  const exportAlerts = () => {
    const dataStr = JSON.stringify(alerts, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `alerts-${new Date().toISOString()}.json`;
    link.click();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Alerts</h1>
          <p className="text-muted-foreground mt-1">
            View and manage security alerts
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={exportAlerts}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Button variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Priority:</span>
              <Button
                variant={filterPriority === null ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterPriority(null)}
              >
                All
              </Button>
              <Button
                variant={filterPriority === 1 ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterPriority(1)}
                className="text-red-500"
              >
                Critical
              </Button>
              <Button
                variant={filterPriority === 2 ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterPriority(2)}
                className="text-orange-500"
              >
                High
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Alerts Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            Security Alerts ({filteredAlerts.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8 text-muted-foreground">Loading alerts...</div>
          ) : filteredAlerts.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No alerts found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>SID</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAlerts.map((alert, index) => (
                    <TableRow key={index}>
                      <TableCell className="whitespace-nowrap">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <PriorityBadge priority={alert.priority} />
                      </TableCell>
                      <TableCell>
                        <ActionBadge action={alert.action} />
                      </TableCell>
                      <TableCell className="max-w-md truncate" title={alert.message}>
                        {alert.message}
                      </TableCell>
                      <TableCell>{alert.category}</TableCell>
                      <TableCell className="font-mono text-sm">
                        {alert.src_ip}:{alert.src_port}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {alert.dst_ip}:{alert.dst_port}
                      </TableCell>
                      <TableCell className="font-mono">{alert.sid}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
