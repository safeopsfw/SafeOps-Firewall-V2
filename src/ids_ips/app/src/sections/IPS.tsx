import { useState } from 'react';
import { useBlocked, useCapture } from '@/hooks/useApi';
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
  Shield, 
  Ban, 
  Play, 
  Pause, 
  Plus,
  X,
  Clock,
  AlertTriangle
} from 'lucide-react';
import type { BlockedEntry } from '@/types';

export function IPS() {
  const { blocked, loading, unblockIP, unblockFlow } = useBlocked();
  const { stats: captureStats, isRunning, start, stop, pause } = useCapture();
  const [newBlockIP, setNewBlockIP] = useState('');
  const [activeTab, setActiveTab] = useState<'blocked' | 'flows'>('blocked');

  const handleBlockIP = async () => {
    if (!newBlockIP) return;
    
    try {
      await fetch('http://localhost:8080/api/v1/ips/block/ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: newBlockIP, reason: 'Manual block' }),
      });
      setNewBlockIP('');
    } catch (err) {
      console.error('Error blocking IP:', err);
    }
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getRemainingTime = (expires: string) => {
    const remaining = new Date(expires).getTime() - Date.now();
    if (remaining <= 0) return 'Expired';
    const hours = Math.floor(remaining / (1000 * 60 * 60));
    const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${minutes}m`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">IPS Management</h1>
          <p className="text-muted-foreground mt-1">
            Manage inline prevention and blocked entities
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isRunning ? (
            <>
              <Button variant="outline" onClick={pause}>
                <Pause className="h-4 w-4 mr-2" />
                Pause
              </Button>
              <Button variant="destructive" onClick={stop}>
                <X className="h-4 w-4 mr-2" />
                Stop
              </Button>
            </>
          ) : (
            <Button onClick={start}>
              <Play className="h-4 w-4 mr-2" />
              Start Capture
            </Button>
          )}
        </div>
      </div>

      {/* Capture Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{captureStats?.packets_read || 0}</div>
            <p className="text-xs text-muted-foreground">Packets Read</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{captureStats?.packets_dropped || 0}</div>
            <p className="text-xs text-muted-foreground">Packets Dropped</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{blocked.blocked_ips?.length || 0}</div>
            <p className="text-xs text-muted-foreground">Blocked IPs</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{blocked.blocked_flows?.length || 0}</div>
            <p className="text-xs text-muted-foreground">Blocked Flows</p>
          </CardContent>
        </Card>
      </div>

      {/* Block IP */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Ban className="h-5 w-5" />
            Block IP Address
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input
              placeholder="Enter IP address to block..."
              value={newBlockIP}
              onChange={(e) => setNewBlockIP(e.target.value)}
              className="flex-1"
            />
            <Button onClick={handleBlockIP}>
              <Plus className="h-4 w-4 mr-2" />
              Block
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        <button
          className={`px-4 py-2 font-medium ${activeTab === 'blocked' ? 'border-b-2 border-primary' : 'text-muted-foreground'}`}
          onClick={() => setActiveTab('blocked')}
        >
          Blocked IPs ({blocked.blocked_ips?.length || 0})
        </button>
        <button
          className={`px-4 py-2 font-medium ${activeTab === 'flows' ? 'border-b-2 border-primary' : 'text-muted-foreground'}`}
          onClick={() => setActiveTab('flows')}
        >
          Blocked Flows ({blocked.blocked_flows?.length || 0})
        </button>
      </div>

      {/* Blocked IPs Table */}
      {activeTab === 'blocked' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Blocked IP Addresses
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8 text-muted-foreground">Loading...</div>
            ) : blocked.blocked_ips?.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No blocked IPs</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Blocked At</TableHead>
                      <TableHead>Expires In</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blocked.blocked_ips?.map((entry: BlockedEntry, index: number) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono">{entry.ip}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-red-500/10 text-red-500">
                            {entry.reason}
                          </Badge>
                        </TableCell>
                        <TableCell>{formatTime(entry.timestamp)}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1 text-sm">
                            <Clock className="h-4 w-4" />
                            {getRemainingTime(entry.expires)}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => entry.ip && unblockIP(entry.ip)}
                          >
                            <X className="h-4 w-4 mr-1" />
                            Unblock
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Blocked Flows Table */}
      {activeTab === 'flows' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Blocked Flows
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8 text-muted-foreground">Loading...</div>
            ) : blocked.blocked_flows?.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No blocked flows</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Flow ID</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Blocked At</TableHead>
                      <TableHead>Expires In</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blocked.blocked_flows?.map((entry: BlockedEntry, index: number) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono">{entry.flow_id}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="bg-red-500/10 text-red-500">
                            {entry.reason}
                          </Badge>
                        </TableCell>
                        <TableCell>{formatTime(entry.timestamp)}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1 text-sm">
                            <Clock className="h-4 w-4" />
                            {getRemainingTime(entry.expires)}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => entry.flow_id && unblockFlow(entry.flow_id)}
                          >
                            <X className="h-4 w-4 mr-1" />
                            Unblock
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
