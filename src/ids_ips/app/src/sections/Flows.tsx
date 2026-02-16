import { useState } from 'react';
import { useFlows } from '@/hooks/useApi';
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
  Network, 
  Search, 
  RefreshCw,
  ArrowRight,
  ArrowLeft
} from 'lucide-react';
import type { Flow } from '@/types';

function StateBadge({ state }: { state: string }) {
  const variants: Record<string, string> = {
    NEW: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    ESTABLISHED: 'bg-green-500/10 text-green-500 border-green-500/20',
    CLOSED: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
    RESET: 'bg-red-500/10 text-red-500 border-red-500/20',
    TIMED_OUT: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  };

  return (
    <Badge variant="outline" className={variants[state] || variants.NEW}>
      {state}
    </Badge>
  );
}

function ProtocolBadge({ protocol }: { protocol: number }) {
  const protocols: Record<number, string> = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6',
  };

  return (
    <Badge variant="outline" className="bg-purple-500/10 text-purple-500 border-purple-500/20">
      {protocols[protocol] || `Proto ${protocol}`}
    </Badge>
  );
}

export function Flows() {
  const { flows, loading, refetch } = useFlows();
  const [searchTerm, setSearchTerm] = useState('');

  const filteredFlows = flows.filter((flow: Flow) => {
    return (
      flow.src_ip?.includes(searchTerm) ||
      flow.dst_ip?.includes(searchTerm) ||
      flow.state?.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  const formatBytes = (bytes: number) => {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return bytes + ' B';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Flows</h1>
          <p className="text-muted-foreground mt-1">
            Active network flows and sessions
          </p>
        </div>
        <Button variant="outline" onClick={refetch}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Search */}
      <Card>
        <CardContent className="pt-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search flows by IP or state..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
        </CardContent>
      </Card>

      {/* Flows Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Active Flows ({filteredFlows.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8 text-muted-foreground">Loading flows...</div>
          ) : filteredFlows.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Network className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No active flows</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Flow ID</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead></TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Packets</TableHead>
                    <TableHead>Bytes</TableHead>
                    <TableHead>Duration</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredFlows.map((flow, index) => (
                    <TableRow key={index}>
                      <TableCell className="font-mono text-sm">
                        {flow.flow_id?.toString().slice(-8)}
                      </TableCell>
                      <TableCell>
                        <StateBadge state={flow.state} />
                      </TableCell>
                      <TableCell>
                        <ProtocolBadge protocol={flow.protocol} />
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {flow.src_ip}:{flow.src_port}
                      </TableCell>
                      <TableCell>
                        {flow.pkts_to_server > flow.pkts_to_client ? (
                          <ArrowRight className="h-4 w-4 text-blue-500" />
                        ) : (
                          <ArrowLeft className="h-4 w-4 text-green-500" />
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {flow.dst_ip}:{flow.dst_port}
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          <div>→ {flow.pkts_to_server || 0}</div>
                          <div>← {flow.pkts_to_client || 0}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          <div>→ {formatBytes(flow.bytes_to_server || 0)}</div>
                          <div>← {formatBytes(flow.bytes_to_client || 0)}</div>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {flow.start_time ? 
                          Math.floor((Date.now() - new Date(flow.start_time).getTime()) / 1000) + 's' 
                          : '-'}
                      </TableCell>
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
