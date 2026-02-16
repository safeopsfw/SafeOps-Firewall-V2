import { useState } from 'react';
import { useRules } from '@/hooks/useApi';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table';
import { 
  FileText, 
  Search, 
  RefreshCw,
  Plus,
  Upload,
  Play,
  Pause
} from 'lucide-react';
import type { Rule } from '@/types';

function ActionBadge({ action }: { action: string }) {
  const variants: Record<string, string> = {
    alert: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    drop: 'bg-red-500/10 text-red-500 border-red-500/20',
    pass: 'bg-green-500/10 text-green-500 border-green-500/20',
    reject: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    rejectsrc: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    rejectdst: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    rejectboth: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  };

  return (
    <Badge variant="outline" className={variants[action] || variants.alert}>
      {action.toUpperCase()}
    </Badge>
  );
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  const variants: Record<string, string> = {
    tcp: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    udp: 'bg-green-500/10 text-green-500 border-green-500/20',
    icmp: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
    ip: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
    http: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    dns: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
    tls: 'bg-pink-500/10 text-pink-500 border-pink-500/20',
    ssh: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
  };

  return (
    <Badge variant="outline" className={variants[protocol.toLowerCase()] || variants.ip}>
      {protocol.toUpperCase()}
    </Badge>
  );
}

export function Rules() {
  const { rules, loading, refetch, enableRule, disableRule } = useRules();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRules, setSelectedRules] = useState<Set<number>>(new Set());

  const filteredRules = rules.filter((rule: Rule) => {
    return (
      rule.message?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.sid?.toString().includes(searchTerm) ||
      rule.protocol?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.action?.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  const toggleRule = (sid: number, enabled: boolean) => {
    if (enabled) {
      disableRule(sid);
    } else {
      enableRule(sid);
    }
  };

  const handleBulkEnable = () => {
    selectedRules.forEach(sid => enableRule(sid));
    setSelectedRules(new Set());
  };

  const handleBulkDisable = () => {
    selectedRules.forEach(sid => disableRule(sid));
    setSelectedRules(new Set());
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Rules</h1>
          <p className="text-muted-foreground mt-1">
            Manage detection rules and signatures
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={refetch}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline">
            <Upload className="h-4 w-4 mr-2" />
            Import
          </Button>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            Add Rule
          </Button>
        </div>
      </div>

      {/* Search and Bulk Actions */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search rules by SID, message, protocol..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
            {selectedRules.size > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">
                  {selectedRules.size} selected
                </span>
                <Button size="sm" variant="outline" onClick={handleBulkEnable}>
                  <Play className="h-4 w-4 mr-1" />
                  Enable
                </Button>
                <Button size="sm" variant="outline" onClick={handleBulkDisable}>
                  <Pause className="h-4 w-4 mr-1" />
                  Disable
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Rules Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Detection Rules ({filteredRules.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8 text-muted-foreground">Loading rules...</div>
          ) : filteredRules.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No rules found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">
                      <input 
                        type="checkbox" 
                        className="rounded border-gray-300"
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedRules(new Set(filteredRules.map(r => r.sid)));
                          } else {
                            setSelectedRules(new Set());
                          }
                        }}
                      />
                    </TableHead>
                    <TableHead>SID</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead>Rev</TableHead>
                    <TableHead className="text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((rule, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <input 
                          type="checkbox" 
                          className="rounded border-gray-300"
                          checked={selectedRules.has(rule.sid)}
                          onChange={(e) => {
                            const newSelected = new Set(selectedRules);
                            if (e.target.checked) {
                              newSelected.add(rule.sid);
                            } else {
                              newSelected.delete(rule.sid);
                            }
                            setSelectedRules(newSelected);
                          }}
                        />
                      </TableCell>
                      <TableCell className="font-mono">{rule.sid}</TableCell>
                      <TableCell>
                        <ActionBadge action={rule.action} />
                      </TableCell>
                      <TableCell>
                        <ProtocolBadge protocol={rule.protocol} />
                      </TableCell>
                      <TableCell className="max-w-md truncate" title={rule.message}>
                        {rule.message}
                      </TableCell>
                      <TableCell>{rule.rev}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          <span className={rule.enabled ? 'text-green-500' : 'text-gray-400'}>
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                          <Switch
                            checked={rule.enabled}
                            onCheckedChange={() => toggleRule(rule.sid, rule.enabled)}
                          />
                        </div>
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
