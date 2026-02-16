import { useState, useEffect, useCallback } from 'react';
import type { Stats, Alert, Flow, Rule, BlockedEntry, SystemStatus, CaptureStats } from '@/types';

const API_BASE = 'http://localhost:8080/api/v1';

export function useStats() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/stats`);
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  return { stats, loading, error, refetch: fetchStats };
}

export function useStatus() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch(`${API_BASE}/status`);
        if (!response.ok) throw new Error('Failed to fetch status');
        const data = await response.json();
        setStatus(data);
      } catch (err) {
        console.error('Error fetching status:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  return { status, loading };
}

export function useAlerts(limit = 100) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch(`${API_BASE}/alerts/recent?limit=${limit}`);
        if (!response.ok) throw new Error('Failed to fetch alerts');
        const data = await response.json();
        setAlerts(data.alerts || []);
      } catch (err) {
        console.error('Error fetching alerts:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchAlerts();
  }, [limit]);

  return { alerts, loading };
}

export function useFlows() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchFlows = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/flows`);
      if (!response.ok) throw new Error('Failed to fetch flows');
      const data = await response.json();
      setFlows(data.flows || []);
    } catch (err) {
      console.error('Error fetching flows:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFlows();
    const interval = setInterval(fetchFlows, 5000);
    return () => clearInterval(interval);
  }, [fetchFlows]);

  return { flows, loading, refetch: fetchFlows };
}

export function useRules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchRules = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/rules?limit=1000`);
      if (!response.ok) throw new Error('Failed to fetch rules');
      const data = await response.json();
      setRules(data.rules || []);
    } catch (err) {
      console.error('Error fetching rules:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const enableRule = async (sid: number) => {
    try {
      const response = await fetch(`${API_BASE}/rules/${sid}/enable`, { method: 'POST' });
      if (!response.ok) throw new Error('Failed to enable rule');
      fetchRules();
    } catch (err) {
      console.error('Error enabling rule:', err);
    }
  };

  const disableRule = async (sid: number) => {
    try {
      const response = await fetch(`${API_BASE}/rules/${sid}/disable`, { method: 'POST' });
      if (!response.ok) throw new Error('Failed to disable rule');
      fetchRules();
    } catch (err) {
      console.error('Error disabling rule:', err);
    }
  };

  return { rules, loading, refetch: fetchRules, enableRule, disableRule };
}

export function useBlocked() {
  const [blocked, setBlocked] = useState<{ blocked_ips: BlockedEntry[]; blocked_flows: BlockedEntry[] }>({ 
    blocked_ips: [], 
    blocked_flows: [] 
  });
  const [loading, setLoading] = useState(true);

  const fetchBlocked = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/ips/blocked`);
      if (!response.ok) throw new Error('Failed to fetch blocked entries');
      const data = await response.json();
      setBlocked(data);
    } catch (err) {
      console.error('Error fetching blocked entries:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBlocked();
    const interval = setInterval(fetchBlocked, 5000);
    return () => clearInterval(interval);
  }, [fetchBlocked]);

  const unblockIP = async (ip: string) => {
    try {
      const response = await fetch(`${API_BASE}/ips/unblock/ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      if (!response.ok) throw new Error('Failed to unblock IP');
      fetchBlocked();
    } catch (err) {
      console.error('Error unblocking IP:', err);
    }
  };

  const unblockFlow = async (flowId: number) => {
    try {
      const response = await fetch(`${API_BASE}/ips/unblock/flow`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow_id: flowId }),
      });
      if (!response.ok) throw new Error('Failed to unblock flow');
      fetchBlocked();
    } catch (err) {
      console.error('Error unblocking flow:', err);
    }
  };

  return { blocked, loading, refetch: fetchBlocked, unblockIP, unblockFlow };
}

export function useCapture() {
  const [stats, setStats] = useState<CaptureStats | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/capture/stats`);
      if (!response.ok) throw new Error('Failed to fetch capture stats');
      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Error fetching capture stats:', err);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  const start = async () => {
    try {
      await fetch(`${API_BASE}/capture/start`, { method: 'POST' });
      setIsRunning(true);
    } catch (err) {
      console.error('Error starting capture:', err);
    }
  };

  const stop = async () => {
    try {
      await fetch(`${API_BASE}/capture/stop`, { method: 'POST' });
      setIsRunning(false);
    } catch (err) {
      console.error('Error stopping capture:', err);
    }
  };

  const pause = async () => {
    try {
      await fetch(`${API_BASE}/capture/pause`, { method: 'POST' });
    } catch (err) {
      console.error('Error pausing capture:', err);
    }
  };

  const resume = async () => {
    try {
      await fetch(`${API_BASE}/capture/resume`, { method: 'POST' });
    } catch (err) {
      console.error('Error resuming capture:', err);
    }
  };

  return { stats, isRunning, start, stop, pause, resume };
}
