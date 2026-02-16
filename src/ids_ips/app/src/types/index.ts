// IDS Engine Dashboard Types

export interface Stats {
  detection: {
    packets_processed: number;
    alerts_generated: number;
    rules_loaded: number;
    rules_evaluated: number;
    rules_matched: number;
  };
  flow: {
    flows_active: number;
    flows_created: number;
    flows_released: number;
    flows_timedout: number;
  };
  ips: {
    packets_blocked: number;
    packets_passed: number;
    flows_blocked: number;
    ips_blocked: number;
  };
  capture: {
    packets_read: number;
    packets_dropped: number;
    bytes_read: number;
    files_processed: number;
  };
}

export interface Alert {
  sid: number;
  gid: number;
  rev: number;
  message: string;
  category: string;
  priority: number;
  action: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  flow_id: number;
}

export interface Flow {
  flow_id: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  state: string;
  pkts_to_server: number;
  pkts_to_client: number;
  bytes_to_server: number;
  bytes_to_client: number;
  start_time: string;
  last_seen: string;
}

export interface Rule {
  sid: number;
  gid: number;
  rev: number;
  message: string;
  action: string;
  protocol: string;
  enabled: boolean;
  raw: string;
}

export interface BlockedEntry {
  ip?: string;
  flow_id?: number;
  port?: number;
  reason: string;
  timestamp: string;
  expires: string;
}

export interface SystemStatus {
  status: string;
  version: string;
  uptime: number;
  capture_status: boolean;
  rules_loaded: number;
  flows_active: number;
}

export interface CaptureStats {
  packets_read: number;
  packets_dropped: number;
  bytes_read: number;
  files_processed: number;
  current_file: string;
  line_number: number;
}
