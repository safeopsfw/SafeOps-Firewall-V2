# SAFEOPS FIREWALL - WEB UI DESIGN

**Version:** 1.0.0
**Last Updated:** 2026-01-23
**Purpose:** Complete UI/UX design for SafeOps Firewall web interface

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [User Roles & Permissions](#user-roles--permissions)
4. [Page Structure](#page-structure)
5. [Dashboard](#dashboard)
6. [Rules Management](#rules-management)
7. [Objects Management](#objects-management)
8. [Monitoring & Analytics](#monitoring--analytics)
9. [Logs & Events](#logs--events)
10. [Block Page](#block-page)
11. [Captive Portal](#captive-portal)
12. [Settings](#settings)
13. [API Documentation](#api-documentation)
14. [Technical Specifications](#technical-specifications)

---

## 🎯 Overview

### **Purpose:**
Provide administrators with a comprehensive web interface to:
- Monitor firewall performance and traffic
- Manage firewall rules and policies
- View logs and security events
- Configure firewall settings
- Manage network objects (IPs, domains, groups)

### **Target Users:**
- Network Administrators
- Security Analysts
- System Administrators
- IT Managers

### **Technology Stack:**
```
Frontend:
├─ Framework: React 18 + TypeScript
├─ UI Library: Material-UI (MUI) v5
├─ State Management: Redux Toolkit
├─ Charts: Recharts / Chart.js
├─ Table: TanStack Table (React Table v8)
├─ Forms: React Hook Form + Zod validation
├─ HTTP Client: Axios
└─ Real-time: WebSocket (for live updates)

Backend (Web UI Server):
├─ Framework: Go Fiber (or Gin)
├─ API: RESTful + WebSocket
├─ Auth: JWT tokens + session management
├─ Database: PostgreSQL (shared with firewall)
└─ Port: 8443 (HTTPS) or 8080 (HTTP for dev)

Deployment:
├─ Build: Vite (fast dev server, optimized builds)
├─ Serve: Embedded in Go binary (embed.FS)
└─ TLS: Let's Encrypt or self-signed cert
```

---

## 🏗️ Architecture

### **System Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                    SAFEOPS WEB UI                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────────────────────────────────────────────┐     │
│  │         Frontend (React SPA)                      │     │
│  │  ┌─────────────────────────────────────────────┐  │     │
│  │  │  Components                                 │  │     │
│  │  │  ├─ Dashboard                               │  │     │
│  │  │  ├─ Rules Manager                           │  │     │
│  │  │  ├─ Objects Manager                         │  │     │
│  │  │  ├─ Logs Viewer                             │  │     │
│  │  │  ├─ Analytics                               │  │     │
│  │  │  └─ Settings                                │  │     │
│  │  └─────────────────────────────────────────────┘  │     │
│  │                      ↕ HTTP/REST + WebSocket      │     │
│  └───────────────────────────────────────────────────┘     │
│                          ↓                                  │
│  ┌───────────────────────────────────────────────────┐     │
│  │         Backend (Go Web Server)                   │     │
│  │  ┌─────────────────────────────────────────────┐  │     │
│  │  │  API Routes                                 │  │     │
│  │  │  ├─ /api/dashboard    (metrics)             │  │     │
│  │  │  ├─ /api/rules        (CRUD)                │  │     │
│  │  │  ├─ /api/objects      (CRUD)                │  │     │
│  │  │  ├─ /api/logs         (query)               │  │     │
│  │  │  ├─ /api/analytics    (stats)               │  │     │
│  │  │  ├─ /api/settings     (config)              │  │     │
│  │  │  └─ /ws/live          (WebSocket)           │  │     │
│  │  └─────────────────────────────────────────────┘  │     │
│  └───────────────────────────────────────────────────┘     │
│                          ↓                                  │
│  ┌───────────────────────────────────────────────────┐     │
│  │         Data Layer                                │     │
│  │  ├─ PostgreSQL (firewall rules, logs, config)    │     │
│  │  ├─ Firewall Engine gRPC (rule updates)          │     │
│  │  └─ Prometheus (metrics scraping)                │     │
│  └───────────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### **Data Flow:**
```
User Action → Frontend → API Request → Backend → Database/Firewall
                                           ↓
User Action ← Frontend ← API Response ← Backend ← Database/Firewall

Real-time Updates:
Firewall → Database → WebSocket Server → Frontend (live updates)
```

---

## 👥 User Roles & Permissions

### **Role Hierarchy:**
```
┌────────────────────────────────────────────────────────┐
│  ROLE             PERMISSIONS                          │
├────────────────────────────────────────────────────────┤
│  Super Admin      • Full access (all features)        │
│                   • Manage users & roles              │
│                   • System settings                   │
│                   • Delete rules                      │
│                   • View audit logs                   │
├────────────────────────────────────────────────────────┤
│  Admin            • Manage rules                      │
│                   • Manage objects                    │
│                   • View logs & analytics             │
│                   • Configure settings                │
│                   • Cannot delete system rules        │
├────────────────────────────────────────────────────────┤
│  Operator         • View dashboard                    │
│                   • View rules (read-only)            │
│                   • View logs                         │
│                   • Enable/disable rules              │
│                   • Cannot create/delete rules        │
├────────────────────────────────────────────────────────┤
│  Analyst          • View dashboard                    │
│                   • View logs & analytics             │
│                   • Export reports                    │
│                   • Read-only access                  │
│                   • Cannot modify rules               │
└────────────────────────────────────────────────────────┘
```

---

## 📄 Page Structure

### **Navigation Layout:**
```
┌──────────────────────────────────────────────────────────────┐
│  🔥 SafeOps Firewall          [Search]    [🔔] [👤 Admin ▼] │
├──────────────────────────────────────────────────────────────┤
│  ┌────────┐                                                  │
│  │ MENU   │  ┌─────────────────────────────────────────┐    │
│  │        │  │                                         │    │
│  │ 📊 Dash│  │         PAGE CONTENT                    │    │
│  │ 🛡️ Rules│  │                                         │    │
│  │ 📦 Objs│  │                                         │    │
│  │ 📈 Mon │  │                                         │    │
│  │ 📋 Logs│  │                                         │    │
│  │ ⚙️ Sets│  │                                         │    │
│  │ 📚 Docs│  │                                         │    │
│  │        │  │                                         │    │
│  └────────┘  └─────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### **Main Navigation:**
```
Dashboard          /                   (home page)
├─ Overview
├─ Traffic Monitor
└─ Security Events

Rules              /rules              (firewall rules)
├─ All Rules
├─ Create Rule
├─ Rule Groups
└─ Templates

Objects            /objects            (network objects)
├─ IP Addresses
├─ Domains
├─ Services
├─ Groups
└─ GeoIP

Monitoring         /monitoring         (analytics)
├─ Real-time Traffic
├─ Top Talkers
├─ Protocol Distribution
├─ Bandwidth Usage
└─ Threat Map

Logs               /logs               (logs & events)
├─ Traffic Logs
├─ Security Events
├─ System Logs
├─ Audit Logs
└─ Export

Settings           /settings           (configuration)
├─ General
├─ Network
├─ Security
├─ Users & Roles
├─ Notifications
└─ Backup & Restore

Documentation      /docs               (help & docs)
└─ API Documentation
```

---

## 📊 Dashboard

### **Dashboard Layout:**
```
┌──────────────────────────────────────────────────────────────┐
│  📊 Dashboard                              🔄 Last updated: 2s ago │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────┐│
│  │ 📦 PACKETS   │ │ 📊 THROUGHPUT│ │ ⚡ LATENCY   │ │ 🔥  ││
│  │              │ │              │ │              │ │     ││
│  │   102,847    │ │   850 Mbps   │ │   0.62 ms    │ │ 94% ││
│  │   packets/s  │ │   ↑ 12%      │ │   ✅ Good    │ │ CPU ││
│  └──────────────┘ └──────────────┘ └──────────────┘ └─────┘│
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 📈 Traffic Over Time (Last 24 Hours)                    ││
│  │                                                          ││
│  │      ┌─────────────────────────────────────────────┐    ││
│  │ 1Gbps│                              ╱╲              │    ││
│  │      │                         ╱╲  ╱  ╲             │    ││
│  │ 500  │              ╱╲   ╱╲  ╱  ╲╱    ╲            │    ││
│  │ Mbps │    ╱╲   ╱╲  ╱  ╲ ╱  ╲╱          ╲╱╲         │    ││
│  │    0 │───────────────────────────────────────────  │    ││
│  │      0h    6h    12h   18h   24h                    │    ││
│  │      └─────────────────────────────────────────────┘    ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌──────────────────────────┐ ┌──────────────────────────┐ │
│  │ 🔴 Top Blocked Domains   │ │ ✅ Top Allowed Sources   │ │
│  │                          │ │                          │ │
│  │ 1. facebook.com  (1.2K)  │ │ 1. 192.168.1.100 (45K)   │ │
│  │ 2. doubleclick.net (890) │ │ 2. 192.168.1.50  (32K)   │ │
│  │ 3. malware.xyz   (234)   │ │ 3. 192.168.1.75  (28K)   │ │
│  │ 4. ads.google.com (156)  │ │ 4. 192.168.1.120 (19K)   │ │
│  │ 5. tracker.com   (89)    │ │ 5. 192.168.1.200 (15K)   │ │
│  │                          │ │                          │ │
│  │ [View All →]             │ │ [View All →]             │ │
│  └──────────────────────────┘ └──────────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 🚨 Recent Security Events                               ││
│  │                                                          ││
│  │ ⚠️  15:42:23  Malware detected                          ││
│  │     Source: 192.168.1.150 → malware.xyz:443            ││
│  │     Action: BLOCKED | Rule: Anti-Malware               ││
│  │                                                          ││
│  │ 🔴  15:38:12  Port scan detected                        ││
│  │     Source: 203.0.113.45 → 192.168.1.0/24              ││
│  │     Action: BLOCKED | Rule: IDS-PortScan               ││
│  │                                                          ││
│  │ ⚠️  15:35:47  Suspicious domain access                  ││
│  │     Source: 192.168.1.220 → phishing.example.com:80    ││
│  │     Action: BLOCKED | Rule: Domain-Blocklist           ││
│  │                                                          ││
│  │ [View All Events →]                                     ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌──────────────────────────┐ ┌──────────────────────────┐ │
│  │ 📊 Protocol Distribution │ │ 🌍 Traffic by Country    │ │
│  │                          │ │                          │ │
│  │   ┌────────────┐         │ │   🇺🇸 USA       (45%)    │ │
│  │   │            │ HTTPS   │ │   🇬🇧 UK        (12%)    │ │
│  │   │     78%    │         │ │   🇩🇪 Germany   (8%)     │ │
│  │   │            │         │ │   🇯🇵 Japan     (6%)     │ │
│  │   └────────────┘         │ │   🇨🇦 Canada    (4%)     │ │
│  │                          │ │   🌍 Other      (25%)    │ │
│  │   HTTP: 12%  DNS: 5%    │ │                          │ │
│  │   SMTP: 3%   Other: 2%  │ │   [View Map →]           │ │
│  └──────────────────────────┘ └──────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Dashboard Features:**

#### **1. Key Metrics Cards:**
```typescript
interface MetricCard {
  title: string;
  value: number | string;
  unit: string;
  trend: {
    direction: 'up' | 'down' | 'neutral';
    percentage: number;
  };
  status: 'good' | 'warning' | 'critical';
  icon: React.ReactNode;
}

const metricCards: MetricCard[] = [
  {
    title: 'Packets per Second',
    value: 102847,
    unit: 'pps',
    trend: { direction: 'up', percentage: 5.2 },
    status: 'good',
    icon: <PacketsIcon />
  },
  {
    title: 'Throughput',
    value: 850,
    unit: 'Mbps',
    trend: { direction: 'up', percentage: 12 },
    status: 'good',
    icon: <ThroughputIcon />
  },
  {
    title: 'Latency',
    value: 0.62,
    unit: 'ms',
    trend: { direction: 'down', percentage: 3 },
    status: 'good',
    icon: <LatencyIcon />
  },
  {
    title: 'CPU Usage',
    value: 94,
    unit: '%',
    trend: { direction: 'up', percentage: 8 },
    status: 'warning',  // >90% = warning
    icon: <CPUIcon />
  }
];
```

#### **2. Real-time Traffic Chart:**
```typescript
interface TrafficDataPoint {
  timestamp: Date;
  inbound: number;   // Mbps
  outbound: number;  // Mbps
  total: number;     // Mbps
}

// WebSocket updates every 1 second
const [trafficData, setTrafficData] = useState<TrafficDataPoint[]>([]);

useEffect(() => {
  const ws = new WebSocket('ws://localhost:8080/ws/live');

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    setTrafficData(prev => [...prev.slice(-1440), data]); // Keep 24h (1440 minutes)
  };
}, []);
```

#### **3. Security Events Feed:**
```typescript
interface SecurityEvent {
  id: string;
  timestamp: Date;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: 'malware' | 'port_scan' | 'dos' | 'intrusion' | 'policy_violation';
  source_ip: string;
  destination: string;
  rule_name: string;
  action: 'BLOCKED' | 'ALLOWED' | 'LOGGED';
  description: string;
}

const recentEvents: SecurityEvent[] = [
  {
    id: 'evt_123',
    timestamp: new Date('2026-01-23T15:42:23Z'),
    severity: 'high',
    type: 'malware',
    source_ip: '192.168.1.150',
    destination: 'malware.xyz:443',
    rule_name: 'Anti-Malware',
    action: 'BLOCKED',
    description: 'Malware detected in HTTPS traffic'
  }
];
```

---

## 🛡️ Rules Management

### **Rules Page Layout:**
```
┌──────────────────────────────────────────────────────────────┐
│  🛡️ Firewall Rules                     [+ Create Rule]       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  [🔍 Search rules...]  [🔽 Filter]  [📊 Group By]  [⚙️ ⋮]   │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ # │ Name │ Src │ Dst │ Service │ Action │ Status │ ⋮│   │
│  ├───┼──────┼─────┼─────┼─────────┼────────┼────────┼──┤   │
│  │ 1 │✅ Block FB    │ Any   │ facebook.com │ HTTPS │DENY│🟢│⋮│   │
│  │ 2 │✅ Allow HTTP  │ LAN   │ Any          │ HTTP  │ALLOW│🟢│⋮│   │
│  │ 3 │✅ Block Malwr │ Any   │ malware.*    │ Any   │DENY│🟢│⋮│   │
│  │ 4 │⏸️ Test Rule   │10.0.0│ 10.0.1.0     │ SSH   │ALLOW│⚫│⋮│   │
│  │ 5 │✅ GeoBlock NK │ Any   │ *            │ Any   │DENY│🟢│⋮│   │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Showing 1-5 of 152 rules              [← 1 2 3 ... 31 →]   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Create/Edit Rule Form:**
```
┌──────────────────────────────────────────────────────────────┐
│  ✏️ Create Firewall Rule                       [Save] [Cancel]│
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  📝 Basic Information                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Rule Name: [___________________________________]         │ │
│  │            (e.g., "Block Social Media")                 │ │
│  │                                                          │ │
│  │ Description: [_____________________________________]     │ │
│  │              [_____________________________________]     │ │
│  │              (Optional, explain purpose)                │ │
│  │                                                          │ │
│  │ Enabled:  [✓] Enable this rule                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔍 Source                                                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Type: ( ) Any                                            │ │
│  │       (•) IP Address/Range                               │ │
│  │       ( ) Network Object                                 │ │
│  │       ( ) Group                                          │ │
│  │                                                          │ │
│  │ Value: [192.168.1.0/24________________] [+ Add More]     │ │
│  │                                                          │ │
│  │ Selected:                                                │ │
│  │ • 192.168.1.0/24 (LAN)                          [×]      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🎯 Destination                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Type: ( ) Any                                            │ │
│  │       ( ) IP Address/Range                               │ │
│  │       ( ) Network Object                                 │ │
│  │       (•) Domain                                         │ │
│  │       ( ) GeoIP                                          │ │
│  │                                                          │ │
│  │ Domain: [facebook.com_______________] [+ Add More]       │ │
│  │                                                          │ │
│  │ Match Type: [•] Exact  ( ) Wildcard  ( ) Regex          │ │
│  │                                                          │ │
│  │ Selected:                                                │ │
│  │ • facebook.com                                  [×]      │ │
│  │ • www.facebook.com                              [×]      │ │
│  │ • *.facebook.com                                [×]      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ⚡ Service                                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Protocol: [HTTPS (TCP/443)_______________▼]             │ │
│  │                                                          │ │
│  │ Common Services:                                         │
│  │ [HTTP] [HTTPS] [SSH] [FTP] [DNS] [SMTP] [Custom...]     │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🎬 Action                                                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Action: ( ) ALLOW                                        │ │
│  │         (•) DENY                                         │ │
│  │         ( ) REJECT (send RST)                            │ │
│  │         ( ) LOG (no action)                              │ │
│  │                                                          │ │
│  │ [✓] Log this rule                                        │ │
│  │ [✓] Generate alert on match                              │ │
│  │ [ ] Rate limit (max ___ connections/min)                │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  📅 Schedule (Optional)                                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [ ] Enable scheduling                                    │ │
│  │                                                          │ │
│  │ Active Days: [Mon] [Tue] [Wed] [Thu] [Fri] [Sat] [Sun]  │ │
│  │                                                          │ │
│  │ Active Time: [09:00] to [17:00]                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔢 Priority                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Priority: [50____________]  (1-100, higher = first)     │ │
│  │                                                          │ │
│  │ Position: (•) Auto (by priority)                         │ │
│  │           ( ) Before rule: [Select rule_______▼]         │ │
│  │           ( ) After rule:  [Select rule_______▼]         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  [💾 Save Rule]  [🧪 Test Rule]  [❌ Cancel]                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Rule Context Menu (⋮):**
```
┌─────────────────────┐
│ ✏️  Edit Rule       │
│ 📋 Duplicate        │
│ ⏸️  Disable/Enable  │
│ 📊 View Stats       │
│ 📝 View Logs        │
│ ⬆️  Move Up         │
│ ⬇️  Move Down       │
│ 🗑️  Delete          │
└─────────────────────┘
```

### **Rule Statistics Modal:**
```
┌──────────────────────────────────────────────────────────────┐
│  📊 Rule Statistics: "Block Facebook"           [×]          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  🎯 Match Statistics (Last 24 Hours)                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Total Matches:      1,234 packets                       │ │
│  │ Unique Sources:     45 IP addresses                     │ │
│  │ Bytes Blocked:      12.5 MB                             │ │
│  │ First Match:        2026-01-22 08:15:23                 │ │
│  │ Last Match:         2026-01-23 15:42:11                 │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  📈 Matches Over Time                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │     ┌───────────────────────────────────────────────┐  │ │
│  │ 200 │     ▁▃▅█▇▅▃▁                ▁▃▅▇▅▃▁           │  │ │
│  │ 150 │  ▁▃▅█▓▓▓▓▓█▅▃▁         ▁▃▅█▓▓▓▓▓█▅▃▁         │  │ │
│  │ 100 │ ▃▓▓▓▓▓▓▓▓▓▓▓▓▓▃       ▃▓▓▓▓▓▓▓▓▓▓▓▓▓▃       │  │ │
│  │  50 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     │  │ │
│  │   0 │────────────────────────────────────────────  │  │ │
│  │     0h   6h   12h  18h  24h                        │  │ │
│  │     └───────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔝 Top Sources                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 1. 192.168.1.100    234 matches (19%)                   │ │
│  │ 2. 192.168.1.150    187 matches (15%)                   │ │
│  │ 3. 192.168.1.75     145 matches (12%)                   │ │
│  │ 4. 192.168.1.220    123 matches (10%)                   │ │
│  │ 5. 192.168.1.50     98  matches (8%)                    │ │
│  │ ... (40 more)                                            │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  [📥 Export CSV]  [📝 View Logs]  [Close]                    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 📦 Objects Management

### **Objects Page Layout:**
```
┌──────────────────────────────────────────────────────────────┐
│  📦 Network Objects                    [+ Create Object]     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Tabs: [IP Addresses] [Domains] [Services] [Groups] [GeoIP] │
│                                                              │
│  ═══════════════════════════════════════════════════════════│
│                                                              │
│  🌐 IP Address Objects                                       │
│                                                              │
│  [🔍 Search...]  [🔽 Filter: All Types]  [⬇️ Export]        │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Name          │ Type    │ Value           │ Used │ ⋮│   │
│  ├───────────────┼─────────┼─────────────────┼──────┼──┤   │
│  │ LAN_Network   │ Subnet  │ 192.168.1.0/24  │ 12   │⋮│   │
│  │ DMZ_Network   │ Subnet  │ 10.0.1.0/24     │ 8    │⋮│   │
│  │ Web_Servers   │ Range   │ 10.0.1.10-20    │ 5    │⋮│   │
│  │ VPN_Gateway   │ Single  │ 203.0.113.50    │ 3    │⋮│   │
│  │ DNS_Servers   │ Group   │ 3 addresses     │ 15   │⋮│   │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Showing 1-5 of 47 objects                [← 1 2 3 ... →]   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Create IP Object Form:**
```
┌──────────────────────────────────────────────────────────────┐
│  ➕ Create IP Address Object                 [Save] [Cancel] │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Object Name: [LAN_Network________________________]          │
│                                                              │
│  Description: [Internal LAN network______________]           │
│               [_________________________________]            │
│                                                              │
│  Type: (•) Single IP                                         │
│        ( ) IP Range                                          │
│        ( ) Subnet/CIDR                                       │
│        ( ) Wildcard Mask                                     │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Network Address: [192.168.1.0________________]          │ │
│  │                                                          │ │
│  │ Subnet Mask:     [255.255.255.0_____________] or        │ │
│  │ CIDR Notation:   [/24]                                  │ │
│  │                                                          │ │
│  │ 📊 Address Range: 192.168.1.0 - 192.168.1.255           │ │
│  │    Total Hosts:   254 usable addresses                  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Tags: [internal] [lan] [trusted] [+ Add tag]               │
│                                                              │
│  [💾 Save]  [Cancel]                                         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Domain Objects Tab:**
```
┌──────────────────────────────────────────────────────────────┐
│  🌐 Domain Objects                         [+ Create Domain] │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  [🔍 Search domains...]  [🔽 Filter]  [📥 Import List]       │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Name          │ Pattern      │ Type    │ Used │ ⋮│      │
│  ├───────────────┼──────────────┼─────────┼──────┼──┤      │
│  │ Facebook      │ facebook.com │ Exact   │ 3    │⋮│      │
│  │ Google Ads    │ *.google.*   │ Wildcard│ 5    │⋮│      │
│  │ Malware Sites │ 1,234 domains│ List    │ 1    │⋮│      │
│  │ CDN Akamai    │ *.akamai.*   │ Wildcard│ 8    │⋮│      │
│  │ Social Media  │ 15 domains   │ Group   │ 2    │⋮│      │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Service Objects Tab:**
```
┌──────────────────────────────────────────────────────────────┐
│  ⚡ Service Objects                        [+ Create Service]│
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Common Services:                                            │
│  [HTTP] [HTTPS] [SSH] [FTP] [DNS] [SMTP] [IMAP] [+ More]    │
│                                                              │
│  Custom Services:                                            │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Name          │ Protocol │ Port(s)     │ Used │ ⋮│      │
│  ├───────────────┼──────────┼─────────────┼──────┼──┤      │
│  │ Web Services  │ TCP      │ 80,443      │ 15   │⋮│      │
│  │ Email         │ TCP      │ 25,587,993  │ 8    │⋮│      │
│  │ Custom App    │ TCP      │ 8080-8090   │ 2    │⋮│      │
│  │ VoIP          │ UDP      │ 5060,5061   │ 4    │⋮│      │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Group Objects Tab:**
```
┌──────────────────────────────────────────────────────────────┐
│  📂 Groups                                  [+ Create Group]  │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 📁 Trusted_Networks                            [Edit]    │ │
│  │    Type: IP Address Group                               │ │
│  │    Members: 3 objects                                   │ │
│  │    ├─ LAN_Network (192.168.1.0/24)                      │ │
│  │    ├─ DMZ_Network (10.0.1.0/24)                         │ │
│  │    └─ VPN_Range (172.16.0.0/24)                         │ │
│  │    Used in: 12 rules                                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 📁 Blocked_Domains                             [Edit]    │ │
│  │    Type: Domain Group                                   │ │
│  │    Members: 15 domains                                  │ │
│  │    ├─ facebook.com                                      │ │
│  │    ├─ twitter.com                                       │ │
│  │    ├─ instagram.com                                     │ │
│  │    └─ ... (12 more)                                     │ │
│  │    Used in: 3 rules                                     │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 📈 Monitoring & Analytics

### **Real-time Traffic Page:**
```
┌──────────────────────────────────────────────────────────────┐
│  📈 Real-time Traffic Monitor           🔴 LIVE  [⏸️ Pause]  │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 📊 Live Traffic (Last 5 Minutes)                        ││
│  │                                                          ││
│  │      ┌─────────────────────────────────────────────┐    ││
│  │ 1Gbps│                                    ╱╲        │    ││
│  │      │                               ╱╲  ╱  ╲       │    ││
│  │ 500  │                          ╱╲  ╱  ╲╱    ╲      │    ││
│  │ Mbps │                     ╱╲  ╱  ╲╱          ╲╱╲   │    ││
│  │    0 │────────────────────────────────────────────  │    ││
│  │      -5m   -4m   -3m   -2m   -1m   now            │    ││
│  │      └─────────────────────────────────────────────┘    ││
│  │      ▬ Inbound  ▬ Outbound  ▬ Total                    ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌──────────────────────────┐ ┌──────────────────────────┐ │
│  │ 🔝 Top Talkers (Sources) │ │ 🎯 Top Destinations      │ │
│  │                          │ │                          │ │
│  │ 192.168.1.100  [████████]│ │ 93.184.216.34 [████████]│ │
│  │ 45.2 Mbps      58%       │ │ 23.5 Mbps     72%       │ │
│  │                          │ │                          │ │
│  │ 192.168.1.50   [█████░░░]│ │ 172.217.1.46  [███░░░░░]│ │
│  │ 18.3 Mbps      23%       │ │ 8.4 Mbps      25%       │ │
│  │                          │ │                          │ │
│  │ 192.168.1.75   [██░░░░░░]│ │ 151.101.1.69  [█░░░░░░░]│ │
│  │ 7.8 Mbps       10%       │ │ 1.2 Mbps      4%        │ │
│  │                          │ │                          │ │
│  │ (+ 42 more)              │ │ (+ 138 more)             │ │
│  └──────────────────────────┘ └──────────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 📡 Active Connections (1,234)                           ││
│  │                                                          ││
│  │ Source IP      │ Dst IP         │ Port │ Proto │ Bytes  ││
│  │ 192.168.1.100  │ 93.184.216.34  │ 443  │ TCP   │ 1.2MB  ││
│  │ 192.168.1.50   │ 172.217.1.46   │ 443  │ TCP   │ 845KB  ││
│  │ 192.168.1.75   │ 151.101.1.69   │ 80   │ TCP   │ 234KB  ││
│  │ 192.168.1.120  │ 8.8.8.8        │ 53   │ UDP   │ 1.2KB  ││
│  │ ... (1,230 more connections)                            ││
│  │                                                          ││
│  │ [View All →]                                             ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Protocol Distribution:**
```
┌──────────────────────────────────────────────────────────────┐
│  📊 Protocol Distribution                 [Last 24 Hours ▼]  │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────┐ ┌──────────────────────────┐ │
│  │    Pie Chart             │ │  Protocol Breakdown      │ │
│  │                          │ │                          │ │
│  │        ┌────┐            │ │  HTTPS (TCP/443)         │ │
│  │        │    │            │ │  ████████████████ 78%    │ │
│  │        │ 78%│   HTTPS    │ │  1.2 TB  (↑ 12%)         │ │
│  │        │    │            │ │                          │ │
│  │  Other └────┘ HTTP       │ │  HTTP (TCP/80)           │ │
│  │   2%          12%        │ │  ███ 12%                 │ │
│  │        DNS  SMTP         │ │  180 GB  (↓ 3%)          │ │
│  │        5%   3%           │ │                          │ │
│  │                          │ │  DNS (UDP/53)            │ │
│  │                          │ │  █ 5%                    │ │
│  │                          │ │  75 GB  (↑ 5%)           │ │
│  │                          │ │                          │ │
│  │                          │ │  SMTP (TCP/25)           │ │
│  │                          │ │  █ 3%                    │ │
│  │                          │ │  45 GB  (→ 0%)           │ │
│  │                          │ │                          │ │
│  │                          │ │  Other                   │ │
│  │                          │ │  ░ 2%                    │ │
│  │                          │ │  30 GB  (↑ 8%)           │ │
│  └──────────────────────────┘ └──────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Threat Map:**
```
┌──────────────────────────────────────────────────────────────┐
│  🌍 Global Threat Map                     [🔴 LIVE]          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    World Map                             ││
│  │                                                          ││
│  │         🌍                    🌏                         ││
│  │      Europe               Asia                          ││
│  │    🔴 🔴 🔴            🔴 🔴                             ││
│  │     (UK, FR)            (CN, JP)                         ││
│  │                                                          ││
│  │         🌎                                               ││
│  │    North America                                         ││
│  │      🔴 🔴                                               ││
│  │      (US, CA)                                            ││
│  │                                                          ││
│  │  Legend:                                                 ││
│  │  🔴 Attack Source  (dot size = attack volume)            ││
│  │  ═══> Attack Direction                                   ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  🚨 Active Threats (Last Hour)                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Source Country │ Attacks │ Type              │ Blocked  │ │
│  ├────────────────┼─────────┼───────────────────┼──────────┤ │
│  │ 🇨🇳 China       │ 1,234   │ Port Scan         │ 1,234    │ │
│  │ 🇷🇺 Russia      │ 456     │ Malware           │ 456      │ │
│  │ 🇰🇵 North Korea │ 89      │ APT Attack        │ 89       │ │
│  │ 🇺🇸 USA         │ 34      │ Botnet (hijacked) │ 34       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 📋 Logs & Events

### **Logs Page:**
```
┌──────────────────────────────────────────────────────────────┐
│  📋 Logs & Events                          [🔄 Auto-refresh] │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Tabs: [Traffic Logs] [Security Events] [System] [Audit]    │
│                                                              │
│  ═══════════════════════════════════════════════════════════│
│                                                              │
│  🔍 Filters:                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Time: [Last 1 Hour ▼]  Action: [All ▼]                  │ │
│  │                                                          │ │
│  │ Source: [___________]  Destination: [___________]        │ │
│  │                                                          │ │
│  │ Protocol: [All ▼]     Port: [___]                        │ │
│  │                                                          │ │
│  │ [🔍 Search]  [Clear Filters]  [📥 Export]               │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔴 DENY logs only: [✓]  Show connections: [✓]              │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Time      │ Src IP     │ Dst IP        │ Port│ Action│  │
│  ├───────────┼────────────┼───────────────┼─────┼───────┤  │
│  │ 15:42:23  │192.168.1.150│malware.xyz   │ 443 │🔴DENY │  │
│  │ 15:42:19  │192.168.1.100│facebook.com  │ 443 │🔴DENY │  │
│  │ 15:42:15  │192.168.1.75 │google.com    │ 443 │✅ALLOW│  │
│  │ 15:42:12  │192.168.1.50 │youtube.com   │ 443 │✅ALLOW│  │
│  │ 15:42:08  │192.168.1.220│phishing.com  │ 80  │🔴DENY │  │
│  │ ... (4,521 more logs)                                   │  │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Showing 1-5 of 4,526 logs                [← 1 2 3 ... →]   │
│                                                              │
│  [📥 Export CSV]  [📊 Generate Report]  [🗑️ Clear Logs]     │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Log Detail Modal (Click on log entry):**
```
┌──────────────────────────────────────────────────────────────┐
│  📝 Log Details                                    [×]       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  🕐 Timestamp: 2026-01-23 15:42:23.456 UTC                   │
│                                                              │
│  🔴 Action: DENY (Blocked by firewall)                       │
│                                                              │
│  📊 Connection Details:                                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Source IP:       192.168.1.150                          │ │
│  │ Source Port:     54321                                  │ │
│  │ Source Country:  🇺🇸 United States                       │ │
│  │                                                          │ │
│  │ Destination IP:  93.184.216.34                          │ │
│  │ Destination Port: 443 (HTTPS)                            │ │
│  │ Destination DNS: malware.xyz                            │ │
│  │ Destination Country: 🇳🇱 Netherlands                     │ │
│  │                                                          │ │
│  │ Protocol:        TCP                                    │ │
│  │ Bytes Sent:      1,234 bytes                            │ │
│  │ Packets:         3 packets                              │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🛡️ Rule Matched:                                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Rule ID:         rule_12345                             │ │
│  │ Rule Name:       Anti-Malware                           │ │
│  │ Rule Priority:   90                                     │ │
│  │ Rule Action:     DENY                                   │ │
│  │                                                          │ │
│  │ Match Reason:    Domain matched blocklist               │ │
│  │                  (malware.xyz in known malware list)    │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔍 Threat Intelligence:                                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ ⚠️ Threat Category: Malware Distribution                │ │
│  │ Severity:          HIGH                                 │ │
│  │ First Seen:        2026-01-15 (8 days ago)             │ │
│  │ Last Seen:         2026-01-23 (today)                  │ │
│  │ Total Attempts:    23 attempts from this source         │ │
│  │                                                          │ │
│  │ IOC (Indicator of Compromise):                          │ │
│  │ • Domain: malware.xyz                                   │ │
│  │ • IP: 93.184.216.34                                     │ │
│  │ • SHA256: a3f4b5c6... (malware signature)              │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  [🔍 Whois Lookup]  [🔗 VirusTotal]  [📋 Copy Details]      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Security Events Tab:**
```
┌──────────────────────────────────────────────────────────────┐
│  🚨 Security Events                        [🔴 15 Unacknowledged]│
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Severity: [All ▼]  Type: [All ▼]  Status: [Unack ▼]        │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ ⚠️  HIGH │ 15:42:23 │ Malware Detected                  │ │
│  │    Source: 192.168.1.150 → malware.xyz:443              │ │
│  │    [Acknowledge]  [View Details]  [Create Rule]         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ 🔴  CRITICAL │ 15:38:12 │ Port Scan Detected            │ │
│  │    Source: 203.0.113.45 → 192.168.1.0/24                │ │
│  │    Scanned Ports: 22, 80, 443, 3389, 8080 (5 ports)     │ │
│  │    [Acknowledge]  [View Details]  [Block Source IP]     │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ ⚠️  HIGH │ 15:35:47 │ Phishing Attempt                  │ │
│  │    Source: 192.168.1.220 → phishing.example.com:80      │ │
│  │    [Acknowledged by admin]                               │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚫 Block Page

### **Block Page Design (Shown to end users):**

**URL:** `http://firewall.local/blocked?url=facebook.com&rule=Block-Social-Media&user=192.168.1.100`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Access Blocked - SafeOps Firewall</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            padding: 40px;
            text-align: center;
        }
        .icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        h1 {
            color: #e53e3e;
            font-size: 32px;
            margin: 0 0 10px 0;
        }
        .blocked-url {
            background: #f7fafc;
            border-left: 4px solid #e53e3e;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
            word-break: break-all;
        }
        .blocked-url strong {
            color: #2d3748;
        }
        .reason {
            background: #fff5f5;
            border: 1px solid #fc8181;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
        }
        .reason h3 {
            color: #e53e3e;
            margin-top: 0;
        }
        .info {
            text-align: left;
            color: #4a5568;
            line-height: 1.6;
            margin: 20px 0;
        }
        .info dt {
            font-weight: bold;
            color: #2d3748;
            margin-top: 10px;
        }
        .info dd {
            margin-left: 0;
            margin-bottom: 10px;
        }
        .actions {
            margin-top: 30px;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            margin: 5px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #4299e1;
            color: white;
        }
        .btn-primary:hover {
            background: #3182ce;
        }
        .btn-secondary {
            background: #e2e8f0;
            color: #2d3748;
        }
        .btn-secondary:hover {
            background: #cbd5e0;
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            color: #718096;
            font-size: 14px;
        }
        .reference {
            background: #edf2f7;
            border-radius: 4px;
            padding: 8px 12px;
            font-family: monospace;
            font-size: 12px;
            color: #4a5568;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>Access Blocked</h1>
        <p style="color: #4a5568; font-size: 18px;">
            This website has been blocked by your organization's firewall policy.
        </p>

        <div class="blocked-url">
            <strong>Blocked URL:</strong><br>
            <span style="color: #e53e3e; font-family: monospace;">
                https://facebook.com
            </span>
        </div>

        <div class="reason">
            <h3>🚫 Reason</h3>
            <p><strong>Category:</strong> Social Media</p>
            <p><strong>Rule:</strong> Block-Social-Media</p>
            <p><strong>Policy:</strong> Company Internet Usage Policy prohibits access to social media during work hours.</p>
        </div>

        <dl class="info">
            <dt>📅 Date & Time:</dt>
            <dd>January 23, 2026 at 3:42:23 PM UTC</dd>

            <dt>💻 Your IP Address:</dt>
            <dd>192.168.1.100</dd>

            <dt>🌐 Destination IP:</dt>
            <dd>157.240.1.35 (facebook.com)</dd>

            <dt>📋 Reference ID:</dt>
            <dd class="reference">BLK-20260123-154223-A3F4B5C6</dd>
        </dl>

        <div class="actions">
            <a href="javascript:history.back()" class="btn btn-primary">
                ← Go Back
            </a>
            <a href="http://firewall.local/request-access?url=facebook.com&ref=BLK-20260123-154223-A3F4B5C6" class="btn btn-secondary">
                📝 Request Access
            </a>
        </div>

        <div class="footer">
            <p>
                <strong>Need help?</strong> Contact your IT administrator<br>
                Email: <a href="mailto:it@yourcompany.com">it@yourcompany.com</a> |
                Phone: +1 (555) 123-4567
            </p>
            <p style="margin-top: 15px; font-size: 12px;">
                Protected by <strong>SafeOps Firewall</strong> v12.0.0<br>
                © 2026 Your Organization. All rights reserved.
            </p>
        </div>
    </div>
</body>
</html>
```

### **Block Page Variants:**

#### **1. Malware Block Page:**
```html
<div class="icon">⚠️</div>
<h1 style="color: #c53030;">Malware Threat Blocked</h1>
<p style="color: #e53e3e; font-weight: bold; font-size: 20px;">
    DANGER: This site contains malware!
</p>

<div class="reason" style="background: #fff5f5; border-color: #fc8181;">
    <h3>⚠️ Threat Details</h3>
    <p><strong>Threat Type:</strong> Trojan Downloader</p>
    <p><strong>Severity:</strong> HIGH</p>
    <p><strong>First Detected:</strong> January 15, 2026</p>
    <p>This website is known to distribute malicious software that can harm your computer and steal sensitive information.</p>
</div>

<div style="background: #fed7d7; border: 2px solid #fc8181; border-radius: 8px; padding: 15px; margin: 20px 0;">
    <strong>🚨 DO NOT ATTEMPT TO BYPASS THIS BLOCK</strong><br>
    Accessing this site could compromise your device and the entire network.
</div>
```

#### **2. Phishing Block Page:**
```html
<div class="icon">🎣</div>
<h1 style="color: #d69e2e;">Phishing Attempt Blocked</h1>

<div class="reason" style="background: #fffaf0; border-color: #f6ad55;">
    <h3>🎣 Phishing Warning</h3>
    <p><strong>Attack Type:</strong> Credential Harvesting</p>
    <p><strong>Impersonating:</strong> PayPal Login Page</p>
    <p>This website is attempting to steal your username and password by impersonating a legitimate service.</p>
</div>

<div style="background: #fef5e7; border-left: 4px solid #f6ad55; padding: 15px; margin: 20px 0;">
    <strong>🔒 Security Tip:</strong><br>
    Always verify the URL matches the legitimate website before entering credentials.
</div>
```

#### **3. Geo-Blocked Page:**
```html
<div class="icon">🌍</div>
<h1 style="color: #3182ce;">Geographic Restriction</h1>

<div class="reason" style="background: #ebf8ff; border-color: #63b3ed;">
    <h3>🌍 Location Blocked</h3>
    <p><strong>Destination Country:</strong> 🇰🇵 North Korea</p>
    <p><strong>Policy:</strong> Company policy prohibits connections to sanctioned countries.</p>
    <p>This restriction is in place to comply with legal and regulatory requirements.</p>
</div>
```

---

## 🔐 Captive Portal

### **Captive Portal - Landing Page:**

**URL:** `http://captive.local/portal` (auto-redirect on first connection)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SafeOps Network - Authentication Required</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .portal-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .step {
            margin-bottom: 30px;
        }
        .step-number {
            display: inline-block;
            width: 32px;
            height: 32px;
            background: #667eea;
            color: white;
            border-radius: 50%;
            text-align: center;
            line-height: 32px;
            font-weight: bold;
            margin-right: 10px;
        }
        .step h3 {
            display: inline;
            color: #2d3748;
            font-size: 18px;
        }
        .step-content {
            margin-left: 42px;
            margin-top: 10px;
            color: #4a5568;
            line-height: 1.6;
        }
        .cert-download {
            background: #f7fafc;
            border: 2px dashed #cbd5e0;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin-top: 15px;
        }
        .cert-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
            cursor: pointer;
            border: none;
            font-size: 16px;
        }
        .btn-primary {
            background: #667eea;
            color: white;
            width: 100%;
        }
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #e2e8f0;
            color: #4a5568;
            margin-top: 10px;
            width: 100%;
        }
        .btn-secondary:hover {
            background: #cbd5e0;
        }
        .warning {
            background: #fff5f5;
            border-left: 4px solid #fc8181;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .info-box {
            background: #ebf8ff;
            border-left: 4px solid #4299e1;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .footer {
            background: #f7fafc;
            padding: 20px;
            text-align: center;
            color: #718096;
            font-size: 14px;
            border-top: 1px solid #e2e8f0;
        }
        .device-info {
            background: #f7fafc;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            font-size: 14px;
            color: #4a5568;
        }
        .device-info dt {
            font-weight: bold;
            color: #2d3748;
            margin-top: 8px;
        }
        .device-info dd {
            margin-left: 0;
        }
    </style>
</head>
<body>
    <div class="portal-container">
        <div class="header">
            <h1>🔥 Welcome to SafeOps Network</h1>
            <p>Authentication Required</p>
        </div>

        <div class="content">
            <p style="color: #2d3748; font-size: 16px; text-align: center; margin-bottom: 30px;">
                Your device needs to authenticate before accessing the internet.
            </p>

            <!-- Step 1: Certificate Installation -->
            <div class="step">
                <span class="step-number">1</span>
                <h3>Install CA Certificate</h3>
                <div class="step-content">
                    <p>Download and install our root certificate for secure HTTPS inspection.</p>

                    <div class="cert-download">
                        <div class="cert-icon">📜</div>
                        <p style="margin: 10px 0; font-weight: bold;">SafeOps Root CA Certificate</p>
                        <p style="margin: 10px 0; font-size: 14px; color: #718096;">
                            File: safeops-root-ca.crt<br>
                            Expires: January 23, 2036
                        </p>
                        <a href="/download-cert" class="btn btn-primary" download>
                            📥 Download Certificate
                        </a>
                    </div>

                    <div class="info-box" style="margin-top: 15px; font-size: 14px;">
                        <strong>💡 Why install?</strong><br>
                        • Enables secure content inspection<br>
                        • Better malware protection<br>
                        • Required for corporate devices<br>
                        • Guest devices can skip (not recommended)
                    </div>

                    <div class="warning" style="margin-top: 15px; font-size: 14px;">
                        <strong>⚠️ Important:</strong> After downloading, install the certificate in your system's trust store.
                        <a href="/help/install-cert" style="color: #667eea;">Installation guide →</a>
                    </div>

                    <button class="btn btn-secondary" onclick="skipCert()">
                        ⏭️ Skip (Not Recommended)
                    </button>
                </div>
            </div>

            <!-- Step 2: Verify Installation -->
            <div class="step" id="step2" style="display: none;">
                <span class="step-number">2</span>
                <h3>Verify Installation</h3>
                <div class="step-content">
                    <p>Testing certificate installation...</p>
                    <div style="text-align: center; padding: 20px;">
                        <div class="spinner">🔄</div>
                        <p style="color: #718096;">Please wait...</p>
                    </div>
                </div>
            </div>

            <!-- Step 3: Authentication -->
            <div class="step" id="step3" style="display: none;">
                <span class="step-number">3</span>
                <h3>Login</h3>
                <div class="step-content">
                    <form action="/portal/authenticate" method="POST">
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; color: #2d3748; font-weight: 600;">
                                Username
                            </label>
                            <input type="text" name="username" required
                                   style="width: 100%; padding: 12px; border: 1px solid #cbd5e0; border-radius: 8px; font-size: 16px;"
                                   placeholder="john.doe">
                        </div>

                        <div style="margin-bottom: 20px;">
                            <label style="display: block; margin-bottom: 5px; color: #2d3748; font-weight: 600;">
                                Password
                            </label>
                            <input type="password" name="password" required
                                   style="width: 100%; padding: 12px; border: 1px solid #cbd5e0; border-radius: 8px; font-size: 16px;"
                                   placeholder="••••••••">
                        </div>

                        <button type="submit" class="btn btn-primary">
                            🔓 Login & Connect
                        </button>
                    </form>

                    <p style="text-align: center; margin-top: 15px; font-size: 14px; color: #718096;">
                        <a href="/portal/forgot-password" style="color: #667eea;">Forgot password?</a>
                    </p>
                </div>
            </div>

            <!-- Device Information -->
            <dl class="device-info">
                <dt>💻 Device Information:</dt>
                <dd>MAC Address: 00:11:22:33:44:55</dd>
                <dd>IP Address: 192.168.1.100</dd>
                <dd>Hostname: LAPTOP-ABC123</dd>
            </dl>
        </div>

        <div class="footer">
            <p>
                <strong>Need help?</strong> Contact IT Support<br>
                Email: <a href="mailto:support@company.com">support@company.com</a>
            </p>
            <p style="margin-top: 10px; font-size: 12px;">
                Protected by SafeOps Firewall v12.0.0
            </p>
        </div>
    </div>

    <script>
        // Auto-proceed to step 3 if cert is skipped or already installed
        function skipCert() {
            document.getElementById('step2').style.display = 'block';
            setTimeout(() => {
                document.getElementById('step2').style.display = 'none';
                document.getElementById('step3').style.display = 'block';
            }, 2000);
        }

        // Check if certificate is installed (HTTPS test)
        async function checkCertInstalled() {
            try {
                const response = await fetch('https://captive.local/cert-test');
                if (response.ok) {
                    // Certificate installed, proceed to login
                    document.getElementById('step2').style.display = 'none';
                    document.getElementById('step3').style.display = 'block';
                }
            } catch (error) {
                // Certificate not installed, show warning
                console.error('Certificate not installed');
            }
        }
    </script>
</body>
</html>
```

### **Captive Portal - Success Page:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome to SafeOps Network</title>
    <style>
        /* Similar styling as above */
    </style>
</head>
<body>
    <div class="portal-container">
        <div class="header" style="background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);">
            <h1>✅ Authentication Successful</h1>
            <p>You're now connected to the internet</p>
        </div>

        <div class="content" style="text-align: center;">
            <div style="font-size: 80px; margin: 20px 0;">🎉</div>

            <h2 style="color: #2d3748;">Welcome, John Doe!</h2>

            <div style="background: #f0fff4; border: 2px solid #9ae6b4; border-radius: 8px; padding: 20px; margin: 30px 0;">
                <p style="color: #22543d; font-weight: bold; margin: 0;">
                    ✅ Internet Access: ENABLED
                </p>
                <p style="color: #22543d; margin: 10px 0 0 0;">
                    Device: LAPTOP-ABC123 (192.168.1.100)
                </p>
            </div>

            <div style="background: #f7fafc; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: left;">
                <h3 style="margin-top: 0; color: #2d3748;">📊 Session Information</h3>
                <dl style="margin: 0;">
                    <dt style="font-weight: bold; color: #2d3748; margin-top: 10px;">Username:</dt>
                    <dd style="margin-left: 0;">john.doe@company.com</dd>

                    <dt style="font-weight: bold; color: #2d3748; margin-top: 10px;">Login Time:</dt>
                    <dd style="margin-left: 0;">January 23, 2026 at 3:45 PM</dd>

                    <dt style="font-weight: bold; color: #2d3748; margin-top: 10px;">Session Expires:</dt>
                    <dd style="margin-left: 0;">January 24, 2026 at 3:45 PM (24 hours)</dd>

                    <dt style="font-weight: bold; color: #2d3748; margin-top: 10px;">HTTPS Inspection:</dt>
                    <dd style="margin-left: 0;">
                        ✅ ENABLED (certificate installed)
                    </dd>
                </dl>
            </div>

            <div style="background: #ebf8ff; border-left: 4px solid #4299e1; padding: 15px; margin: 20px 0; text-align: left;">
                <strong>📋 Important Policies:</strong><br>
                • Social media blocked during work hours (9 AM - 5 PM)<br>
                • Malware and phishing sites automatically blocked<br>
                • All traffic is logged for security purposes<br>
                • Bandwidth limit: 100 Mbps per device
            </div>

            <p style="margin-top: 30px;">
                <a href="http://google.com" class="btn btn-primary">
                    🌐 Start Browsing
                </a>
            </p>

            <p style="margin-top: 15px; font-size: 14px; color: #718096;">
                This page will automatically close in <strong id="countdown">10</strong> seconds...
            </p>
        </div>

        <div class="footer">
            <p>Have a great day!</p>
        </div>
    </div>

    <script>
        // Countdown and auto-redirect
        let seconds = 10;
        const countdownEl = document.getElementById('countdown');

        const interval = setInterval(() => {
            seconds--;
            countdownEl.textContent = seconds;

            if (seconds <= 0) {
                clearInterval(interval);
                window.location.href = 'http://google.com';
            }
        }, 1000);
    </script>
</body>
</html>
```

---

## ⚙️ Settings

### **Settings Page:**
```
┌──────────────────────────────────────────────────────────────┐
│  ⚙️ Settings                                                  │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Tabs: [General] [Network] [Security] [Users] [Notifications]│
│                                                              │
│  ═══════════════════════════════════════════════════════════│
│                                                              │
│  ⚙️ General Settings                                         │
│                                                              │
│  🔥 Firewall Information                                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Version:         12.0.0                                 │ │
│  │ Uptime:          15 days, 8 hours, 32 minutes           │ │
│  │ License:         Enterprise (Expires: Jan 2027)         │ │
│  │ Mode:            Production                             │ │
│  │ Last Updated:    January 10, 2026                       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🌐 Network Interface                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Interface: [Ethernet 1_______________▼]                 │ │
│  │ Mode:      (•) Inline   ( ) Monitor                     │ │
│  │                                                          │ │
│  │ [✓] Enable IPv6                                          │ │
│  │ [✓] Enable DNS filtering                                 │ │
│  │ [✓] Enable TLS inspection (requires CA cert)             │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ⏱️ Performance                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Max Memory:      [2048_______] MB                       │ │
│  │ Worker Threads:  [8___________] (auto: CPU cores)       │ │
│  │ Batch Size:      [100_________] packets                 │ │
│  │                                                          │ │
│  │ [✓] Enable zero-copy optimization                        │ │
│  │ [✓] Enable memory pooling                                │ │
│  │ [✓] Enable performance monitoring                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  📝 Logging                                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Log Level:       [INFO_______________▼]                 │ │
│  │ Log Retention:   [30______________] days                │ │
│  │ Max Log Size:    [1GB_____________] per file            │ │
│  │                                                          │ │
│  │ [✓] Log all allowed connections                          │ │
│  │ [✓] Log all denied connections                           │ │
│  │ [ ] Log DNS queries                                      │ │
│  │ [✓] Log security events                                  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  [💾 Save Changes]  [↩️ Reset to Defaults]                   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Security Settings Tab:**
```
┌──────────────────────────────────────────────────────────────┐
│  🔒 Security Settings                                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  🛡️ Threat Protection                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [✓] Enable IDS/IPS                                       │ │
│  │ [✓] Enable malware detection                             │ │
│  │ [✓] Enable phishing protection                           │ │
│  │ [✓] Enable botnet detection                              │ │
│  │ [✓] Enable port scan detection                           │ │
│  │                                                          │ │
│  │ IDS Sensitivity: (Low) ──●────── (High)                  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🌍 GeoIP Blocking                                           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [✓] Enable GeoIP filtering                               │ │
│  │                                                          │ │
│  │ Blocked Countries:                                       │ │
│  │ [Select countries_______________________________▼]       │ │
│  │                                                          │ │
│  │ Selected:                                                │ │
│  │ 🇰🇵 North Korea [×]  🇮🇷 Iran [×]  🇨🇺 Cuba [×]        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ⏱️ Rate Limiting                                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [✓] Enable rate limiting                                 │ │
│  │                                                          │ │
│  │ Max connections per IP: [1000_____] / minute            │ │
│  │ Max bandwidth per IP:   [100______] Mbps                │ │
│  │ Max new connections:    [100______] / second            │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔐 TLS Inspection                                           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ [✓] Enable TLS inspection                                │ │
│  │                                                          │ │
│  │ CA Certificate: safeops-root-ca.crt (Installed)         │ │
│  │ [📥 Download]  [🔄 Regenerate]  [📋 View Details]       │ │
│  │                                                          │ │
│  │ Bypass TLS Inspection:                                  │ │
│  │ • banking.com (certificate pinning)                     │ │
│  │ • *.microsoft.com (trusted CDN)                         │ │
│  │ [+ Add Domain]                                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  [💾 Save Changes]                                           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### **Users & Roles Tab:**
```
┌──────────────────────────────────────────────────────────────┐
│  👥 Users & Roles                         [+ Create User]    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Username     │ Role        │ Last Login      │ Status│⋮││
│  ├──────────────┼─────────────┼─────────────────┼───────┼─┤│
│  │ admin        │ Super Admin │ 2 hours ago     │ 🟢    │⋮││
│  │ john.doe     │ Admin       │ 5 hours ago     │ 🟢    │⋮││
│  │ jane.smith   │ Operator    │ 1 day ago       │ 🟢    │⋮││
│  │ analyst      │ Analyst     │ 3 days ago      │ 🟡    │⋮││
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔐 Role Permissions:                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Role: [Admin_______________▼]                           │ │
│  │                                                          │ │
│  │ Permissions:                                             │ │
│  │ ┌──────────────────────────────────────────────────┐   │ │
│  │ │ [✓] View Dashboard                                │   │ │
│  │ │ [✓] Manage Rules (create, edit)                   │   │ │
│  │ │ [ ] Delete Rules (super admin only)               │   │ │
│  │ │ [✓] Manage Objects                                │   │ │
│  │ │ [✓] View Logs                                     │   │ │
│  │ │ [✓] View Analytics                                │   │ │
│  │ │ [✓] Configure Settings                            │   │ │
│  │ │ [ ] Manage Users (super admin only)               │   │ │
│  │ │ [ ] View Audit Logs (super admin only)            │   │ │
│  │ └──────────────────────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 📚 API Documentation

### **API Documentation Page:**
```
┌──────────────────────────────────────────────────────────────┐
│  📚 API Documentation                                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  🔑 Authentication                                           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ All API requests require JWT token authentication.      │ │
│  │                                                          │ │
│  │ POST /api/auth/login                                    │ │
│  │ {                                                        │ │
│  │   "username": "admin",                                  │ │
│  │   "password": "your_password"                           │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ Response:                                                │ │
│  │ {                                                        │ │
│  │   "token": "eyJhbGciOiJIUzI1NiIs...",                   │ │
│  │   "expires_in": 3600                                    │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ Use token in subsequent requests:                       │ │
│  │ Authorization: Bearer <token>                           │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  📊 Dashboard API                                            │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ GET /api/dashboard/metrics                              │ │
│  │ Returns current firewall metrics                        │ │
│  │                                                          │ │
│  │ GET /api/dashboard/traffic?period=24h                   │ │
│  │ Returns traffic data for specified period               │ │
│  │                                                          │ │
│  │ GET /api/dashboard/events?severity=high&limit=10        │ │
│  │ Returns recent security events                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🛡️ Rules API                                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ GET    /api/rules              List all rules           │ │
│  │ POST   /api/rules              Create new rule          │ │
│  │ GET    /api/rules/{id}         Get specific rule        │ │
│  │ PUT    /api/rules/{id}         Update rule              │ │
│  │ DELETE /api/rules/{id}         Delete rule              │ │
│  │ PATCH  /api/rules/{id}/toggle  Enable/disable rule      │ │
│  │ GET    /api/rules/{id}/stats   Get rule statistics      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  📦 Objects API                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ GET    /api/objects/ips        List IP objects          │ │
│  │ POST   /api/objects/ips        Create IP object         │ │
│  │ GET    /api/objects/domains    List domain objects      │ │
│  │ POST   /api/objects/domains    Create domain object     │ │
│  │ GET    /api/objects/groups     List groups              │ │
│  │ POST   /api/objects/groups     Create group             │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  📋 Logs API                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ GET /api/logs/traffic?from=2026-01-22&to=2026-01-23    │ │
│  │ Query Parameters:                                       │ │
│  │   - from: Start date (ISO 8601)                         │ │
│  │   - to: End date (ISO 8601)                             │ │
│  │   - source: Source IP filter                            │ │
│  │   - destination: Destination filter                     │ │
│  │   - action: ALLOW/DENY                                  │ │
│  │   - limit: Max results (default: 100)                   │ │
│  │   - offset: Pagination offset                           │ │
│  │                                                          │ │
│  │ GET /api/logs/export?format=csv                         │ │
│  │ Export logs in CSV/JSON format                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  🔌 WebSocket API (Real-time)                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ ws://firewall.local:8080/ws/live                        │ │
│  │                                                          │ │
│  │ Subscribe to real-time updates:                         │ │
│  │ {                                                        │ │
│  │   "type": "subscribe",                                  │ │
│  │   "channels": ["traffic", "events", "metrics"]          │ │
│  │ }                                                        │ │
│  │                                                          │ │
│  │ Receive updates:                                         │ │
│  │ {                                                        │ │
│  │   "channel": "traffic",                                 │ │
│  │   "data": {                                             │ │
│  │     "timestamp": "2026-01-23T15:42:23Z",                │ │
│  │     "packets_per_second": 102847,                       │ │
│  │     "throughput_mbps": 850                              │ │
│  │   }                                                      │ │
│  │ }                                                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  [📥 Download OpenAPI Spec]  [🧪 Try API (Postman)]         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technical Specifications

### **Frontend Tech Stack:**
```typescript
// package.json
{
  "name": "safeops-firewall-ui",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "@mui/material": "^5.15.0",
    "@mui/icons-material": "^5.15.0",
    "@reduxjs/toolkit": "^2.0.1",
    "react-redux": "^9.0.4",
    "axios": "^1.6.2",
    "recharts": "^2.10.3",
    "@tanstack/react-table": "^8.11.2",
    "react-hook-form": "^7.49.2",
    "zod": "^3.22.4",
    "date-fns": "^3.0.6",
    "socket.io-client": "^4.6.0"
  },
  "devDependencies": {
    "typescript": "^5.3.3",
    "vite": "^5.0.10",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.18"
  }
}
```

### **Backend API Structure:**
```go
// main.go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/websocket/v2"
)

func main() {
    app := fiber.New()

    // Serve static frontend files
    app.Static("/", "./frontend/dist")

    // API routes
    api := app.Group("/api")

    // Dashboard
    api.Get("/dashboard/metrics", getDashboardMetrics)
    api.Get("/dashboard/traffic", getTrafficData)
    api.Get("/dashboard/events", getSecurityEvents)

    // Rules
    api.Get("/rules", listRules)
    api.Post("/rules", createRule)
    api.Get("/rules/:id", getRule)
    api.Put("/rules/:id", updateRule)
    api.Delete("/rules/:id", deleteRule)
    api.Patch("/rules/:id/toggle", toggleRule)
    api.Get("/rules/:id/stats", getRuleStats)

    // Objects
    api.Get("/objects/ips", listIPObjects)
    api.Post("/objects/ips", createIPObject)
    api.Get("/objects/domains", listDomainObjects)
    api.Post("/objects/domains", createDomainObject)

    // Logs
    api.Get("/logs/traffic", queryTrafficLogs)
    api.Get("/logs/events", querySecurityEvents)
    api.Get("/logs/export", exportLogs)

    // Settings
    api.Get("/settings", getSettings)
    api.Put("/settings", updateSettings)

    // WebSocket for real-time updates
    app.Get("/ws/live", websocket.New(handleWebSocket))

    // Block page (redirect)
    app.Get("/blocked", serveBlockPage)

    // Captive portal
    app.Get("/portal", serveCaptivePortal)
    app.Post("/portal/authenticate", authenticateUser)

    app.Listen(":8080")
}
```

### **Database Schema (PostgreSQL):**
```sql
-- Firewall rules
CREATE TABLE rules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    enabled         BOOLEAN DEFAULT TRUE,
    priority        INTEGER NOT NULL,
    source_type     VARCHAR(50),
    source_value    TEXT,
    dest_type       VARCHAR(50),
    dest_value      TEXT,
    service         VARCHAR(100),
    action          VARCHAR(20),  -- ALLOW, DENY, REJECT, LOG
    log_enabled     BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Network objects
CREATE TABLE objects_ip (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(50),  -- single, range, subnet
    value           TEXT NOT NULL,
    description     TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE objects_domain (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    pattern         TEXT NOT NULL,
    match_type      VARCHAR(50),  -- exact, wildcard, regex
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Traffic logs
CREATE TABLE logs_traffic (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL,
    source_ip       INET NOT NULL,
    source_port     INTEGER,
    dest_ip         INET,
    dest_domain     VARCHAR(255),
    dest_port       INTEGER,
    protocol        VARCHAR(20),
    action          VARCHAR(20),
    rule_id         INTEGER REFERENCES rules(id),
    bytes           BIGINT,
    packets         INTEGER,
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_dest_domain (dest_domain)
);

-- Security events
CREATE TABLE events_security (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMP NOT NULL,
    severity        VARCHAR(20),  -- critical, high, medium, low
    type            VARCHAR(50),  -- malware, port_scan, dos, etc.
    source_ip       INET,
    destination     TEXT,
    description     TEXT,
    rule_id         INTEGER REFERENCES rules(id),
    acknowledged    BOOLEAN DEFAULT FALSE,
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_acknowledged (acknowledged)
);

-- Users
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    email           VARCHAR(255),
    role            VARCHAR(50),  -- super_admin, admin, operator, analyst
    enabled         BOOLEAN DEFAULT TRUE,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Captive portal devices
CREATE TABLE devices (
    id              SERIAL PRIMARY KEY,
    mac_address     VARCHAR(17) UNIQUE NOT NULL,
    ip_address      INET,
    hostname        VARCHAR(255),
    user_id         INTEGER REFERENCES users(id),
    trusted         BOOLEAN DEFAULT FALSE,
    cert_installed  BOOLEAN DEFAULT FALSE,
    first_seen      TIMESTAMP DEFAULT NOW(),
    last_seen       TIMESTAMP DEFAULT NOW()
);
```

---

## ✅ Summary

### **Complete Web UI Structure:**

```
SafeOps Firewall Web UI
├─ Dashboard (home page)
│  ├─ Key metrics (packets/sec, throughput, latency, CPU)
│  ├─ Real-time traffic chart
│  ├─ Top blocked domains
│  ├─ Top sources
│  ├─ Security events feed
│  ├─ Protocol distribution
│  └─ Traffic by country
│
├─ Rules Management
│  ├─ Rules list (table with search, filter, pagination)
│  ├─ Create/edit rule form (comprehensive)
│  ├─ Rule statistics modal
│  ├─ Rule groups
│  └─ Rule templates
│
├─ Objects Management
│  ├─ IP addresses (single, range, subnet)
│  ├─ Domains (exact, wildcard, lists)
│  ├─ Services (protocols, ports)
│  ├─ Groups (collections of objects)
│  └─ GeoIP (countries)
│
├─ Monitoring & Analytics
│  ├─ Real-time traffic monitor
│  ├─ Top talkers (sources & destinations)
│  ├─ Active connections
│  ├─ Protocol distribution
│  └─ Global threat map
│
├─ Logs & Events
│  ├─ Traffic logs (with filters)
│  ├─ Security events (severity-based)
│  ├─ System logs
│  ├─ Audit logs
│  ├─ Log detail modal
│  └─ Export (CSV, JSON)
│
├─ Block Page (end-user redirect)
│  ├─ Social media block
│  ├─ Malware block (critical warning)
│  ├─ Phishing block (credential theft)
│  ├─ Geo-block (country restriction)
│  └─ Request access form
│
├─ Captive Portal (device authentication)
│  ├─ Landing page (certificate + login)
│  ├─ Certificate download
│  ├─ Installation verification
│  ├─ Authentication form
│  ├─ Success page (welcome)
│  └─ Session information
│
├─ Settings
│  ├─ General (firewall info, network, performance)
│  ├─ Network (interface, IPv6, DNS)
│  ├─ Security (IDS, malware, GeoIP, rate limit, TLS)
│  ├─ Users & Roles (permissions matrix)
│  ├─ Notifications (email, Slack, webhooks)
│  └─ Backup & Restore
│
└─ API Documentation
   ├─ Authentication (JWT)
   ├─ Dashboard API
   ├─ Rules API (CRUD)
   ├─ Objects API (CRUD)
   ├─ Logs API (query, export)
   ├─ WebSocket API (real-time)
   └─ OpenAPI spec download
```

---

**END OF WEB UI DESIGN DOCUMENT**
