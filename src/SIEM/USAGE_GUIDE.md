# SafeOps SIEM - Quick Start Guide

## ✅ Setup Complete!

**Status:** All ELK services are running

---

## Access URLs

| Service | URL | Status |
|---------|-----|--------|
| **Kibana** | http://localhost:5601 | 🟢 Running |
| **Elasticsearch** | http://localhost:9200 | 🟢 Running |

---

## Login Credentials

```
Username: safeops_admin
Password: SafeOps@SIEM2026!
```

---

## How to Use Kibana

### 1. Open Kibana
Navigate to: **http://localhost:5601**

### 2. Login
Use credentials above

### 3. Create Index Pattern
1. Go to **Management** → **Stack Management** → **Data Views**
2. Click **Create data view**
3. Enter pattern: `safeops-*`
4. Select `@timestamp` as time field
5. Click **Save**

### 4. View Logs
1. Go to **Analytics** → **Discover**
2. Select the `safeops-*` data view
3. Set time range to "Last 15 minutes"
4. See live SafeOps network logs!

---

## Available Index Patterns

| Pattern | Description |
|---------|-------------|
| `safeops-network_packets-*` | All network traffic |
| `safeops-ids_alerts-*` | IDS security alerts |
| `safeops-firewall-*` | Firewall events |
| `safeops-devices-*` | Device inventory |

---

## Service Management

### Start All Services
```powershell
D:\SafeOpsFV2\bin\elk\start-siem.bat
```

### Stop All Services
```powershell
D:\SafeOpsFV2\bin\elk\stop-siem.bat
```

---

## File Locations

| Component | Path |
|-----------|------|
| Elasticsearch | `D:\SafeOpsFV2\bin\elk\elasticsearch-8.17.0\` |
| Kibana | `D:\SafeOpsFV2\bin\elk\kibana-8.17.0\` |
| Logstash | `D:\SafeOpsFV2\bin\elk\logstash-8.17.0\` |
| ELK Logs | `D:\SafeOpsFV2\bin\elk\logs\` |
| ELK Data | `D:\SafeOpsFV2\bin\elk\data\` |

---

## Troubleshooting

### Services not starting?
```powershell
# Check what's running
Get-Process -Name "java", "node" | Format-Table

# Check port usage
netstat -an | findstr "9200 5601"
```

### No data in Kibana?
1. Ensure SafeOps Logger is running
2. Check Logstash logs in `D:\SafeOpsFV2\bin\elk\logs\logstash\`
3. Verify log files exist in `D:\SafeOpsFV2\logs\`

---

## Change Password

Edit these files and update the password:
1. `kibana-8.17.0\config\kibana.yml`
2. `logstash-8.17.0\config\conf.d\safeops.conf`

Then restart services.
