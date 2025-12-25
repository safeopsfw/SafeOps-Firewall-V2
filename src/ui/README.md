# SafeOps UI

This folder contains both developer and end-user interfaces.

## Structure

```
src/ui/
├── dev/       # Developer Dashboard (Port 3001)
│   └── (Admin panels, threat intel management, system config)
│
└── user/      # End-User Dashboard (Port 3000)
    └── (Client-facing interface, simple status views)
```

## Developer Dashboard (`dev/`)

**Port:** 3001

Full-featured admin interface for:

- Threat Intelligence Dashboard
- IOC Management (Indicators of Compromise)
- Feed Configuration
- Analytics & Reports
- User Management
- Firewall Rules
- IDS/IPS Configuration

### Run Dev Dashboard:

```bash
cd src/ui/dev
npm install
npm run dev  # Runs on http://localhost:3001
```

---

## User Dashboard (`user/`)

**Port:** 3000

Simplified end-user interface for:

- System Status Overview
- Basic Threat Stats
- Quick Lookups
- Notifications

### Run User Dashboard:

```bash
cd src/ui/user
npm install
npm run dev  # Runs on http://localhost:3000
```

---

## API Connection

Both dashboards connect to the threat intel API:

- `http://localhost:8080/api/status`
- `http://localhost:8080/api/lookup/ip/{ip}`
- `http://localhost:8080/api/lookup/domain/{domain}`
- `http://localhost:8080/api/lookup/hash/{hash}`
