# SafeOps UI Architecture Plan

## Overview

SafeOps is a unified security platform with multiple modules. The UI is a single React SPA that connects to various Go backend APIs.

## Architecture

```
SafeOps/
├── ui/                          # React SPA (Vite + React)
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.jsx        # Authentication
│   │   │   ├── Dashboard.jsx    # Main SafeOps dashboard
│   │   │   ├── Cognitive.jsx    # Entity/Library browser
│   │   │   ├── ThreatIntel/     # Threat Intelligence module
│   │   │   ├── DNSServer/       # DNS Server module
│   │   │   ├── Firewall/        # Firewall module
│   │   │   └── Settings.jsx     # App settings
│   │   ├── components/          # Reusable components
│   │   ├── services/            # API clients
│   │   └── context/             # React Context (Auth, Theme)
│   └── package.json
│
├── src/
│   ├── threat_intel/            # Threat Intel Go API (no UI)
│   ├── dns_server/              # DNS Server module
│   ├── firewall/                # Firewall module
│   └── auth/                    # NEW: Auth service
│
└── database/
    └── schemas/
        ├── users.sql            # User management
        └── threat_intel.sql     # Threat intel tables
```

## Modules

| Module       | Status      | Description                               |
| ------------ | ----------- | ----------------------------------------- |
| Login/Auth   | 🔨 Building | User authentication with hashed passwords |
| Dashboard    | 🔨 Building | Main SafeOps landing page                 |
| Cognitive    | 📋 Planned  | Entity/Library browser                    |
| Threat Intel | 📋 Planned  | IOC Workspace, Feeds, Analytics           |
| DNS Server   | 📋 Planned  | DNS monitoring                            |
| Firewall     | 📋 Planned  | Firewall rules management                 |
| Settings     | 📋 Planned  | Data toggle (Dummy/DB), User preferences  |

## Default Superuser

- **Email**: admin@safeops.com
- **Password**: safeops1234 (stored as bcrypt hash)
- **Role**: superadmin

## Data Source Toggle

Settings page will have a toggle:

- **Dummy Data**: Shows mock/sample data for development
- **Database**: Connects to real PostgreSQL data

## Technology Stack

- **Frontend**: React 18 + Vite + Tailwind CSS
- **Backend**: Go (existing modules)
- **Database**: PostgreSQL
- **Auth**: JWT tokens + bcrypt password hashing
