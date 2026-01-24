## 2026-05-22 - Launcher Ignored Project Security Config
**Vulnerability:** Hardcoded PostgreSQL credentials ("postgres"/"postgres") in `src/launcher/main.go` were effectively bypassing the user-configured `.env` file in `backend/`, forcing usage of default insecure credentials or preventing connection if users followed security instructions.
**Learning:** In polyglot repos (Go + Node.js), inconsistent configuration loading patterns (Node using `dotenv`, Go using constants) lead to security gaps where one component respects secrets and another hardcodes them.
**Prevention:** Establish a unified configuration strategy (e.g., a shared config loader or strict strict adherence to `.env` loading) across all microservices regardless of language.
