-- SafeOps DHCP Monitor Database Setup
-- Run this as PostgreSQL superuser (postgres)

-- Create database if not exists
SELECT 'CREATE DATABASE safeops' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'safeops')\gexec

-- Create user if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'safeops') THEN
        CREATE USER safeops WITH PASSWORD 'safeops123';
    END IF;
END
$$;

-- Connect to safeops database
\c safeops

-- Grant all privileges on public schema
GRANT ALL ON SCHEMA public TO safeops;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO safeops;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO safeops;
GRANT CREATE ON SCHEMA public TO safeops;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO safeops;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO safeops;

-- Make safeops owner of public schema (alternative fix)
ALTER SCHEMA public OWNER TO safeops;

\echo 'Database setup complete!'
