-- Migration: Fix missing portal and CA tracking columns
-- These columns were missed in previous migrations or failed to apply

ALTER TABLE devices ADD COLUMN IF NOT EXISTS portal_shown BOOLEAN DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS portal_shown_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ca_cert_installed BOOLEAN DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ca_cert_installed_at TIMESTAMPTZ;

-- Re-create indexes if they don't exist
CREATE INDEX IF NOT EXISTS idx_devices_portal_shown ON devices(portal_shown);
CREATE INDEX IF NOT EXISTS idx_devices_ca_cert_installed ON devices(ca_cert_installed);
