-- Migration: Add CA certificate tracking to devices table
-- Phase 3B: Track which devices have installed the SafeOps CA certificate

ALTER TABLE devices
ADD COLUMN ca_cert_installed BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE devices
ADD COLUMN ca_cert_installed_at TIMESTAMP WITH TIME ZONE;

-- Create index for fast lookup of devices without CA cert
CREATE INDEX idx_devices_ca_cert_installed ON devices(ca_cert_installed);

-- Comments
COMMENT ON COLUMN devices.ca_cert_installed IS 'Has device installed SafeOps CA certificate (Phase 3B)';
COMMENT ON COLUMN devices.ca_cert_installed_at IS 'Timestamp when CA certificate was installed';
