-- Migration: Add device fingerprint columns to devices table
-- Description: Stores comprehensive device identification data collected via Windows APIs

-- NetBIOS Information
ALTER TABLE devices ADD COLUMN IF NOT EXISTS netbios_name VARCHAR(255);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS netbios_domain VARCHAR(255);

-- DNS/Hostname
ALTER TABLE devices ADD COLUMN IF NOT EXISTS resolved_hostname VARCHAR(255);

-- OS Detection
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_type VARCHAR(100);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version VARCHAR(100);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_fingerprint VARCHAR(500);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS initial_ttl INTEGER;

-- DHCP Fingerprint
ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_vendor_class VARCHAR(255);

-- Device Classification
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_class VARCHAR(100);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS manufacturer VARCHAR(255);

-- Fingerprint Timestamp
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fingerprinted_at TIMESTAMP;

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_devices_os_type ON devices(os_type);
CREATE INDEX IF NOT EXISTS idx_devices_device_class ON devices(device_class);
CREATE INDEX IF NOT EXISTS idx_devices_manufacturer ON devices(manufacturer);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprinted_at ON devices(fingerprinted_at);

COMMENT ON COLUMN devices.netbios_name IS 'NetBIOS computer name from Windows API';
COMMENT ON COLUMN devices.netbios_domain IS 'NetBIOS domain/workgroup';
COMMENT ON COLUMN devices.resolved_hostname IS 'DNS reverse lookup hostname';
COMMENT ON COLUMN devices.os_type IS 'Detected OS: Windows, Linux, Android, iOS, etc.';
COMMENT ON COLUMN devices.os_version IS 'Detected OS version';
COMMENT ON COLUMN devices.os_fingerprint IS 'Complete fingerprint string for device identification';
COMMENT ON COLUMN devices.initial_ttl IS 'Initial TTL value for OS fingerprinting (64=Linux,128=Windows,255=Network)';
COMMENT ON COLUMN devices.dhcp_vendor_class IS 'DHCP Option 60 vendor class identifier';
COMMENT ON COLUMN devices.device_class IS 'Device classification: Phone, Laptop, IoT, Router, etc.';
COMMENT ON COLUMN devices.manufacturer IS 'Device manufacturer from enhanced MAC lookup';
COMMENT ON COLUMN devices.fingerprinted_at IS 'Last fingerprint collection timestamp';
