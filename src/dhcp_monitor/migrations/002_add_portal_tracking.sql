-- Migration: Add captive portal tracking to devices table
-- Phase 3A: Track which devices have been shown the captive portal (ALLOW_ONCE policy)

ALTER TABLE devices
ADD COLUMN portal_shown BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE devices
ADD COLUMN portal_shown_at TIMESTAMP WITH TIME ZONE;

-- Create index for fast lookup of devices without portal
CREATE INDEX idx_devices_portal_shown ON devices(portal_shown);

-- Comments
COMMENT ON COLUMN devices.portal_shown IS 'Has device been shown captive portal (Phase 3A ALLOW_ONCE)';
COMMENT ON COLUMN devices.portal_shown_at IS 'Timestamp when captive portal was first shown';
