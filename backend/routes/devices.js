// Device Management Routes
// Provides REST API for DHCP Monitor devices table

const express = require('express');
const router = express.Router();
const db = require('../db');

// =============================================================================
// GET /api/devices - List all devices
// =============================================================================
router.get('/', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                device_id,
                mac_address,
                current_ip::text,
                hostname,
                device_type,
                vendor,
                trust_status,
                interface_name,
                interface_index,
                status,
                is_online,
                detection_method,
                first_seen,
                last_seen,
                notes
            FROM devices 
            ORDER BY last_seen DESC
            LIMIT 100
        `);

        // Map to UI-friendly format
        const devices = result.rows.map(row => ({
            id: row.device_id,
            mac: row.mac_address,
            ip: row.current_ip,
            hostname: row.hostname || 'Unknown',
            os: row.device_type || row.vendor || 'Unknown',
            vendor: row.vendor,
            trustStatus: row.trust_status,
            hasCertificate: row.trust_status === 'TRUSTED',
            nicInterfaceName: row.interface_name,
            nicType: row.interface_name?.includes('Wi-Fi Direct') ? 'hotspot'
                : row.interface_name?.includes('Ethernet') ? 'ethernet'
                    : row.interface_name?.includes('Wi-Fi') ? 'wifi'
                        : 'other',
            status: row.status,
            isOnline: row.is_online,
            detectionMethod: row.detection_method,
            firstSeen: row.first_seen,
            lastSeen: row.last_seen,
            notes: row.notes
        }));

        res.json(devices);
    } catch (error) {
        console.error('Error fetching devices:', error);
        res.status(500).json({ error: 'Failed to fetch devices', details: error.message });
    }
});

// =============================================================================
// GET /api/devices/stats - Get device statistics
// =============================================================================
router.get('/stats', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                COUNT(*)::int as total,
                COUNT(*) FILTER (WHERE trust_status = 'TRUSTED')::int as enrolled,
                COUNT(*) FILTER (WHERE trust_status = 'UNTRUSTED')::int as unenrolled,
                COUNT(*) FILTER (WHERE trust_status = 'BLOCKED')::int as blocked,
                COUNT(*) FILTER (WHERE is_online = true)::int as active,
                COUNT(*) FILTER (WHERE status = 'ACTIVE')::int as active_status,
                COUNT(*) FILTER (WHERE interface_name LIKE '%Wi-Fi Direct%')::int as hotspot_devices,
                COUNT(*) FILTER (WHERE interface_name LIKE '%Ethernet%')::int as ethernet_devices
            FROM devices
        `);

        const stats = result.rows[0];

        res.json({
            totalDevices: stats.total || 0,
            enrolledDevices: stats.enrolled || 0,
            unenrolledDevices: stats.unenrolled || 0,
            blockedDevices: stats.blocked || 0,
            activeDevices: stats.hotspot_devices || 0,
            hotspotDevices: stats.hotspot_devices || 0,
            ethernetDevices: stats.ethernet_devices || 0
        });
    } catch (error) {
        console.error('Error fetching device stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
    }
});

// =============================================================================
// GET /api/devices/:mac - Get single device by MAC
// =============================================================================
router.get('/:mac', async (req, res) => {
    try {
        const { mac } = req.params;

        const result = await db.query(`
            SELECT * FROM devices WHERE mac_address = $1
        `, [mac.toUpperCase()]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }

        const row = result.rows[0];
        res.json({
            id: row.device_id,
            mac: row.mac_address,
            ip: row.current_ip,
            hostname: row.hostname,
            trustStatus: row.trust_status,
            hasCertificate: row.trust_status === 'TRUSTED',
            nicInterfaceName: row.interface_name,
            firstSeen: row.first_seen,
            lastSeen: row.last_seen
        });
    } catch (error) {
        console.error('Error fetching device:', error);
        res.status(500).json({ error: 'Failed to fetch device', details: error.message });
    }
});

// =============================================================================
// PATCH /api/devices/:id/trust - Update trust status
// =============================================================================
router.patch('/:id/trust', async (req, res) => {
    try {
        const { id } = req.params;
        const { trustStatus } = req.body;

        // Validate trust status
        const validStatuses = ['TRUSTED', 'UNTRUSTED', 'BLOCKED'];
        if (!validStatuses.includes(trustStatus)) {
            return res.status(400).json({
                error: 'Invalid trust status',
                valid: validStatuses
            });
        }

        const result = await db.query(`
            UPDATE devices 
            SET trust_status = $1, updated_at = NOW()
            WHERE device_id = $2
            RETURNING device_id, mac_address, trust_status
        `, [trustStatus, id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }

        console.log(`[DEVICES] Trust updated: ${result.rows[0].mac_address} → ${trustStatus}`);

        res.json({
            success: true,
            device: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating trust status:', error);
        res.status(500).json({ error: 'Failed to update trust', details: error.message });
    }
});

// =============================================================================
// DELETE /api/devices/:id - Delete device
// =============================================================================
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const result = await db.query(`
            DELETE FROM devices WHERE device_id = $1
            RETURNING mac_address
        `, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }

        console.log(`[DEVICES] Deleted: ${result.rows[0].mac_address}`);
        res.json({ success: true, deleted: result.rows[0].mac_address });
    } catch (error) {
        console.error('Error deleting device:', error);
        res.status(500).json({ error: 'Failed to delete device', details: error.message });
    }
});

// =============================================================================
// GET /api/devices/interface/:name - Get devices by interface
// =============================================================================
router.get('/interface/:name', async (req, res) => {
    try {
        const { name } = req.params;

        const result = await db.query(`
            SELECT * FROM devices 
            WHERE interface_name ILIKE $1
            ORDER BY last_seen DESC
        `, [`%${name}%`]);

        res.json(result.rows.map(row => ({
            id: row.device_id,
            mac: row.mac_address,
            ip: row.current_ip,
            hostname: row.hostname,
            trustStatus: row.trust_status,
            nicInterfaceName: row.interface_name
        })));
    } catch (error) {
        console.error('Error fetching devices by interface:', error);
        res.status(500).json({ error: 'Failed to fetch devices', details: error.message });
    }
});

module.exports = router;
