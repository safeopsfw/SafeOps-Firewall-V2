// Firewall Management Routes
// Provides REST API for firewall rules, stats, and packet logs

const express = require('express');
const router = express.Router();
const db = require('../db');

// =============================================================================
// GET /api/firewall/rules - List all firewall rules
// =============================================================================
router.get('/rules', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                rule_id,
                name,
                description,
                action,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                device_mac,
                priority,
                enabled,
                hit_count,
                status,
                created_at,
                updated_at
            FROM firewall_rules 
            ORDER BY priority ASC, created_at DESC
        `);

        const rules = result.rows.map(row => ({
            id: row.rule_id,
            name: row.name,
            description: row.description,
            action: row.action,
            protocol: row.protocol,
            srcIp: row.src_ip,
            dstIp: row.dst_ip,
            srcPort: row.src_port,
            dstPort: row.dst_port,
            deviceMac: row.device_mac,
            priority: row.priority,
            enabled: row.enabled,
            hitCount: row.hit_count,
            status: row.status,
            createdAt: row.created_at,
            updatedAt: row.updated_at
        }));

        res.json(rules);
    } catch (error) {
        console.error('Error fetching firewall rules:', error);
        res.status(500).json({ error: 'Failed to fetch rules', details: error.message });
    }
});

// =============================================================================
// POST /api/firewall/rules - Create new rule
// =============================================================================
router.post('/rules', async (req, res) => {
    try {
        const {
            name, description, action, protocol,
            srcIp, dstIp, srcPort, dstPort,
            deviceMac, priority, enabled
        } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'Rule name is required' });
        }

        const result = await db.query(`
            INSERT INTO firewall_rules 
                (name, description, action, protocol, src_ip, dst_ip, src_port, dst_port, device_mac, priority, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
        `, [
            name,
            description || null,
            action || 'BLOCK',
            protocol || 'ANY',
            srcIp || '*',
            dstIp || '*',
            srcPort || '*',
            dstPort || '*',
            deviceMac || '*',
            priority || 100,
            enabled !== false
        ]);

        const row = result.rows[0];
        console.log(`[FIREWALL] Rule created: ${name} (${action})`);

        res.status(201).json({
            id: row.rule_id,
            name: row.name,
            action: row.action,
            protocol: row.protocol,
            srcIp: row.src_ip,
            dstIp: row.dst_ip,
            srcPort: row.src_port,
            dstPort: row.dst_port,
            deviceMac: row.device_mac,
            priority: row.priority,
            enabled: row.enabled,
            hitCount: 0
        });
    } catch (error) {
        console.error('Error creating firewall rule:', error);
        res.status(500).json({ error: 'Failed to create rule', details: error.message });
    }
});

// =============================================================================
// PUT /api/firewall/rules/:id - Update existing rule
// =============================================================================
router.put('/rules/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            name, description, action, protocol,
            srcIp, dstIp, srcPort, dstPort,
            deviceMac, priority, enabled
        } = req.body;

        const result = await db.query(`
            UPDATE firewall_rules SET
                name = COALESCE($1, name),
                description = COALESCE($2, description),
                action = COALESCE($3, action),
                protocol = COALESCE($4, protocol),
                src_ip = COALESCE($5, src_ip),
                dst_ip = COALESCE($6, dst_ip),
                src_port = COALESCE($7, src_port),
                dst_port = COALESCE($8, dst_port),
                device_mac = COALESCE($9, device_mac),
                priority = COALESCE($10, priority),
                enabled = COALESCE($11, enabled),
                updated_at = NOW()
            WHERE rule_id = $12
            RETURNING *
        `, [name, description, action, protocol, srcIp, dstIp, srcPort, dstPort, deviceMac, priority, enabled, id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        const row = result.rows[0];
        console.log(`[FIREWALL] Rule updated: ${row.name}`);

        res.json({
            id: row.rule_id,
            name: row.name,
            action: row.action,
            protocol: row.protocol,
            srcIp: row.src_ip,
            dstIp: row.dst_ip,
            srcPort: row.src_port,
            dstPort: row.dst_port,
            deviceMac: row.device_mac,
            priority: row.priority,
            enabled: row.enabled,
            hitCount: row.hit_count
        });
    } catch (error) {
        console.error('Error updating firewall rule:', error);
        res.status(500).json({ error: 'Failed to update rule', details: error.message });
    }
});

// =============================================================================
// DELETE /api/firewall/rules/:id - Delete rule
// =============================================================================
router.delete('/rules/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const result = await db.query(`
            DELETE FROM firewall_rules WHERE rule_id = $1
            RETURNING name
        `, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        console.log(`[FIREWALL] Rule deleted: ${result.rows[0].name}`);
        res.json({ success: true, deleted: result.rows[0].name });
    } catch (error) {
        console.error('Error deleting firewall rule:', error);
        res.status(500).json({ error: 'Failed to delete rule', details: error.message });
    }
});

// =============================================================================
// PATCH /api/firewall/rules/:id/toggle - Enable/disable rule
// =============================================================================
router.patch('/rules/:id/toggle', async (req, res) => {
    try {
        const { id } = req.params;

        const result = await db.query(`
            UPDATE firewall_rules 
            SET enabled = NOT enabled, updated_at = NOW()
            WHERE rule_id = $1
            RETURNING rule_id, name, enabled
        `, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rule not found' });
        }

        const row = result.rows[0];
        console.log(`[FIREWALL] Rule ${row.enabled ? 'enabled' : 'disabled'}: ${row.name}`);

        res.json({
            id: row.rule_id,
            name: row.name,
            enabled: row.enabled
        });
    } catch (error) {
        console.error('Error toggling firewall rule:', error);
        res.status(500).json({ error: 'Failed to toggle rule', details: error.message });
    }
});

// =============================================================================
// GET /api/firewall/stats - Get packet statistics
// =============================================================================
router.get('/stats', async (req, res) => {
    try {
        // Get today's stats
        const todayResult = await db.query(`
            SELECT 
                COALESCE(SUM(total_packets), 0)::int as total,
                COALESCE(SUM(allowed_packets), 0)::int as allowed,
                COALESCE(SUM(blocked_packets), 0)::int as blocked,
                COALESCE(SUM(tcp_packets), 0)::int as tcp,
                COALESCE(SUM(udp_packets), 0)::int as udp,
                COALESCE(SUM(icmp_packets), 0)::int as icmp
            FROM firewall_stats
            WHERE stat_date >= CURRENT_DATE - INTERVAL '7 days'
        `);

        // Get rule counts
        const rulesResult = await db.query(`
            SELECT 
                COUNT(*)::int as total_rules,
                COUNT(*) FILTER (WHERE enabled = true)::int as active_rules,
                COUNT(*) FILTER (WHERE action = 'BLOCK')::int as block_rules,
                COUNT(*) FILTER (WHERE action = 'ALLOW')::int as allow_rules
            FROM firewall_rules
        `);

        const stats = todayResult.rows[0];
        const ruleStats = rulesResult.rows[0];

        res.json({
            total: stats.total || 0,
            allowed: stats.allowed || 0,
            blocked: stats.blocked || 0,
            tcp: stats.tcp || 0,
            udp: stats.udp || 0,
            icmp: stats.icmp || 0,
            totalRules: ruleStats.total_rules || 0,
            activeRules: ruleStats.active_rules || 0,
            blockRules: ruleStats.block_rules || 0,
            allowRules: ruleStats.allow_rules || 0
        });
    } catch (error) {
        console.error('Error fetching firewall stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
    }
});

// =============================================================================
// GET /api/firewall/logs - Get recent packet logs
// =============================================================================
router.get('/logs', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;

        const result = await db.query(`
            SELECT 
                log_id,
                timestamp,
                src_ip::text,
                dst_ip::text,
                src_port,
                dst_port,
                protocol,
                action,
                rule_name,
                device_mac
            FROM packet_logs
            ORDER BY timestamp DESC
            LIMIT $1
        `, [limit]);

        const logs = result.rows.map(row => ({
            id: row.log_id,
            timestamp: row.timestamp,
            srcIp: row.src_ip,
            dstIp: row.dst_ip,
            srcPort: row.src_port,
            dstPort: row.dst_port,
            protocol: row.protocol,
            action: row.action,
            rule: row.rule_name || 'Default',
            deviceMac: row.device_mac
        }));

        res.json(logs);
    } catch (error) {
        console.error('Error fetching packet logs:', error);
        res.status(500).json({ error: 'Failed to fetch logs', details: error.message });
    }
});

// =============================================================================
// POST /api/firewall/logs - Log a packet (for packet engine integration)
// =============================================================================
router.post('/logs', async (req, res) => {
    try {
        const { srcIp, dstIp, srcPort, dstPort, protocol, action, ruleName, ruleId, deviceMac } = req.body;

        const result = await db.query(`
            INSERT INTO packet_logs 
                (src_ip, dst_ip, src_port, dst_port, protocol, action, rule_name, rule_id, device_mac)
            VALUES ($1::inet, $2::inet, $3, $4, $5, $6, $7, $8, $9)
            RETURNING log_id
        `, [srcIp, dstIp, srcPort, dstPort, protocol, action, ruleName, ruleId || null, deviceMac]);

        // Update daily stats
        await db.query(`SELECT update_firewall_stats($1, $2)`, [action, protocol]);

        res.status(201).json({ id: result.rows[0].log_id });
    } catch (error) {
        console.error('Error logging packet:', error);
        res.status(500).json({ error: 'Failed to log packet', details: error.message });
    }
});

// =============================================================================
// GET /api/firewall/policies - Get device policies
// =============================================================================
router.get('/policies', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                dp.policy_id,
                dp.device_mac,
                dp.policy_name,
                dp.default_action,
                dp.bandwidth_limit,
                dp.time_restriction,
                dp.blocked_ports,
                dp.allowed_ports,
                dp.notes,
                d.hostname,
                d.current_ip::text as ip,
                d.trust_status
            FROM device_policies dp
            LEFT JOIN devices d ON dp.device_mac = d.mac_address
            ORDER BY dp.created_at DESC
        `);

        res.json(result.rows.map(row => ({
            id: row.policy_id,
            mac: row.device_mac,
            policyName: row.policy_name,
            defaultAction: row.default_action,
            bandwidthLimit: row.bandwidth_limit,
            timeRestriction: row.time_restriction,
            blockedPorts: row.blocked_ports,
            allowedPorts: row.allowed_ports,
            notes: row.notes,
            hostname: row.hostname,
            ip: row.ip,
            trustStatus: row.trust_status
        })));
    } catch (error) {
        console.error('Error fetching device policies:', error);
        res.status(500).json({ error: 'Failed to fetch policies', details: error.message });
    }
});

module.exports = router;
