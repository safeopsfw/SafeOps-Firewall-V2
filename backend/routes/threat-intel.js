// Threat Intelligence API Routes
const express = require('express');
const router = express.Router();
const db = require('../db');

// GET /api/threat-intel/stats - Dashboard statistics
router.get('/stats', async (req, res) => {
    try {
        const stats = await db.query(`
      SELECT 
        (SELECT COUNT(*) FROM domains WHERE is_malicious = true) as malicious_domains,
        (SELECT COUNT(*) FROM ip_blacklist WHERE is_malicious = true) as malicious_ips,
        (SELECT COUNT(*) FROM hashes WHERE is_malicious = true) as malicious_hashes,
        (SELECT COUNT(*) FROM iocs) as total_iocs,
        (SELECT COUNT(*) FROM threat_feeds WHERE is_active = true) as active_feeds,
        (SELECT COUNT(DISTINCT source) FROM iocs) as ioc_sources
    `);

        res.json({
            success: true,
            data: stats.rows[0]
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch statistics' });
    }
});

// GET /api/threat-intel/domains - Domain reputation data
router.get('/domains', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const search = req.query.search || '';

        let query = `
      SELECT domain, is_malicious, threat_score, category, first_seen, last_seen
      FROM domains
      WHERE 1=1
    `;
        const params = [];

        if (search) {
            params.push(`%${search}%`);
            query += ` AND domain ILIKE $${params.length}`;
        }

        query += ` ORDER BY last_seen DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(limit, offset);

        const result = await db.query(query, params);

        // Get total count
        const countQuery = search
            ? `SELECT COUNT(*) FROM domains WHERE domain ILIKE $1`
            : `SELECT COUNT(*) FROM domains`;
        const countResult = await db.query(countQuery, search ? [`%${search}%`] : []);

        res.json({
            success: true,
            data: result.rows,
            pagination: {
                total: parseInt(countResult.rows[0].count),
                limit,
                offset
            }
        });
    } catch (error) {
        console.error('Domains error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch domains' });
    }
});

// GET /api/threat-intel/ips - IP reputation data
router.get('/ips', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;

        const result = await db.query(`
      SELECT ip_address, is_malicious, threat_score, abuse_type, first_seen, last_seen
      FROM ip_blacklist
      ORDER BY last_seen DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

        const countResult = await db.query('SELECT COUNT(*) FROM ip_blacklist');

        res.json({
            success: true,
            data: result.rows,
            pagination: {
                total: parseInt(countResult.rows[0].count),
                limit,
                offset
            }
        });
    } catch (error) {
        console.error('IPs error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch IPs' });
    }
});

// GET /api/threat-intel/hashes - File hash data
router.get('/hashes', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;

        const result = await db.query(`
      SELECT sha256, md5, sha1, is_malicious, malware_family, av_detection_rate, first_seen, last_seen
      FROM hashes
      ORDER BY last_seen DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

        const countResult = await db.query('SELECT COUNT(*) FROM hashes');

        res.json({
            success: true,
            data: result.rows,
            pagination: {
                total: parseInt(countResult.rows[0].count),
                limit,
                offset
            }
        });
    } catch (error) {
        console.error('Hashes error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch hashes' });
    }
});

// GET /api/threat-intel/feeds - Threat feed sources
router.get('/feeds', async (req, res) => {
    try {
        const result = await db.query(`
      SELECT 
        id, name, url, feed_type, is_active, update_frequency,
        last_update, last_success, record_count, error_count
      FROM threat_feeds
      ORDER BY name
    `);

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        console.error('Feeds error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch feeds' });
    }
});

// GET /api/threat-intel/indicators - IOC indicators
router.get('/indicators', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const type = req.query.type || '';

        let query = `
      SELECT indicator, indicator_type, threat_type, confidence, source, first_seen, last_seen, tags
      FROM iocs
      WHERE 1=1
    `;
        const params = [];

        if (type) {
            params.push(type);
            query += ` AND indicator_type = $${params.length}`;
        }

        query += ` ORDER BY last_seen DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(limit, offset);

        const result = await db.query(query, params);

        // Get total count
        const countQuery = type
            ? `SELECT COUNT(*) FROM iocs WHERE indicator_type = $1`
            : `SELECT COUNT(*) FROM iocs`;
        const countResult = await db.query(countQuery, type ? [type] : []);

        res.json({
            success: true,
            data: result.rows,
            pagination: {
                total: parseInt(countResult.rows[0].count),
                limit,
                offset
            }
        });
    } catch (error) {
        console.error('Indicators error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch indicators' });
    }
});

// GET /api/threat-intel/feed-history - Feed execution history
router.get('/feed-history', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;

        const result = await db.query(`
      SELECT 
        fh.id, fh.feed_id, tf.name as feed_name,
        fh.execution_time, fh.status, fh.records_processed,
        fh.records_added, fh.records_updated, fh.error_message
      FROM feed_history fh
      JOIN threat_feeds tf ON fh.feed_id = tf.id
      ORDER BY fh.execution_time DESC
      LIMIT $1
    `, [limit]);

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        console.error('Feed history error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch feed history' });
    }
});

module.exports = router;
