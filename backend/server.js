// SafeOps Backend API Server
// Provides REST API access to PostgreSQL databases

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const db = require('./db');
const threatIntelRoutes = require('./routes/threat-intel');
const devicesRoutes = require('./routes/devices');

const app = express();
const PORT = process.env.PORT || 5050;

// Middleware
app.use(cors()); // Enable CORS for frontend
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Rate limiting - increased for development
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // Limit each IP to 1000 requests per windowMs (dev friendly)
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Health check endpoint
app.get('/health', async (req, res) => {
    try {
        const dbConnected = await db.testConnection();
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: dbConnected ? 'connected' : 'disconnected',
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: error.message
        });
    }
});

// Step-CA Proxy Routes (bypass TLS issues from browser)
const https = require('https');

// Proxy Step-CA health check
app.get('/api/stepca/health', async (req, res) => {
    const options = {
        hostname: 'localhost',
        port: 9000,
        path: '/health',
        method: 'GET',
        rejectUnauthorized: false // Ignore TLS cert errors
    };

    const proxyReq = https.request(options, (proxyRes) => {
        let data = '';
        proxyRes.on('data', chunk => data += chunk);
        proxyRes.on('end', () => {
            try {
                const json = JSON.parse(data);
                // Map 'ok' status to 'healthy' for the UI
                res.json({ status: json.status === 'ok' ? 'healthy' : json.status, ...json });
            } catch {
                res.json({ status: 'healthy', raw: data });
            }
        });
    });

    proxyReq.on('error', (err) => {
        console.error('Step-CA proxy error:', err.message);
        res.json({ status: 'offline', message: 'Cannot reach step-ca' });
    });

    proxyReq.end();
});

// Proxy Step-CA root CA download
app.get('/api/stepca/roots.pem', async (req, res) => {
    const options = {
        hostname: 'localhost',
        port: 9000,
        path: '/roots.pem',
        method: 'GET',
        rejectUnauthorized: false
    };

    const proxyReq = https.request(options, (proxyRes) => {
        let data = '';
        proxyRes.on('data', chunk => data += chunk);
        proxyRes.on('end', () => {
            res.type('application/x-pem-file').send(data);
        });
    });

    proxyReq.on('error', (err) => {
        res.status(503).json({ error: 'Cannot reach step-ca' });
    });

    proxyReq.end();
});

// API Routes
app.use('/api/threat-intel', threatIntelRoutes);
app.use('/api/devices', devicesRoutes);

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'SafeOps Backend API',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            devices: {
                list: '/api/devices',
                stats: '/api/devices/stats',
                byMac: '/api/devices/:mac',
                updateTrust: '/api/devices/:id/trust (PATCH)',
                delete: '/api/devices/:id (DELETE)'
            },
            threatIntel: {
                stats: '/api/threat-intel/stats',
                domains: '/api/threat-intel/domains',
                ips: '/api/threat-intel/ips',
                hashes: '/api/threat-intel/hashes',
                feeds: '/api/threat-intel/feeds',
                indicators: '/api/threat-intel/indicators',
                feedHistory: '/api/threat-intel/feed-history'
            }
        }
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Cannot ${req.method} ${req.path}`
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// Start server
async function startServer() {
    try {
        // Test database connection
        console.log('Testing database connection...');
        const dbConnected = await db.testConnection();

        if (!dbConnected) {
            console.warn('⚠ Database connection failed, but server will start anyway');
            console.warn('⚠ Make sure PostgreSQL is running and credentials are correct in .env');
        }

        // Start HTTP server
        app.listen(PORT, () => {
            console.log('');
            console.log('═══════════════════════════════════════════════════════════');
            console.log('  SafeOps Backend API Server');
            console.log('═══════════════════════════════════════════════════════════');
            console.log(`  ✓ Server running on http://localhost:${PORT}`);
            console.log(`  ✓ Health check: http://localhost:${PORT}/health`);
            console.log(`  ✓ API docs: http://localhost:${PORT}/`);
            console.log(`  ✓ Database: ${dbConnected ? 'Connected' : 'Disconnected'}`);
            console.log('═══════════════════════════════════════════════════════════');
            console.log('');
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully...');
    await db.closePool();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('\nSIGINT received, shutting down gracefully...');
    await db.closePool();
    process.exit(0);
});

// Start the server
startServer();
