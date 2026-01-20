import express from 'express';
import cors from 'cors';
import pg from 'pg';
import https from 'https';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5050;

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'threat_intel_db',
  user: 'postgres',
  password: 'admin',
});

// Project root
const PROJECT_ROOT = path.resolve(__dirname, '../../../../');
const THREAT_INTEL_PATH = path.join(PROJECT_ROOT, 'src', 'threat_intel');
const DATA_FETCH_PATH = path.join(THREAT_INTEL_PATH, 'data', 'fetch');

// Track pipeline status
let pipelineStatus = {
  running: false,
  lastRun: null,
  lastResult: null,
  logs: []
};

// ============================================================================
// API Endpoints
// ============================================================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Health check alias
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================================
// Device Endpoints (safeops database)
// ============================================================================

// SafeOps database pool for devices
const safeopsPool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'safeops',
  user: 'postgres',
  password: 'postgres',
});

// Get all devices
app.get('/api/devices', async (req, res) => {
  try {
    const result = await safeopsPool.query(`
      SELECT 
        mac_address as mac,
        host(current_ip) as ip,
        hostname,
        vendor,
        device_type as os,
        trust_status,
        interface_name as "nicType",
        interface_name as "nicInterfaceName",
        COALESCE(ca_cert_installed, false) as "hasCertificate",
        first_seen as "firstSeen",
        last_seen as "lastSeen"
      FROM devices
      ORDER BY last_seen DESC
    `);
    res.json(result.rows);
  } catch (error) {
    // Fallback query without ca_cert_installed column
    try {
      const result = await safeopsPool.query(`
        SELECT 
          mac_address as mac,
          host(current_ip) as ip,
          hostname,
          vendor,
          device_type as os,
          trust_status,
          interface_name as "nicType",
          interface_name as "nicInterfaceName",
          false as "hasCertificate",
          first_seen as "firstSeen",
          last_seen as "lastSeen"
        FROM devices
        ORDER BY last_seen DESC
      `);
      res.json(result.rows);
    } catch (fallbackErr) {
      console.error('Error fetching devices:', fallbackErr.message);
      res.json([]);
    }
  }
});

// Get device stats
app.get('/api/devices/stats', async (req, res) => {
  try {
    const result = await safeopsPool.query(`
      SELECT 
        COUNT(*) as total,
        0 as enrolled,
        COUNT(*) as unenrolled,
        COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes') as active
      FROM devices
    `);
    const stats = result.rows[0];
    res.json({
      totalDevices: parseInt(stats.total) || 0,
      enrolledDevices: parseInt(stats.enrolled) || 0,
      unenrolledDevices: parseInt(stats.unenrolled) || 0,
      activeDevices: parseInt(stats.active) || 0
    });
  } catch (error) {
    console.error('Error fetching device stats:', error.message);
    res.json({ totalDevices: 0, enrolledDevices: 0, unenrolledDevices: 0, activeDevices: 0 });
  }
});

// Database status
app.get('/api/status', async (req, res) => {
  try {
    const tables = ['domains', 'hashes', 'ip_blacklist', 'ip_geolocation', 'ip_anonymization'];
    const status = {};

    for (const table of tables) {
      try {
        const result = await pool.query(`SELECT COUNT(*) as count FROM ${table}`);
        const colResult = await pool.query(`
          SELECT column_name FROM information_schema.columns 
          WHERE table_name = $1
        `, [table]);

        status[table] = {
          row_count: parseInt(result.rows[0].count),
          columns: colResult.rows.length
        };
      } catch (err) {
        status[table] = { error: err.message };
      }
    }

    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get table headers
app.get('/api/headers', async (req, res) => {
  try {
    const tables = ['domains', 'hashes', 'ip_blacklist', 'ip_geolocation', 'ip_anonymization'];
    const headers = {};

    for (const table of tables) {
      try {
        const result = await pool.query(`
          SELECT column_name, data_type, is_nullable 
          FROM information_schema.columns 
          WHERE table_name = $1
          ORDER BY ordinal_position
        `, [table]);
        headers[table] = result.rows;
      } catch (err) {
        headers[table] = { error: err.message };
      }
    }

    res.json(headers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// IP Lookup
app.get('/api/lookup/ip/:ip', async (req, res) => {
  const { ip } = req.params;
  const result = {};

  try {
    // Check blacklist
    const blacklist = await pool.query(
      'SELECT * FROM ip_blacklist WHERE ip_address = $1 LIMIT 1',
      [ip]
    );
    if (blacklist.rows.length > 0) result.blacklist = blacklist.rows[0];

    // Check geolocation
    const geo = await pool.query(
      'SELECT * FROM ip_geolocation WHERE ip_address = $1 LIMIT 1',
      [ip]
    );
    if (geo.rows.length > 0) result.geolocation = geo.rows[0];

    // Check anonymization
    const anon = await pool.query(
      'SELECT * FROM ip_anonymization WHERE ip_address = $1 LIMIT 1',
      [ip]
    );
    if (anon.rows.length > 0) result.anonymization = anon.rows[0];

    res.json({ ip, found: Object.keys(result).length > 0, data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Domain Lookup
app.get('/api/lookup/domain/:domain', async (req, res) => {
  const { domain } = req.params;

  try {
    const result = await pool.query(
      'SELECT * FROM domains WHERE domain = $1 LIMIT 1',
      [domain]
    );

    res.json({
      domain,
      found: result.rows.length > 0,
      data: result.rows[0] || null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Hash Lookup
app.get('/api/lookup/hash/:hash', async (req, res) => {
  const { hash } = req.params;

  try {
    let result;
    if (hash.length === 64) {
      result = await pool.query(
        'SELECT * FROM hashes WHERE sha256 = $1 LIMIT 1',
        [hash]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM hashes WHERE md5 = $1 LIMIT 1',
        [hash]
      );
    }

    res.json({
      hash,
      found: result.rows.length > 0,
      data: result.rows[0] || null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// Pipeline Execution
// ============================================================================

// Get pipeline status
app.get('/api/pipeline/status', (req, res) => {
  res.json(pipelineStatus);
});

// Trigger pipeline update
app.post('/api/update', async (req, res) => {
  if (pipelineStatus.running) {
    return res.status(409).json({
      error: 'Pipeline is already running',
      status: pipelineStatus
    });
  }

  pipelineStatus = {
    running: true,
    lastRun: new Date().toISOString(),
    lastResult: null,
    logs: ['Pipeline started...']
  };

  // Return immediately, pipeline runs in background
  res.json({
    message: 'Pipeline started',
    status: pipelineStatus
  });

  // Run pipeline in background
  runPipeline();
});

// Run the Go pipeline
async function runPipeline() {
  const startTime = Date.now();

  try {
    pipelineStatus.logs.push('[FETCH] Starting fetcher...');

    // Run the Go pipeline with -delete flag
    await new Promise((resolve, reject) => {
      const proc = spawn('go', ['run', './cmd/pipeline', '-delete=true'], {
        cwd: THREAT_INTEL_PATH,
        shell: true
      });

      proc.stdout.on('data', (data) => {
        const lines = data.toString().split('\n').filter(l => l.trim());
        lines.forEach(line => pipelineStatus.logs.push(line));
      });

      proc.stderr.on('data', (data) => {
        const lines = data.toString().split('\n').filter(l => l.trim());
        lines.forEach(line => pipelineStatus.logs.push(`[ERROR] ${line}`));
      });

      proc.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Pipeline exited with code ${code}`));
        }
      });

      proc.on('error', (err) => {
        reject(err);
      });
    });

    // Clean up data/fetch folder
    pipelineStatus.logs.push('[CLEANUP] Removing data/fetch folder...');
    if (fs.existsSync(DATA_FETCH_PATH)) {
      fs.rmSync(DATA_FETCH_PATH, { recursive: true, force: true });
      pipelineStatus.logs.push('[CLEANUP] data/fetch folder removed');
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    pipelineStatus.logs.push(`[COMPLETE] Pipeline finished in ${duration}s`);
    pipelineStatus.lastResult = { success: true, duration: `${duration}s` };

  } catch (error) {
    pipelineStatus.logs.push(`[FAILED] ${error.message}`);
    pipelineStatus.lastResult = { success: false, error: error.message };
  } finally {
    pipelineStatus.running = false;
  }
}

// ============================================================================
// Step-CA Proxy Endpoints (bypass TLS issues for self-signed certs)
// ============================================================================

// Helper function to make https request ignoring self-signed certs
function httpsGet(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const options = {
      rejectUnauthorized: false, // Ignore self-signed cert
      timeout: timeout
    };

    const req = https.get(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

// Step-CA health check proxy
app.get('/api/stepca/health', async (req, res) => {
  try {
    const result = await httpsGet('https://localhost:9000/health');
    if (result.status === 200) {
      res.json(JSON.parse(result.data));
    } else {
      res.status(result.status).json({ status: 'error', message: 'Step-CA not responding' });
    }
  } catch (error) {
    console.error('Step-CA health check failed:', error.message);
    res.status(503).json({ status: 'offline', message: error.message });
  }
});

// Step-CA root CA certificate proxy
app.get('/api/stepca/roots.pem', async (req, res) => {
  try {
    const result = await httpsGet('https://localhost:9000/roots.pem');
    if (result.status === 200) {
      res.type('text/plain').send(result.data);
    } else {
      res.status(result.status).send('Unable to fetch root CA');
    }
  } catch (error) {
    console.error('Step-CA roots.pem fetch failed:', error.message);
    res.status(503).send('Step-CA not available');
  }
});

// ============================================================================
// Start Server
// ============================================================================

app.listen(PORT, () => {
  console.log('==========================================');
  console.log('  SafeOps Threat Intel API Server');
  console.log('==========================================');
  console.log(`  Port: ${PORT}`);
  console.log(`  Endpoints:`);
  console.log(`    GET  /api/health`);
  console.log(`    GET  /api/status`);
  console.log(`    GET  /api/headers`);
  console.log(`    GET  /api/lookup/ip/{ip}`);
  console.log(`    GET  /api/lookup/domain/{domain}`);
  console.log(`    GET  /api/lookup/hash/{hash}`);
  console.log(`    POST /api/update`);
  console.log(`    GET  /api/pipeline/status`);
  console.log(`    GET  /api/stepca/health`);
  console.log(`    GET  /api/stepca/roots.pem`);
  console.log('==========================================');
});
