import express from 'express';
import cors from 'cors';
import pg from 'pg';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 8080;

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
  console.log('==========================================');
});
