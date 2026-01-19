/**
 * Threat Intel Service
 * Handles all API calls to the threat intel backend
 */

const API_BASE = 'http://localhost:5050/api/threat-intel';

// =============================================================================
// Database Categories
// =============================================================================
export const DB_CATEGORIES = {
  domains: {
    name: 'Domains',
    icon: '🌐',
    description: 'Malicious domain database (abuse, malware, phishing)',
    color: 'from-blue-500 to-blue-600'
  },
  hashes: {
    name: 'Malware Hashes',
    icon: '🔐',
    description: 'MD5/SHA256 file hashes (malware samples)',
    color: 'from-purple-500 to-purple-600'
  },
  ip_blacklist: {
    name: 'IP Blacklist',
    icon: '🚫',
    description: 'Blocked IP addresses (C2, scanners, attackers)',
    color: 'from-red-500 to-red-600'
  },
  ip_geolocation: {
    name: 'GeoIP Database',
    icon: '🗺️',
    description: 'IP geolocation data (country, city, ISP)',
    color: 'from-green-500 to-green-600'
  },
  ip_anonymization: {
    name: 'Anonymizers',
    icon: '🎭',
    description: 'Tor exit nodes, VPNs, proxies, hosting IPs',
    color: 'from-orange-500 to-orange-600'
  }
};

// =============================================================================
// Source Types
// =============================================================================
export const SOURCE_TYPES = [
  { id: 'url_csv', name: 'CSV Feed URL', icon: '📊' },
  { id: 'url_json', name: 'JSON API', icon: '📦' },
  { id: 'url_txt', name: 'Plain Text List', icon: '📄' },
  { id: 'api_key', name: 'API with Key', icon: '🔑' },
  { id: 'manual', name: 'Manual Upload', icon: '📤' },
];

// =============================================================================
// API Functions
// =============================================================================

/**
 * Get database statistics (row counts, etc.)
 */
export async function getDatabaseStats() {
  try {
    const response = await fetch(`${API_BASE}/status`);
    if (!response.ok) throw new Error('Failed to fetch stats');
    return await response.json();
  } catch (error) {
    console.error('getDatabaseStats error:', error);
    return null;
  }
}

/**
 * Get table headers/columns info
 */
export async function getTableHeaders() {
  try {
    const response = await fetch(`${API_BASE}/headers`);
    if (!response.ok) throw new Error('Failed to fetch headers');
    return await response.json();
  } catch (error) {
    console.error('getTableHeaders error:', error);
    return null;
  }
}

/**
 * Check API health
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE}/health`);
    if (!response.ok) return { status: 'error' };
    return await response.json();
  } catch (error) {
    return { status: 'offline', error: error.message };
  }
}

/**
 * Lookup an IP address
 */
export async function lookupIP(ip) {
  try {
    const response = await fetch(`${API_BASE}/lookup/ip/${ip}`);
    if (!response.ok) throw new Error('Lookup failed');
    return await response.json();
  } catch (error) {
    console.error('lookupIP error:', error);
    return null;
  }
}

/**
 * Lookup a domain
 */
export async function lookupDomain(domain) {
  try {
    const response = await fetch(`${API_BASE}/lookup/domain/${domain}`);
    if (!response.ok) throw new Error('Lookup failed');
    return await response.json();
  } catch (error) {
    console.error('lookupDomain error:', error);
    return null;
  }
}

/**
 * Lookup a hash
 */
export async function lookupHash(hash) {
  try {
    const response = await fetch(`${API_BASE}/lookup/hash/${hash}`);
    if (!response.ok) throw new Error('Lookup failed');
    return await response.json();
  } catch (error) {
    console.error('lookupHash error:', error);
    return null;
  }
}

// =============================================================================
// Local Storage - Sources Management
// =============================================================================
const SOURCES_KEY = 'safeops_threat_sources';
const API_KEYS_KEY = 'safeops_api_keys';

/**
 * Get all configured sources
 */
export function getSources() {
  const data = localStorage.getItem(SOURCES_KEY);
  if (!data) {
    // Return default sources
    return getDefaultSources();
  }
  return JSON.parse(data);
}

/**
 * Save sources to localStorage
 */
export function saveSources(sources) {
  localStorage.setItem(SOURCES_KEY, JSON.stringify(sources));
}

/**
 * Add a new source
 */
export function addSource(source) {
  const sources = getSources();
  const newSource = {
    id: Date.now(),
    createdAt: new Date().toISOString(),
    lastFetch: null,
    records: 0,
    status: 'pending',
    ...source
  };
  sources.push(newSource);
  saveSources(sources);
  return newSource;
}

/**
 * Remove a source
 */
export function removeSource(sourceId) {
  const sources = getSources().filter(s => s.id !== sourceId);
  saveSources(sources);
  return sources;
}

/**
 * Update source status
 */
export function updateSource(sourceId, updates) {
  const sources = getSources().map(s =>
    s.id === sourceId ? { ...s, ...updates } : s
  );
  saveSources(sources);
  return sources;
}

/**
 * Get default sources (pre-configured)
 */
function getDefaultSources() {
  return [
    {
      id: 1,
      name: 'Abuse.ch URLhaus',
      category: 'domains',
      type: 'url_csv',
      url: 'https://urlhaus.abuse.ch/downloads/csv/',
      status: 'active',
      records: 12847,
      lastFetch: '2024-01-15T10:30:00Z'
    },
    {
      id: 2,
      name: 'MalwareBazaar Hashes',
      category: 'hashes',
      type: 'url_csv',
      url: 'https://bazaar.abuse.ch/export/csv/recent/',
      status: 'active',
      records: 45231,
      lastFetch: '2024-01-15T09:00:00Z'
    },
    {
      id: 3,
      name: 'Feodo Tracker IPs',
      category: 'ip_blacklist',
      type: 'url_txt',
      url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
      status: 'active',
      records: 8392,
      lastFetch: '2024-01-15T11:00:00Z'
    },
    {
      id: 4,
      name: 'Tor Exit Nodes',
      category: 'ip_anonymization',
      type: 'url_txt',
      url: 'https://check.torproject.org/torbulkexitlist',
      status: 'active',
      records: 1024,
      lastFetch: '2024-01-15T08:00:00Z'
    }
  ];
}

// =============================================================================
// API Keys Management
// =============================================================================

/**
 * Get all API keys
 */
export function getApiKeys() {
  const data = localStorage.getItem(API_KEYS_KEY);
  if (!data) return [];
  return JSON.parse(data);
}

/**
 * Generate new API key
 */
export function generateApiKey(name, permissions = ['read']) {
  const keys = getApiKeys();
  const newKey = {
    id: Date.now(),
    name,
    key: 'sk_' + generateRandomString(32),
    permissions,
    createdAt: new Date().toISOString(),
    lastUsed: null,
    usageCount: 0,
    isActive: true
  };
  keys.push(newKey);
  localStorage.setItem(API_KEYS_KEY, JSON.stringify(keys));
  return newKey;
}

/**
 * Revoke an API key
 */
export function revokeApiKey(keyId) {
  const keys = getApiKeys().map(k =>
    k.id === keyId ? { ...k, isActive: false } : k
  );
  localStorage.setItem(API_KEYS_KEY, JSON.stringify(keys));
  return keys;
}

/**
 * Delete an API key
 */
export function deleteApiKey(keyId) {
  const keys = getApiKeys().filter(k => k.id !== keyId);
  localStorage.setItem(API_KEYS_KEY, JSON.stringify(keys));
  return keys;
}

/**
 * Generate random string for API key
 */
function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export default {
  getDatabaseStats,
  getTableHeaders,
  checkHealth,
  lookupIP,
  lookupDomain,
  lookupHash,
  getSources,
  saveSources,
  addSource,
  removeSource,
  updateSource,
  getApiKeys,
  generateApiKey,
  revokeApiKey,
  deleteApiKey,
  DB_CATEGORIES,
  SOURCE_TYPES
};
