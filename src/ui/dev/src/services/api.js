import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080/api';

// Check if we're in database mode (default to database mode)
export const getDataSource = () => localStorage.getItem('safeops_data_source') || 'database';
export const isDbMode = () => getDataSource() !== 'dummy';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle errors
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    // Handle 401 - redirect to login
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }

    const message = error.response?.data?.message || error.message || 'An error occurred';
    return Promise.reject(new Error(message));
  }
);

// =============================================================================
// DEMO DATA - Used when in demo mode
// =============================================================================

export const DEMO_DATA = {
  dashboard: {
    stats: {
      totalThreatsBlocked: 0,
      activeFeeds: 0,
      systemHealth: 100,
      openAlerts: 0
    }
  },

  threatIntel: {
    stats: {
      totalIPs: 0,
      totalDomains: 0,
      totalHashes: 0,
      activeThreats: 0
    },
    recentThreats: []
  },

  feeds: [],

  users: [
    { id: 1, email: 'admin@safeops.com', name: 'SafeOps Admin', role: 'superadmin', isActive: true },
    { id: 2, email: 'analyst@safeops.com', name: 'Security Analyst', role: 'analyst', isActive: true },
  ]
};

// =============================================================================
// DATA SERVICE - Fetches from API or returns demo data
// =============================================================================

export const dataService = {
  // Dashboard stats
  async getDashboardStats() {
    if (!isDbMode()) {
      return DEMO_DATA.dashboard.stats;
    }
    try {
      return await api.get('/dashboard/stats');
    } catch (error) {
      console.warn('API unavailable, falling back to demo data:', error.message);
      return DEMO_DATA.dashboard.stats;
    }
  },

  // Threat Intel stats
  async getThreatIntelStats() {
    if (!isDbMode()) {
      return DEMO_DATA.threatIntel.stats;
    }
    try {
      return await api.get('/threat-intel/stats');
    } catch (error) {
      console.warn('API unavailable, falling back to demo data:', error.message);
      return DEMO_DATA.threatIntel.stats;
    }
  },

  // Threat Intel recent threats
  async getRecentThreats() {
    if (!isDbMode()) {
      return DEMO_DATA.threatIntel.recentThreats;
    }
    try {
      return await api.get('/threat-intel/recent');
    } catch (error) {
      console.warn('API unavailable, falling back to demo data:', error.message);
      return DEMO_DATA.threatIntel.recentThreats;
    }
  },

  // Feeds
  async getFeeds() {
    if (!isDbMode()) {
      return DEMO_DATA.feeds;
    }
    try {
      return await api.get('/feeds');
    } catch (error) {
      console.warn('API unavailable, falling back to demo data:', error.message);
      return DEMO_DATA.feeds;
    }
  },

  // Users
  async getUsers() {
    if (!isDbMode()) {
      return DEMO_DATA.users;
    }
    try {
      return await api.get('/users');
    } catch (error) {
      console.warn('API unavailable, falling back to demo data:', error.message);
      return DEMO_DATA.users;
    }
  },

  // IOC comparison
  async compareIOCs(iocs, databases) {
    if (!isDbMode()) {
      // Return mock comparison results
      return {
        items: iocs.split('\n').filter(Boolean).map((ioc, idx) => ({
          ioc: ioc.trim(),
          type: ioc.includes('.') ? 'domain' : 'ip',
          status: idx % 3 === 0 ? 'malicious' : idx % 3 === 1 ? 'clean' : 'unknown',
          score: idx % 3 === 0 ? 85 + Math.random() * 15 : 0,
          sources: idx % 3 === 0 ? ['IP Blacklist'] : []
        })),
        summary: {
          total: iocs.split('\n').filter(Boolean).length,
          malicious: Math.floor(iocs.split('\n').filter(Boolean).length / 3),
          clean: Math.floor(iocs.split('\n').filter(Boolean).length / 3),
          unknown: Math.ceil(iocs.split('\n').filter(Boolean).length / 3)
        }
      };
    }
    try {
      return await api.post('/ioc/compare', { iocs, databases });
    } catch (error) {
      console.warn('API unavailable:', error.message);
      throw error;
    }
  }
};

export default api;
