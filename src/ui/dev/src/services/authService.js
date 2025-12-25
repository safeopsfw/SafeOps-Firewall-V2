import api from './api';

// For development: use mock auth when backend is not available
const USE_MOCK_AUTH = true;

// Mock user for development
const MOCK_USER = {
  id: 1,
  email: 'admin@safeops.com',
  name: 'SafeOps Admin',
  role: 'superadmin',
  avatar: null,
};

// Mock credentials
const MOCK_CREDENTIALS = {
  email: 'admin@safeops.com',
  password: 'safeops1234',
};

export const authService = {
  /**
   * Login with email and password
   */
  login: async (email, password) => {
    if (USE_MOCK_AUTH) {
      // Simulate network delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      if (email === MOCK_CREDENTIALS.email && password === MOCK_CREDENTIALS.password) {
        return {
          token: 'mock-jwt-token-' + Date.now(),
          user: MOCK_USER,
        };
      }
      throw new Error('Invalid email or password');
    }
    
    return api.post('/auth/login', { email, password });
  },

  /**
   * Get current user info
   */
  getMe: async () => {
    if (USE_MOCK_AUTH) {
      const token = localStorage.getItem('token');
      if (token && token.startsWith('mock-jwt-token-')) {
        return MOCK_USER;
      }
      throw new Error('Not authenticated');
    }
    
    return api.get('/auth/me');
  },

  /**
   * Logout
   */
  logout: async () => {
    if (USE_MOCK_AUTH) {
      return { success: true };
    }
    
    return api.post('/auth/logout');
  },
};
