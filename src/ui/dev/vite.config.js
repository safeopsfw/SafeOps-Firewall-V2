import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// SafeOps Developer Dashboard - Port 3001
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    host: true,
    proxy: {
      // Firewall engine REST API (direct to Go engine at :8443)
      '/api/engine': {
        target: 'http://localhost:8443',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/engine/, '/api/v1'),
      },
      // Node backend (threat intel, devices, firewall DB, stepca)
      '/api': {
        target: 'http://localhost:5050',
        changeOrigin: true,
      },
    },
  },
})
