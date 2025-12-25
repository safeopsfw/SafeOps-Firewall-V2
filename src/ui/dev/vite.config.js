import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// SafeOps Developer Dashboard - Port 3001
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    host: true,
  },
})
