import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev server proxies every backend prefix to the orchestrator on :8000.
// In production the same prefixes are served by FastAPI itself (one port).
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/jobs': 'http://127.0.0.1:8000',
      '/firmware': 'http://127.0.0.1:8000',
      '/graph': 'http://127.0.0.1:8000',
      '/healthz': 'http://127.0.0.1:8000',
      '/cbmui': 'http://127.0.0.1:8000',
      '/api': 'http://127.0.0.1:8000',
      '/rpc': 'http://127.0.0.1:8000'
    }
  }
})
