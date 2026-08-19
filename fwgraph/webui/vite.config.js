import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev server proxies every backend prefix to the orchestrator on :8000.
// In production the same prefixes are served by FastAPI itself (one port).
// VITE_PROXY_TARGET 可覆盖 dev 代理目标（默认本机 orchestrator）。
const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://127.0.0.1:8000'
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/jobs': proxyTarget,
      '/firmware': proxyTarget,
      '/graph': proxyTarget,
      '/healthz': proxyTarget,
      '/cbmui': proxyTarget,
      '/api': proxyTarget,
      '/rpc': proxyTarget
    }
  }
})
