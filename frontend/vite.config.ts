import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard is served by nginx, which proxies /api to the API service, so
// the browser only ever talks to one origin. In dev, Vite proxies to the
// loopback forwarder instead.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: true } },
  },
  build: { outDir: "dist", sourcemap: false },
});
