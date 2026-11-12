import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API runs on 127.0.0.1:8000 during development; Vite forwards /api to it
// for both `npm run dev` and `npm run preview`.
const proxy = { "/api": { target: process.env.VS_API_URL || "http://127.0.0.1:8000", changeOrigin: true } };

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 },
  // same port as the Docker dashboard, so every documented start opens http://127.0.0.1:8081
  server: { host: "127.0.0.1", port: 8081, strictPort: true, proxy },
  preview: { host: "127.0.0.1", port: 8081, strictPort: true, proxy },
});
