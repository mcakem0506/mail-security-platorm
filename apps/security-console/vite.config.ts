import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, target: "es2022" },
  server: {
    port: 5173,
    // The API is same-origin behind nginx in production; in development it is proxied so the
    // session cookie keeps working without relaxing SameSite.
    proxy: { "/api": { target: "http://localhost:8000", changeOrigin: true },
             "/health": { target: "http://localhost:8000", changeOrigin: true } },
  },
});
