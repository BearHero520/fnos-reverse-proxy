import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/app/reverse-proxy/",
  build: {
    outDir: "build/web",
    emptyOutDir: true,
  },
  optimizeDeps: {
    include: ["react", "react-dom/client"],
  },
  server: {
    port: 5178,
    warmup: {
      clientFiles: ["./src/main.jsx"],
    },
    proxy: {
      "/app/reverse-proxy/api": {
        target: "http://127.0.0.1:5099",
        changeOrigin: true,
      },
    },
  },
  plugins: [react()],
});
