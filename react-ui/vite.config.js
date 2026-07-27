import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  base: process.env.GITHUB_PAGES_BASE || "/",
  build: {
    // ExcelJS is intentionally lazy-loaded only when a user exports a workbook.
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("/react/") || id.includes("/react-dom/") || id.includes("/scheduler/")) return "vendor-react";
          if (id.includes("/recharts/")) return "vendor-recharts";
          if (id.includes("/d3-") || id.includes("/internmap/") || id.includes("/decimal.js-light/")) return "vendor-d3";
          if (id.includes("/lucide-react/")) return "vendor-icons";
          return undefined;
        },
      },
    },
  },
});
