import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;

          if (id.includes("@mui/x-data-grid")) return "mui-data-grid";
          if (id.includes("@mui/material") || id.includes("@emotion")) return "mui-core";
          if (id.includes("recharts")) return "charts";
          if (id.includes("@tanstack/react-query")) return "react-query";
        },
      },
    },
  },
});
