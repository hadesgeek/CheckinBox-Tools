import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri 在 dev 模式下需要固定端口，Vite 侧同步这个约定。
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    // 注意：1420/1421/1425/1500 在本机被 Windows 保留端口段占用（EACCES），
    // 所以用 5173（实测可绑定）。换机器若冲突，改这里即可。
    port: 5173,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 5174 } : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
