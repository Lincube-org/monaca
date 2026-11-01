import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";
import { defineConfig, loadEnv } from "vite";

/**
 * Contract: docs/contracts/m0.md §2.1. The console is never the public origin — every protocol
 * call goes through the gateway (8080) so the browser only ever sees one origin, and the BFF
 * cookies stay first-party. /internal/ is deliberately absent: it is never proxied (§9).
 *
 * `/t/` keeps its trailing slash on purpose: Vite matches these as plain string prefixes, so a
 * bare `/t` would also swallow console routes such as `/tenant-roles`.
 */
const PROXIED_PREFIXES = ["/bff", "/oauth2", "/t/", "/.well-known", "/v1", "/interaction", "/mcp"];

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const gateway = env.VITE_MONACA_GATEWAY_URL || "http://localhost:8080";
  const port = Number(env.MONACA_CONSOLE_PORT || 5173);

  const proxy = Object.fromEntries(
    PROXIED_PREFIXES.map((prefix) => [
      prefix,
      { target: gateway, changeOrigin: true, ws: prefix === "/mcp" },
    ]),
  );

  return {
    plugins: [vue(), tailwindcss()],
    resolve: {
      alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
    },
    server: { port, strictPort: true, proxy },
    preview: { port, strictPort: true },
    build: { target: "es2022", sourcemap: true },
  };
});
