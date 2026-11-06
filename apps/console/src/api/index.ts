import { httpApi } from "./client";
import type { MonacaApi } from "./contract";
import { mockApi } from "./mock";

/**
 * Which implementation the pages get.
 *
 * The console is an operations tool now, so the default is the **real** BFF client. Setting
 * `VITE_USE_MOCKS=true` keeps the fixture backend for UI work without a server; nothing else in
 * the app changes. An unset variable must not silently show invented data to an operator.
 */
export const USE_MOCKS: boolean =
  (import.meta.env["VITE_USE_MOCKS"] ?? "false").toString().toLowerCase() === "true";

export const api: MonacaApi = USE_MOCKS ? mockApi : httpApi;

/** The gateway origin the Vite dev proxy forwards to, shown in Settings → Diagnostics. */
export const GATEWAY_URL: string = (import.meta.env["VITE_MONACA_GATEWAY_URL"] ?? "http://localhost:8080").toString();
