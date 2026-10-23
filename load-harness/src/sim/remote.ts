// Azure Playwright Workspaces: connect cloud browsers with Entra ID, and account for billed minutes.
// Each open remote browser connection is billed per minute, so sessions are tracked from connect
// to close and the run reports the total.

import type { Browser } from "playwright";

export type BrowserEndpoint = "local" | "azure";

export const AZURE_PRICE_PER_MIN = 0.021;

// wss://<region>.api.playwright.microsoft.com/playwrightworkspaces/<workspace-id>/browsers
const SERVICE_URL = /^wss:\/\/[a-z0-9-]+\.api\.playwright\.microsoft\.com\/playwrightworkspaces\/[0-9a-f-]{36}\/browsers$/i;

export function parseEndpoint(v: string | undefined): BrowserEndpoint {
  const e = (v ?? "local").toLowerCase();
  if (e !== "local" && e !== "azure") throw new Error(`--browser-endpoint must be local or azure (got "${v}")`);
  return e;
}

export interface BrowserOpts {
  endpoint: BrowserEndpoint;
  remoteBrowsers: number;
  contextsPerBrowser: number;
}

// Cloud browsers cannot reach localhost, so azure with a local target is refused.
export function resolveBrowserOpts(endpointArg: string | undefined, target: string, remoteBrowsers: number, contextsPerBrowser: number): BrowserOpts {
  const endpoint = parseEndpoint(endpointArg);
  if (endpoint === "azure") {
    if (target === "local") throw new Error("--browser-endpoint azure cannot reach a local stack (cloud browsers see no localhost); use --target staging or local browsers");
    if (!Number.isInteger(remoteBrowsers) || remoteBrowsers < 1) throw new Error("--remote-browsers must be a positive integer");
    if (!Number.isInteger(contextsPerBrowser) || contextsPerBrowser < 1) throw new Error("--contexts-per-browser must be a positive integer");
  }
  return { endpoint, remoteBrowsers, contextsPerBrowser };
}

// The workspace dataplane URI (https://.../playwrightworkspaces/<id>) becomes the browsers endpoint.
export function serviceUrlFromDataplane(dataplane: string): string {
  return dataplane.replace(/^https:\/\//i, "wss://").replace(/\/+$/, "") + "/browsers";
}

export function checkServiceUrl(v: string | undefined): string {
  if (!v) throw new Error("PLAYWRIGHT_SERVICE_URL is not set (wss://<region>.api.playwright.microsoft.com/playwrightworkspaces/<id>/browsers)");
  if (!SERVICE_URL.test(v)) throw new Error(`PLAYWRIGHT_SERVICE_URL does not look like an Azure Playwright browsers endpoint: ${v}`);
  return v;
}

export interface Session {
  index: number;
  connectMs: number | null;
  openedAt: number | null;
  closedAt: number | null;
  error?: string;
}

export interface BrowserUsage {
  endpoint: BrowserEndpoint;
  remoteBrowsers: number;
  contextsPerBrowser: number | null;
  sessions: Session[];
  browserMinutes: number;
  estCostUsd: number;
}

// Sum of open time across sessions, in minutes. A session still open counts up to `now`.
export function browserMinutes(sessions: Session[], now = Date.now()): number {
  let ms = 0;
  for (const s of sessions) if (s.openedAt !== null) ms += Math.max(0, (s.closedAt ?? now) - s.openedAt);
  return Math.round((ms / 60_000) * 1000) / 1000;
}

export function usageOf(endpoint: BrowserEndpoint, sessions: Session[], contextsPerBrowser: number | null, now = Date.now()): BrowserUsage {
  const minutes = endpoint === "azure" ? browserMinutes(sessions, now) : 0;
  return {
    endpoint,
    remoteBrowsers: endpoint === "azure" ? sessions.length : 0,
    contextsPerBrowser,
    sessions,
    browserMinutes: minutes,
    estCostUsd: Math.round(minutes * AZURE_PRICE_PER_MIN * 1000) / 1000,
  };
}

// Connect N cloud browsers. Credential is DefaultAzureCredential (az login locally, managed
// identity on a VM). Tokens stay inside the connect options and are never logged.
export async function connectAzureBrowsers(n: number, log: (s: string) => void): Promise<{ browsers: Browser[]; sessions: Session[] }> {
  const url = checkServiceUrl(process.env.PLAYWRIGHT_SERVICE_URL);
  const { getConnectOptions } = await import("@azure/playwright");
  const { DefaultAzureCredential } = await import("@azure/identity");
  const { chromium } = await import("playwright");
  const connect = await getConnectOptions({ credential: new DefaultAzureCredential(), serviceAuthType: "ENTRA_ID", os: "linux", connectTimeout: 60_000 });
  const host = new URL(url).host;
  log(`connecting ${n} remote browser(s) at ${host}`);
  const sessions: Session[] = Array.from({ length: n }, (_, i) => ({ index: i, connectMs: null, openedAt: null, closedAt: null }));
  const browsers: Browser[] = [];
  const results = await Promise.allSettled(sessions.map(async (s) => {
    const t0 = Date.now();
    const b = await chromium.connect(connect.wsEndpoint, connect.options);
    s.connectMs = Date.now() - t0;
    s.openedAt = Date.now();
    b.on("disconnected", () => { if (s.closedAt === null) s.closedAt = Date.now(); });
    return b;
  }));
  results.forEach((r, i) => {
    if (r.status === "fulfilled") browsers.push(r.value);
    else sessions[i].error = (r.reason as Error)?.message?.split("\n")[0] ?? String(r.reason);
  });
  for (const s of sessions) log(`remote browser ${s.index}: ${s.error ? "FAILED " + s.error : `connected in ${s.connectMs}ms`}`);
  return { browsers, sessions };
}
