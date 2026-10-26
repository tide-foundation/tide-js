// Server-side evidence per step window, all read-only: Container Apps metrics, Postgres metrics,
// Log Analytics (ORK signatures, execution times, restarts), Prometheus, and the Stripe stub.
// Every collector is best effort: a failure becomes a "missing" note, never an exception.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { az, azToken, redact, redactDeep } from "./az.js";

const run = promisify(execFile);

export interface StepWindow { step: number; kind: string; startMs: number; endMs: number }

export interface AppInfo {
  name: string;
  id: string;
  image: string | null;
  revision: string | null;
  cpu: number | null;
  memoryGi: number | null;
  minReplicas: number | null;
  maxReplicas: number | null;
  env: string | null;
  stripeApiBase: string | null; // host only, from the payer's launch args
  role: string;
}

export interface Inventory {
  at: string;
  apps: AppInfo[];
  pg: { id: string; name: string; sku: string | null; tier: string | null; maxConnections: number | null } | null;
  workspaces: Array<{ env: string; customerId: string }>;
  harnessCommit: string | null;
  missing: string[];
}

export interface CollectConfig {
  rg: string;
  appFilter: RegExp;
  pgName: string;
  promBase: string;
  promJob: string;
  stubUrl: string | null;
}

export const STAGING_COLLECT: CollectConfig = {
  rg: "Tide-Staging",
  appFilter: /^(tidecloak-staging|sork\d+|stripe-stub)$/,
  pgName: "dauthme-staging",
  promBase: "https://ork-prometheus-adehanchbsf2ctfn.australiaeast.prometheus.monitor.azure.com/api/v1",
  promJob: "sork-env/ork",
  stubUrl: "https://stripe-stub.happybeach-4249617c.australiaeast.azurecontainerapps.io",
};

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");

function memGi(s: unknown): number | null {
  if (typeof s !== "string") return null;
  const m = /^([\d.]+)\s*Gi$/i.exec(s);
  return m ? parseFloat(m[1]) : null;
}

// ---------------------------------------------------------------------------
// Inventory (run metadata at start and end)
// ---------------------------------------------------------------------------

export async function inventory(cfg: CollectConfig, harnessDir: string): Promise<Inventory> {
  const missing: string[] = [];
  const inv: Inventory = { at: new Date().toISOString(), apps: [], pg: null, workspaces: [], harnessCommit: null, missing };
  try {
    const { stdout } = await run("git", ["-C", harnessDir, "rev-parse", "--short", "HEAD"]);
    const dirty = (await run("git", ["-C", harnessDir, "status", "--porcelain", "--untracked-files=no"])).stdout.trim() ? "+dirty" : "";
    inv.harnessCommit = stdout.trim() + dirty;
  } catch { missing.push("harness git commit"); }
  try {
    type Raw = { name: string; id: string; properties: { latestRevisionName?: string; managedEnvironmentId?: string; template?: { containers?: Array<{ image?: string; args?: string[]; command?: string[]; resources?: { cpu?: number; memory?: string } }>; scale?: { minReplicas?: number; maxReplicas?: number } } } };
    const raw = await az<Raw[]>(["containerapp", "list", "-g", cfg.rg]);
    for (const a of raw.filter((x) => cfg.appFilter.test(x.name))) {
      const c = a.properties.template?.containers?.[0];
      // Only the stripe-api-base host is read from the args; the rest (keys) is never kept.
      const args = [...(c?.command ?? []), ...(c?.args ?? [])].join(" ");
      const m = /(?:^|\s)(?:--)?stripe-api-base[= ]+(https?:\/\/[^\s"']+)/.exec(args);
      const image = c?.image ?? null;
      inv.apps.push({
        name: a.name, id: a.id, image, revision: a.properties.latestRevisionName ?? null,
        cpu: c?.resources?.cpu ?? null, memoryGi: memGi(c?.resources?.memory),
        minReplicas: a.properties.template?.scale?.minReplicas ?? null, maxReplicas: a.properties.template?.scale?.maxReplicas ?? null,
        env: a.properties.managedEnvironmentId?.split("/").pop() ?? null,
        stripeApiBase: m ? new URL(m[1]).host : null,
        role: /tidecloak/.test(a.name) ? "tidecloak" : /stripe-stub/.test(a.name) ? "stripe-stub" : /master/.test(image ?? "") ? "master ORK" : m ? "ORK + payer" : "ORK",
      });
    }
  } catch (e) { missing.push(`container apps: ${(e as Error).message}`); }
  try {
    const envs = await az<Array<{ name: string; properties: { appLogsConfiguration?: { logAnalyticsConfiguration?: { customerId?: string } } } }>>(["containerapp", "env", "list", "-g", cfg.rg]);
    const used = new Set(inv.apps.map((a) => a.env));
    for (const e of envs) {
      const id = e.properties.appLogsConfiguration?.logAnalyticsConfiguration?.customerId;
      if (id && used.has(e.name)) inv.workspaces.push({ env: e.name, customerId: id });
    }
  } catch (e) { missing.push(`log analytics workspaces: ${(e as Error).message}`); }
  try {
    const pg = await az<{ id: string; name: string; sku?: { name?: string; tier?: string } }>(["postgres", "flexible-server", "show", "-g", cfg.rg, "-n", cfg.pgName]);
    let maxConnections: number | null = null;
    try {
      const p = await az<{ value?: string }>(["postgres", "flexible-server", "parameter", "show", "-g", cfg.rg, "--server-name", cfg.pgName, "--name", "max_connections"]);
      maxConnections = p.value ? parseInt(p.value, 10) : null;
    } catch (e) { missing.push(`postgres max_connections: ${(e as Error).message}`); }
    inv.pg = { id: pg.id, name: pg.name, sku: pg.sku?.name ?? null, tier: pg.sku?.tier ?? null, maxConnections };
  } catch (e) { missing.push(`postgres: ${(e as Error).message}`); }
  return inv;
}

// ---------------------------------------------------------------------------
// Azure Monitor metrics
// ---------------------------------------------------------------------------

type Point = { timeStamp: string; average?: number | null; maximum?: number | null; total?: number | null };
type MetricsRaw = { value: Array<{ name: { value: string }; timeseries: Array<{ data: Point[] }> }> };

function agg(points: Point[], f: "average" | "maximum" | "total"): number[] {
  return points.map((p) => p[f]).filter((v): v is number => typeof v === "number");
}
const avgOf = (xs: number[]) => (xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10 : null);
const maxOf = (xs: number[]) => (xs.length ? Math.round(Math.max(...xs) * 10) / 10 : null);
const sumOf = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) : null);

async function metrics(resourceId: string, names: string[], w: StepWindow): Promise<Record<string, Point[]>> {
  // Metrics land on minute boundaries; widen to whole minutes.
  const start = Math.floor(w.startMs / 60_000) * 60_000;
  const end = Math.ceil(w.endMs / 60_000) * 60_000;
  const raw = await az<MetricsRaw>(["monitor", "metrics", "list", "--resource", resourceId, "--metrics", ...names,
    "--start-time", iso(start), "--end-time", iso(end), "--interval", "PT1M", "--aggregation", "Average", "Maximum", "Total"]);
  const out: Record<string, Point[]> = {};
  for (const v of raw.value ?? []) out[v.name.value] = v.timeseries?.[0]?.data ?? [];
  return out;
}

export interface AppMetrics {
  cpuPctAvg: number | null; cpuPctMax: number | null;
  memPctAvg: number | null; memPctMax: number | null;
  cpuCoresMax: number | null; limitCores: number | null;
  replicasMax: number | null; restarts: number | null;
  requests: number | null; respMsAvg: number | null; respMsMax: number | null;
}

export async function appMetrics(app: AppInfo, w: StepWindow): Promise<AppMetrics> {
  const m = await metrics(app.id, ["CpuPercentage", "MemoryPercentage", "UsageNanoCores", "Replicas", "RestartCount", "Requests", "ResponseTime"], w);
  const cores = agg(m.UsageNanoCores ?? [], "maximum").map((n) => n / 1e9);
  const coresMax = cores.length ? Math.max(...cores) : null;
  let cpuPctMax = maxOf(agg(m.CpuPercentage ?? [], "maximum"));
  let cpuPctAvg = avgOf(agg(m.CpuPercentage ?? [], "average"));
  // Fall back to nano-cores over the configured limit when CpuPercentage is absent.
  if (cpuPctMax === null && coresMax !== null && app.cpu) {
    cpuPctMax = Math.round((coresMax / app.cpu) * 1000) / 10;
    const a = avgOf(agg(m.UsageNanoCores ?? [], "average").map((n) => n / 1e9));
    cpuPctAvg = a !== null ? Math.round((a / app.cpu) * 1000) / 10 : null;
  }
  return {
    cpuPctAvg, cpuPctMax,
    memPctAvg: avgOf(agg(m.MemoryPercentage ?? [], "average")), memPctMax: maxOf(agg(m.MemoryPercentage ?? [], "maximum")),
    cpuCoresMax: coresMax !== null ? Math.round(coresMax * 1000) / 1000 : null, limitCores: app.cpu,
    replicasMax: maxOf(agg(m.Replicas ?? [], "maximum")),
    // RestartCount is a running total per replica, so report the increase across the window.
    restarts: (() => { const xs = agg(m.RestartCount ?? [], "maximum"); return xs.length ? Math.max(...xs) - Math.min(...xs) : null; })(),
    requests: sumOf(agg(m.Requests ?? [], "total")),
    respMsAvg: avgOf(agg(m.ResponseTime ?? [], "average")), respMsMax: maxOf(agg(m.ResponseTime ?? [], "maximum")),
  };
}

export interface PgMetrics {
  cpuPctAvg: number | null; cpuPctMax: number | null;
  memPctMax: number | null;
  activeConnMax: number | null; maxConnections: number | null; connPctMax: number | null;
  iopsPctMax: number | null;
  cpuCreditsMin: number | null;
  connectionsFailed: number | null;
}

export async function pgMetrics(pg: NonNullable<Inventory["pg"]>, w: StepWindow, missing: string[]): Promise<PgMetrics> {
  // Burstable servers reject mixing grains, so ask one metric at a time.
  const one = async (name: string): Promise<Point[]> => {
    try { return (await metrics(pg.id, [name], w))[name] ?? []; } catch (e) { missing.push(`postgres ${name}: ${(e as Error).message}`); return []; }
  };
  const [cpu, mem, conn, iops, credits, failed] = await Promise.all(["cpu_percent", "memory_percent", "active_connections", "disk_iops_consumed_percentage", "cpu_credits_remaining", "connections_failed"].map(one));
  const activeConnMax = maxOf(agg(conn, "maximum"));
  return {
    cpuPctAvg: avgOf(agg(cpu, "average")), cpuPctMax: maxOf(agg(cpu, "maximum")),
    memPctMax: maxOf(agg(mem, "maximum")),
    activeConnMax, maxConnections: pg.maxConnections,
    connPctMax: activeConnMax !== null && pg.maxConnections ? Math.round((activeConnMax / pg.maxConnections) * 1000) / 10 : null,
    iopsPctMax: maxOf(agg(iops, "maximum")),
    cpuCreditsMin: (() => { const xs = agg(credits, "average"); return xs.length ? Math.min(...xs) : null; })(),
    connectionsFailed: sumOf(agg(failed, "total")),
  };
}

// ---------------------------------------------------------------------------
// Log Analytics
// ---------------------------------------------------------------------------

export const LOG_SIGNATURES: Record<string, string> = {
  sqlite_locked: `Log_s contains "SQLite Error 5" or Log_s contains "database is locked"`,
  sqlite_malformed: `Log_s contains "SQLite Error 11" or Log_s contains "malformed"`,
  uid_missing: `Log_s contains "could not find uid"`,
  stmt_timeout: `Log_s contains "statement timeout" or Log_s contains "57014"`,
  // Log_s is JSON, so the quotes around the constraint name arrive as \u0022; match the name alone.
  uid_duplicate: `Log_s contains "IX_UIDs_Id"`,
  pg_unique_violation: `Log_s contains "23505: " or Log_s contains "duplicate key value violates unique constraint"`,
  // Master logs this when a SubmitUser insert really failed; without it the duplicates above were swallowed.
  add_user_failed: `Log_s contains "Failed to add user"`,
  // TideCloak drops an over-long refresh_token (4000 chars), so the refresh silently fails.
  oidc_param_too_long: `Log_s contains "OIDC parameter" and Log_s contains "longer" and Log_s contains "than allowed"`,
  // Only the real error or an HTTP status context: ORK timing lines carry bare numbers like "431 ms".
  header_too_large: `Log_s contains "Request Header Fields Too Large" or Log_s contains "status 431" or Log_s contains "HTTP 431" or Log_s contains " 431 Request"`,
  licence_active_cap: `Log_s contains "exceeded its total concurrent active users"`,
  vendor_already_created: `Log_s contains "VENDOR_ALREADY_CREATED"`,
  seat_cap: `Log_s contains "exceeded its total user count"`,
  vendor_keygen_failed: `Log_s contains "VENDOR_KEYGEN_FAILED"`,
  npgsql_timeout: `Log_s contains "Npgsql" and Log_s contains "imeout"`,
  unhandled_exception: `Log_s contains "Unhandled exception"`,
  error_lines: `Log_s contains "\\"log.level\\":\\"Error\\"" or Log_s contains " ERROR "`,
};

function kqlWindow(w: StepWindow): string {
  // TimeGenerated is the ingestion batch time; the event time is the JSON @timestamp when present.
  return `| where TimeGenerated between (datetime(${iso(w.startMs - 60_000)}) .. datetime(${iso(w.endMs + 300_000)}))
| extend ts = coalesce(todatetime(extract('"@timestamp":"([^"]+)"', 1, Log_s)), TimeGenerated)
| where ts between (datetime(${iso(w.startMs)}) .. datetime(${iso(w.endMs)}))`;
}

async function kql<T>(workspace: string, query: string): Promise<T[]> {
  const rows = await az<Array<T & { TableName?: string }>>(["monitor", "log-analytics", "query", "-w", workspace, "--analytics-query", query], 180_000);
  return rows.map((r) => { const x = { ...r }; delete (x as { TableName?: string }).TableName; return x; });
}

// Top distinct error messages per app, short and redacted. Durations are blanked so repeats group.
export function errorSamples(rows: Array<{ app: string; msg: string; n: number }>, top = 3): Record<string, Array<{ msg: string; n: number }>> {
  const by: Record<string, Map<string, number>> = {};
  for (const r of rows) {
    const lines = String(r.msg ?? "").split("\n").map((l) => l.trim()).filter(Boolean);
    // The innermost exception ("---> ...") says more than the EF wrapper line.
    const inner = lines.filter((l) => l.startsWith("--->")).pop();
    let line = (inner ?? lines.find((l) => /Exception/.test(l)) ?? lines[0] ?? "").replace(/^--->\s*/, "");
    // EF command failures: the SQL says which table, the parameter list says nothing.
    if (/^Failed executing DbCommand/.test(line) && lines[1]) line = `Failed executing DbCommand: ${lines[1]}`;
    // TideCloak lines lead with a timestamp and thread; drop them and shorten the logger so repeats group.
    line = line.replace(/^\d{4}-\d\d-\d\d[ T][\d:.,]+Z?\s*/, "").replace(/\s\((executor-thread|Timer|vert\.x[\w-]*)-?\d*\)/, "").replace(/\[(?:[\w$]+\.)+([\w$]+)\]/, "[$1]");
    const msg = redact(line)
      .replace(/\b(Host|Server|User ?Id|Username|Uid|Database|Data Source)\s*=\s*[^;\s]+/gi, "$1=[REDACTED]")
      .replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]")
      .replace(/[A-Za-z0-9+/_=-]{32,}/g, "[REDACTED]")
      .replace(/\(\d+ms\)/g, "(Nms)")
      .replace(/longer \(\d+\)/g, "longer (N)")
      .replace(/\s+/g, " ")
      .slice(0, 160);
    if (!msg) continue;
    const m = (by[r.app] ??= new Map());
    m.set(msg, (m.get(msg) ?? 0) + Number(r.n));
  }
  const out: Record<string, Array<{ msg: string; n: number }>> = {};
  for (const [app, m] of Object.entries(by)) out[app] = [...m].map(([msg, n]) => ({ msg, n })).sort((a, b) => b.n - a.n || Number(/Exception/.test(b.msg)) - Number(/Exception/.test(a.msg))).slice(0, top);
  return out;
}

export interface ExecRow { app: string; op: string; n: number; p50: number; p95: number; max: number }
export interface LogsResult {
  signatures: Record<string, Record<string, number>>;
  exec: ExecRow[];
  system: Array<{ app: string; reason: string; n: number; exitCodes: string }>;
  errorSamples?: Record<string, Array<{ msg: string; n: number }>>; // absent in older runs
  firstSeen?: Record<string, Record<string, string>>;                 // app -> signature -> first event time
}

export async function logs(inv: Inventory, cfg: CollectConfig, w: StepWindow, missing: string[]): Promise<LogsResult> {
  const out: LogsResult = { signatures: {}, exec: [], system: [], errorSamples: {}, firstSeen: {} };
  const names = inv.apps.map((a) => a.name);
  const appFilter = `| where ContainerAppName_s in (${names.map((n) => `"${n}"`).join(",")})`;
  const sigCols = Object.entries(LOG_SIGNATURES).map(([k, cond]) => `${k}=countif(${cond}), ${k}_t=minif(ts, ${cond})`).join(", ");
  for (const ws of inv.workspaces) {
    try {
      const rows = await kql<Record<string, string | number>>(ws.customerId, `ContainerAppConsoleLogs_CL ${appFilter}
${kqlWindow(w)}
| summarize ${sigCols} by app=ContainerAppName_s`);
      for (const r of rows) {
        const app = String(r.app);
        out.signatures[app] = {};
        out.firstSeen![app] = {};
        for (const k of Object.keys(LOG_SIGNATURES)) {
          out.signatures[app][k] = Number(r[k] ?? 0);
          if (out.signatures[app][k] && r[`${k}_t`]) out.firstSeen![app][k] = String(r[`${k}_t`]);
        }
      }
    } catch (e) { missing.push(`log signatures (${ws.env}): ${(e as Error).message}`); }
    try {
      const rows = await kql<{ app: string; msg: string; n: number }>(ws.customerId, `ContainerAppConsoleLogs_CL ${appFilter}
| where ${LOG_SIGNATURES.error_lines} or ${LOG_SIGNATURES.oidc_param_too_long} or ${LOG_SIGNATURES.header_too_large} or ${LOG_SIGNATURES.licence_active_cap}
${kqlWindow(w)}
| extend m = tostring(parse_json(Log_s).message)
| extend msg = replace_regex(substring(iff(isempty(m), Log_s, m), 0, 2000), @"\\(\\d+ms\\)", "(Nms)")
| summarize n=count() by app=ContainerAppName_s, msg
| order by n desc
| take 200`);
      Object.assign(out.errorSamples!, errorSamples(rows));
    } catch (e) { missing.push(`error samples (${ws.env}): ${(e as Error).message}`); }
    try {
      const rows = await kql<{ app: string; op: string; n: number; p50: number; p95: number; mx: number }>(ws.customerId, `ContainerAppConsoleLogs_CL ${appFilter}
| where Log_s contains "Execution time for"
${kqlWindow(w)}
| extend op = extract("Execution time for ([A-Za-z0-9_.]+): ", 1, Log_s), ms = toint(extract("Execution time for [A-Za-z0-9_.]+: ([0-9]+) ms", 1, Log_s))
| where isnotempty(op)
| summarize n=count(), p50=percentile(ms, 50), p95=percentile(ms, 95), mx=max(ms) by app=ContainerAppName_s, op`);
      for (const r of rows) out.exec.push({ app: r.app, op: r.op, n: Number(r.n), p50: Number(r.p50), p95: Number(r.p95), max: Number(r.mx) });
    } catch (e) { missing.push(`ORK execution times (${ws.env}): ${(e as Error).message}`); }
    try {
      const rows = await kql<{ app: string; reason: string; n: number; codes: string }>(ws.customerId, `ContainerAppSystemLogs_CL ${appFilter}
| where TimeGenerated between (datetime(${iso(w.startMs)}) .. datetime(${iso(w.endMs + 60_000)}))
| where Reason_s in~ ("ContainerTerminated", "BackOff", "ContainerCrashing", "ProbeFailed", "ContainerStarted", "ContainerCreated", "RevisionUpdate", "ContainerAppUpdate", "AssigningReplica") or Log_s contains "exit code"
| extend code = extract("exit code[^0-9]*([0-9]+)", 1, Log_s)
| summarize n=count(), codes=strcat_array(make_set(code, 5), ",") by app=ContainerAppName_s, reason=Reason_s`);
      for (const r of rows) out.system.push({ app: r.app, reason: r.reason, n: Number(r.n), exitCodes: String(r.codes ?? "") });
    } catch (e) { missing.push(`container system logs (${ws.env}): ${(e as Error).message}`); }
  }
  void cfg;
  return out;
}

// ---------------------------------------------------------------------------
// Prometheus (optional)
// ---------------------------------------------------------------------------

export interface PromResult {
  outbound: Array<{ target: string; status: string; count: number }>;
  outboundP95: Record<string, number>;
  outboundAvg: Record<string, number>;
  protocolP95: Record<string, number>;
  semaphoreWaitP95: number | null;
  semaphoreWaitersMax: number | null;
  throttleRejections: number | null;
  threadPoolQueueMax: number | null;
}

export async function prom(cfg: CollectConfig, w: StepWindow, missing: string[], tokenCache: { t?: string }): Promise<PromResult | null> {
  try {
    tokenCache.t ??= await azToken("https://prometheus.monitor.azure.com");
  } catch (e) {
    missing.push(`prometheus token: ${(e as Error).message}`);
    return null;
  }
  // Scrapes are about a minute apart, so short windows are widened to 5 minutes ending at the step end.
  const win = `${Math.max(300, Math.round((w.endMs - w.startMs) / 1000))}s`;
  const at = (w.endMs / 1000).toFixed(0);
  const J = `job="${cfg.promJob}"`;
  const q = async (expr: string): Promise<Array<{ metric: Record<string, string>; value: [number, string] }>> => {
    const r = await fetch(`${cfg.promBase}/query?query=${encodeURIComponent(expr)}&time=${at}`, { headers: { Authorization: `Bearer ${tokenCache.t}` } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = (await r.json()) as { data?: { result?: Array<{ metric: Record<string, string>; value: [number, string] }> } };
    return j.data?.result ?? [];
  };
  const num = (v: string) => { const n = parseFloat(v); return Number.isFinite(n) ? Math.round(n * 1000) / 1000 : 0; };
  const byLabel = (rows: Array<{ metric: Record<string, string>; value: [number, string] }>, label: string, scale = 1) => {
    const o: Record<string, number> = {};
    for (const r of rows) o[r.metric[label] ?? "?"] = Math.round(num(r.value[1]) * scale * 10) / 10;
    return o;
  };
  try {
    const [outbound, p95, sum, cnt, proto, semP95, semMax, thr, tpq] = await Promise.all([
      q(`sum by (target, status) (increase(tide_ork_outbound_duration_seconds_count{${J}}[${win}]))`),
      q(`histogram_quantile(0.95, sum by (le, target) (increase(tide_ork_outbound_duration_seconds_bucket{${J}}[${win}])))`),
      q(`sum by (target) (increase(tide_ork_outbound_duration_seconds_sum{${J}}[${win}]))`),
      q(`sum by (target) (increase(tide_ork_outbound_duration_seconds_count{${J}}[${win}]))`),
      q(`histogram_quantile(0.95, sum by (le, op) (increase(tide_ork_protocol_duration_seconds_bucket{${J}}[${win}])))`),
      q(`histogram_quantile(0.95, sum by (le) (increase(tide_ork_sync_semaphore_wait_seconds_bucket{${J}}[${win}])))`),
      q(`max(max_over_time(tide_ork_sync_semaphore_waiters_callers{${J}}[${win}]))`),
      q(`sum(increase(tide_ork_throttle_rejections_total{${J}}[${win}]))`),
      q(`max(max_over_time(process_runtime_dotnet_thread_pool_queue_length{${J}}[${win}]))`),
    ]);
    const sums = byLabel(sum, "target");
    const cnts = byLabel(cnt, "target");
    const outboundAvg: Record<string, number> = {};
    for (const k of Object.keys(sums)) if (cnts[k]) outboundAvg[k] = Math.round((sums[k] / cnts[k]) * 1000 * 10) / 10;
    const first = (rows: typeof semMax) => (rows.length ? num(rows[0].value[1]) : null);
    return {
      outbound: outbound.map((r) => ({ target: r.metric.target ?? "?", status: r.metric.status ?? "?", count: Math.round(num(r.value[1])) })),
      outboundP95: byLabel(p95, "target", 1000),
      outboundAvg,
      protocolP95: byLabel(proto, "op", 1000),
      semaphoreWaitP95: semP95.length ? Math.round(num(semP95[0].value[1]) * 1000 * 10) / 10 : null,
      semaphoreWaitersMax: first(semMax),
      throttleRejections: first(thr),
      threadPoolQueueMax: first(tpq),
    };
  } catch (e) {
    missing.push(`prometheus: ${(e as Error).message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Stripe stub
// ---------------------------------------------------------------------------

export interface StubStats { decisions: Record<string, number>; byRoute: Record<string, number>; objects?: Record<string, number> }

export async function stubSnapshot(url: string): Promise<StubStats> {
  const r = await fetch(`${url.replace(/\/+$/, "")}/__stub/stats`, { signal: AbortSignal.timeout(10_000) });
  if (!r.ok) throw new Error(`stub stats HTTP ${r.status}`);
  return redactDeep((await r.json()) as StubStats);
}

export interface StubDelta {
  decisions: Record<string, number>;
  byRoute: Record<string, number>;
  unexpectedPassthrough: Record<string, number>;
  ok: boolean;
}

// Load-test Stripe traffic must be stubbed; only the price catalogue may pass through.
export function stubDelta(start: StubStats, end: StubStats): StubDelta {
  const d = (a: Record<string, number>, b: Record<string, number>) => {
    const o: Record<string, number> = {};
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const v = (b[k] ?? 0) - (a[k] ?? 0);
      if (v) o[k] = v;
    }
    return o;
  };
  const byRoute = d(start.byRoute ?? {}, end.byRoute ?? {});
  // The stub always stubs or refuses a load-test object id, so any GET that passed through carries a
  // non-load-test id (another staging realm) and is fine. A load-test leak would show up only as a
  // CREATE passing through (a customer/subscription the stub failed to recognise) or a refusal.
  const unexpected: Record<string, number> = {};
  for (const [k, v] of Object.entries(byRoute)) {
    if (/^passthrough POST \/v1\/(customers|subscriptions)\b/.test(k)) unexpected[k] = v;
    if (k.startsWith("refused ")) unexpected[k] = v;
  }
  return { decisions: d(start.decisions ?? {}, end.decisions ?? {}), byRoute, unexpectedPassthrough: unexpected, ok: Object.keys(unexpected).length === 0 };
}

// ---------------------------------------------------------------------------
// One step
// ---------------------------------------------------------------------------

export interface StepServer {
  step: number;
  kind: string;
  window: { start: string; end: string };
  apps: Record<string, AppMetrics>;
  pg: PgMetrics | null;
  logs: LogsResult | null;
  prom: PromResult | null;
  stub: StubDelta | null;
  missing: string[];
}

export async function collectStep(inv: Inventory, cfg: CollectConfig, w: StepWindow, stubSnaps: { start?: StubStats; end?: StubStats } | null, promToken: { t?: string }): Promise<StepServer> {
  const missing: string[] = [...inv.missing.map((m) => `inventory: ${m}`)];
  const apps: Record<string, AppMetrics> = {};
  await Promise.all(inv.apps.map(async (a) => {
    try { apps[a.name] = await appMetrics(a, w); } catch (e) { missing.push(`metrics ${a.name}: ${(e as Error).message}`); }
  }));
  const pg = inv.pg ? await pgMetrics(inv.pg, w, missing).catch((e) => { missing.push(`postgres: ${(e as Error).message}`); return null; }) : null;
  const lg = inv.workspaces.length ? await logs(inv, cfg, w, missing) : (missing.push("log analytics: no workspace found"), null);
  const pr = await prom(cfg, w, missing, promToken);
  let stub: StubDelta | null = null;
  if (stubSnaps?.start && stubSnaps?.end) stub = stubDelta(stubSnaps.start, stubSnaps.end);
  else if (cfg.stubUrl) missing.push("stripe stub: no start/end snapshot for this step");
  return { step: w.step, kind: w.kind, window: { start: iso(w.startMs), end: iso(w.endMs) }, apps, pg, logs: lg, prom: pr, stub, missing };
}
