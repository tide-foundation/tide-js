// Postgres connections per client during a run. Samples pg_stat_activity every 15s through psql
// (read-only login in STAGING_PG_URL) into pg-activity.jsonl, maps client IPs to apps, and turns
// the samples into per-step tables plus the pool-cap and near-max rules.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { az, redact } from "./az.js";
import type { CollectConfig, Inventory } from "./collectors.js";

const run = promisify(execFile);

export const PG_ENV = "STAGING_PG_URL";
export const PG_DBS = ["simdb0", "zivadb", "dauthme"];
const SAMPLE_MS = 15_000;
const QUERY_TIMEOUT_S = 5;

// A pool cap shows as a flat top: the same peak for 3+ samples in a row with most connections active.
export const PG_PLATEAU = { samples: 3, activeShare: 0.5, minConns: 5 };
export const PG_NEAR_MAX = 0.9;

export interface PgRow { db: string; addr: string | null; appName: string; state: string | null; wait: string | null; n: number }
export interface IpApp { name: string; role: string }
export type IpMap = Record<string, IpApp[]>;

type Line =
  | { kind: "start"; t: string; maxConnections: number | null; ipMap: IpMap; missing: string[] }
  | { kind: "sample"; t: string; serverTotal: number; rows: PgRow[] }
  | { kind: "skipped"; t: string; reason: string };

const SQL = `SELECT datname, client_addr::text, application_name, state, wait_event_type, count(*),
  (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend')
FROM pg_stat_activity WHERE datname IN (${PG_DBS.map((d) => `'${d}'`).join(",")}) AND pid <> pg_backend_pid() GROUP BY 1,2,3,4,5`;

// libpq env from a postgres:// URL, so nothing secret lands in argv.
export function pgEnv(url: string): Record<string, string> {
  const u = new URL(url);
  if (!/^postgres(ql)?:$/.test(u.protocol)) throw new Error(`${PG_ENV} must be a postgres:// URL`);
  const env: Record<string, string> = { PGHOST: u.hostname, PGPORT: u.port || "5432", PGDATABASE: decodeURIComponent(u.pathname.slice(1)) || "postgres", PGSSLMODE: u.searchParams.get("sslmode") ?? "require" };
  if (u.username) env.PGUSER = decodeURIComponent(u.username);
  if (u.password) env.PGPASSWORD = decodeURIComponent(u.password);
  return env;
}

async function psql(url: string, sql: string): Promise<string[][]> {
  const env = { ...process.env, ...pgEnv(url), PGCONNECT_TIMEOUT: String(QUERY_TIMEOUT_S), PGOPTIONS: `-c statement_timeout=${QUERY_TIMEOUT_S * 1000}`, PGAPPNAME: "tide-load-harness" };
  try {
    const { stdout } = await run("psql", ["-X", "-q", "-A", "-t", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-c", sql], { env, timeout: (QUERY_TIMEOUT_S + 3) * 1000 });
    return stdout.split("\n").filter(Boolean).map((l) => l.split("\t"));
  } catch (e) {
    const err = e as { stderr?: string; message?: string; code?: string };
    if (err.code === "ENOENT") throw new Error("psql is not installed");
    throw new Error(redact((err.stderr || err.message || String(e)).split("\n").filter(Boolean).slice(0, 2).join(" ")).slice(0, 300));
  }
}

// IP -> apps from the VM public IPs and the Container Apps outbound IPs.
export async function pgIpMap(cfg: CollectConfig, inv: Inventory | null, missing: string[]): Promise<IpMap> {
  const map: IpMap = {};
  const role = (name: string) => inv?.apps.find((a) => a.name === name)?.role ?? "";
  const add = (ip: string, name: string) => { const k = ip.trim(); if (k && !(map[k] ??= []).some((a) => a.name === name)) map[k].push({ name, role: role(name) }); };
  try {
    for (const v of await az<Array<{ name: string; ip?: string | null }>>(["vm", "list", "-g", cfg.rg, "-d", "--query", "[].{name:name, ip:publicIps}"])) {
      if (cfg.vmFilter.test(v.name)) for (const ip of (v.ip ?? "").split(",")) add(ip, v.name);
    }
  } catch (e) { missing.push(`vm public IPs: ${(e as Error).message}`); }
  try {
    for (const a of await az<Array<{ name: string; ips?: string[] | null }>>(["containerapp", "list", "-g", cfg.rg, "--query", "[].{name:name, ips:properties.outboundIpAddresses}"])) {
      // A VM that replaced a stopped app of the same name owns that name.
      if (cfg.appFilter.test(a.name) && inv?.apps.find((x) => x.name === a.name)?.kind !== "vm") for (const ip of a.ips ?? []) add(ip, a.name);
    }
  } catch (e) { missing.push(`container app outbound IPs: ${(e as Error).message}`); }
  return map;
}

const DB_ROLE: Record<string, { label: string; re: RegExp }> = {
  simdb0: { label: "master ORKs", re: /master/i },
  zivadb: { label: "payers", re: /payer/i },
  dauthme: { label: "tidecloak", re: /tidecloak/i },
};

// One app on the IP: its name. Several (a shared env IP): label by database. Unknown: the raw address.
export function clientLabel(addr: string | null, db: string, map: IpMap): string {
  if (!addr) return "local";
  const ip = addr.replace(/\/\d+$/, "");
  const apps = map[ip];
  if (!apps?.length) return ip;
  if (apps.length === 1) return apps[0].name;
  const r = DB_ROLE[db];
  const hit = r ? apps.filter((a) => r.re.test(a.role)) : [];
  if (hit.length === 1) return hit[0].name;
  return `${r?.label ?? db} (${(hit.length ? hit : apps).map((a) => a.name).join(",")})`;
}

export class PgSampler {
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  private stopped = false;
  private failed = 0;
  private ok = 0;
  private file: string;

  constructor(private cfg: CollectConfig, dir: string, private inv: Inventory | null, private log: (s: string) => void, private url = process.env[PG_ENV]) {
    this.file = join(dir, "pg-activity.jsonl");
  }

  private write(l: Line): void {
    try { appendFileSync(this.file, JSON.stringify(l) + "\n"); } catch { /* never break the run */ }
  }

  async start(): Promise<void> {
    if (!this.url) {
      this.write({ kind: "skipped", t: new Date().toISOString(), reason: `${PG_ENV} not set` });
      this.log(`collect: pg activity skipped (${PG_ENV} not set)`);
      return;
    }
    const missing: string[] = [];
    let maxConnections: number | null = null;
    try { maxConnections = parseInt((await psql(this.url, "SHOW max_connections"))[0]?.[0] ?? "", 10) || null; }
    catch (e) {
      const why = (e as Error).message;
      this.write({ kind: "skipped", t: new Date().toISOString(), reason: why });
      this.log(`collect: pg activity skipped (${why})`);
      return;
    }
    const ipMap = await pgIpMap(this.cfg, this.inv, missing);
    if (this.stopped) return;
    this.write({ kind: "start", t: new Date().toISOString(), maxConnections, ipMap, missing });
    this.log(`collect: pg activity sampling every ${SAMPLE_MS / 1000}s, max_connections ${maxConnections ?? "-"}, ${Object.keys(ipMap).length} known client IP(s)`);
    void this.sample();
    this.timer = setInterval(() => void this.sample(), SAMPLE_MS);
    this.timer.unref();
  }

  private async sample(): Promise<void> {
    if (this.busy || !this.url) return;
    this.busy = true;
    try {
      const t = new Date().toISOString();
      const raw = await psql(this.url, SQL);
      const rows: PgRow[] = raw.map((r) => ({ db: r[0], addr: r[1] || null, appName: r[2] ?? "", state: r[3] || null, wait: r[4] || null, n: parseInt(r[5], 10) || 0 }));
      this.write({ kind: "sample", t, serverTotal: parseInt(raw[0]?.[6] ?? "", 10) || rows.reduce((a, r) => a + r.n, 0), rows });
      this.ok++;
    } catch (e) {
      if (this.failed++ === 0) this.log(`collect: pg activity sample failed (${(e as Error).message}); keeps trying, failures counted`);
    } finally { this.busy = false; }
  }

  stop(): void {
    this.stopped = true;
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
    this.log(`collect: pg activity ${this.ok} sample(s)${this.failed ? `, ${this.failed} failed` : ""}`);
  }
}

// ---------------------------------------------------------------------------
// Report side
// ---------------------------------------------------------------------------

export interface PgClientStep {
  client: string; db: string;
  peakTotal: number; peakActive: number; avgActive: number; peakIdleTx: number;
  plateau: boolean;
}
export interface PgStepActivity { step: number; samples: number; clients: PgClientStep[]; serverPeak: number | null; nearMax: boolean }
export interface PgActivity { maxConnections: number | null; steps: PgStepActivity[]; missing: string | null; notes: string[] }

// True when the series sits at its peak for PG_PLATEAU.samples in a row with most connections active.
export function poolPlateau(series: Array<{ total: number; active: number }>, o = PG_PLATEAU): boolean {
  const peak = Math.max(0, ...series.map((s) => s.total));
  if (peak < o.minConns) return false;
  let runLen = 0;
  for (const s of series) {
    runLen = s.total === peak && s.active / s.total > o.activeShare ? runLen + 1 : 0;
    if (runLen >= o.samples) return true;
  }
  return false;
}

export const PG_MISSING_HINT = `set ${PG_ENV} (postgres:// URL of a read-only login with pg_read_all_stats on dauthme-staging; psql on PATH) before the run`;

export function readPgActivity(dir: string, steps: Array<{ step: number; startedAt: string; endedAt: string }>): PgActivity {
  const p = join(dir, "pg-activity.jsonl");
  const empty = (missing: string): PgActivity => ({ maxConnections: null, steps: [], missing, notes: [] });
  if (!existsSync(p)) return empty(`no pg-activity.jsonl for this run; ${PG_MISSING_HINT}`);
  const lines = readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Line);
  const start = lines.find((l): l is Extract<Line, { kind: "start" }> => l.kind === "start");
  const skipped = lines.find((l): l is Extract<Line, { kind: "skipped" }> => l.kind === "skipped");
  if (!start) return empty(`not sampled (${skipped?.reason ?? "no start line"}); ${PG_MISSING_HINT}`);
  const samples = lines.filter((l): l is Extract<Line, { kind: "sample" }> => l.kind === "sample");
  const notes = start.missing.map((m) => `client mapping: ${m}`);
  if (samples.some((s) => s.rows.some((r) => r.n > 0 && r.state === null))) notes.push("some sessions show no state: the login lacks pg_read_all_stats, so active vs idle is undercounted");
  const max = start.maxConnections;
  const out: PgStepActivity[] = [];
  for (const st of steps) {
    const a = Date.parse(st.startedAt), b = Date.parse(st.endedAt);
    const win = samples.filter((s) => { const t = Date.parse(s.t); return t >= a && t <= b; });
    const keys = new Map<string, { client: string; db: string }>();
    const per = win.map((s) => {
      const m = new Map<string, { total: number; active: number; idleTx: number }>();
      for (const r of s.rows) {
        const client = clientLabel(r.addr, r.db, start.ipMap);
        const k = `${client}\t${r.db}`;
        keys.set(k, { client, db: r.db });
        const c = m.get(k) ?? { total: 0, active: 0, idleTx: 0 };
        c.total += r.n;
        if (r.state === "active") c.active += r.n;
        if (r.state?.startsWith("idle in transaction")) c.idleTx += r.n;
        m.set(k, c);
      }
      return m;
    });
    const clients: PgClientStep[] = [...keys].map(([k, { client, db }]) => {
      const series = per.map((m) => m.get(k) ?? { total: 0, active: 0, idleTx: 0 });
      return {
        client, db,
        peakTotal: Math.max(...series.map((x) => x.total)),
        peakActive: Math.max(...series.map((x) => x.active)),
        avgActive: Math.round((series.reduce((s, x) => s + x.active, 0) / series.length) * 10) / 10,
        peakIdleTx: Math.max(...series.map((x) => x.idleTx)),
        plateau: poolPlateau(series),
      };
    }).sort((x, y) => y.peakTotal - x.peakTotal || x.client.localeCompare(y.client));
    const serverPeak = win.length ? Math.max(...win.map((s) => s.serverTotal)) : null;
    out.push({ step: st.step, samples: win.length, clients, serverPeak, nearMax: !!max && serverPeak !== null && serverPeak >= PG_NEAR_MAX * max });
  }
  return { maxConnections: max, steps: out, missing: null, notes };
}

export function pgActivityMarkdown(pg: PgActivity | null): string[] {
  const lines = ["## Postgres connections by client", ""];
  if (!pg || pg.missing) return [...lines, `- missing data: ${pg?.missing ?? PG_MISSING_HINT}`, ""];
  for (const n of pg.notes) lines.push(`- note: ${n}`);
  if (pg.notes.length) lines.push("");
  for (const s of pg.steps) {
    lines.push(`**Step ${s.step}**: ${s.samples} sample(s), server peak ${s.serverPeak ?? "-"} of ${pg.maxConnections ?? "-"} max_connections${s.nearMax ? " **NEAR MAX**" : ""}`, "");
    if (!s.clients.length) { lines.push("- no sessions on simdb0, zivadb or dauthme in this window", ""); continue; }
    lines.push("| client | database | peak total | peak active | avg active | peak idle in transaction | pool cap? |", "|---|---|---|---|---|---|---|");
    for (const c of s.clients) lines.push(`| ${c.client} | ${c.db} | ${c.peakTotal} | ${c.peakActive} | ${c.avgActive} | ${c.peakIdleTx} | ${c.plateau ? "**likely** (flat at peak, mostly active)" : "-"} |`);
    lines.push("");
  }
  return lines;
}
