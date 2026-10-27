// Staging incident simulator CLI. See load-harness/README.md, section "Staging incident simulator".
//
//   node dist/sim/cli.js run --scenario setup|signup|login|incident --target staging [options]
//   node dist/sim/cli.js prepare-realms --count N --target staging [options]
//   node dist/sim/cli.js report --run <runId>
//   node dist/sim/cli.js checklist --run <runId>

import "../protocol/undici-setup.js";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { resolveTarget, assertAllowedUrl, CALLBACK_URL, OIDC_CLIENT_ID, type Target } from "./targets.js";
import { parseRate, parseDuration, fmtRate, fmtDuration, newRunId, utcStamp, sleep } from "./util.js";
import { planSteps, Engine, DEFAULT_THRESHOLDS, type OpSpec, type PlannedStep, type Thresholds, type EngineResult, type OpOutcome } from "./engine.js";
import { Pool } from "./pool.js";
import { ClientMonitor } from "./monitor.js";
import { Jsonl, ManifestWriter, UsersSecret, runDir, readJson, type Manifest, type SecretUser } from "./sink.js";
import { ServerWatch } from "./watchers.js";
import { writeReport, cleanupChecklist } from "./report.js";
import { AdminClient } from "./admin.js";
import { setupOnce } from "./scenarios/setup.js";
import { prepareRealms, type RealmsFile } from "./scenarios/prepare.js";
import { BrowserHost, RealmPool, type PoolRealm, LoginUserPool, RefreshStore, makeSignupOp, makeLoginOp, makeRefreshOp, newRunPassword } from "./scenarios/browser.js";
import { NodeCmkClient } from "../protocol/nodeCmkClient.js";
import { makeConsoleSetupOp } from "./scenarios/consoleSetup.js";
import { resolveBrowserOpts, AZURE_PRICE_PER_MIN, type BrowserOpts, type BrowserUsage } from "./remote.js";
import { RunCollector, collectAll, readMeta, readSnaps, type ServerMeta } from "./collect/index.js";
import { STAGING_COLLECT, inventory, type CollectConfig, type StepWindow, type StepServer } from "./collect/collectors.js";
import { azLoggedIn } from "./collect/az.js";
import { dirname as pathDirname } from "node:path";
import { fileURLToPath } from "node:url";

const HARNESS_DIR = pathDirname(pathDirname(pathDirname(fileURLToPath(import.meta.url))));

// --collect auto|off. auto collects on staging when az is logged in; never on a local target.
async function collectConfig(o: Opts, target: string, log: (s: string) => void): Promise<CollectConfig | null> {
  const mode = str(o, "collect", "auto");
  if (mode !== "auto" && mode !== "off") throw new Error("--collect must be auto or off");
  if (mode === "off") return null;
  if (target !== "staging") { log("collect: server collection is staging-only; skipped for this target"); return null; }
  if (!(await azLoggedIn())) { log("collect: az is not logged in; server collection skipped (az login, or managed identity on the VM)"); return null; }
  const stub = str(o, "stripe-stub-url");
  return { ...STAGING_COLLECT, stubUrl: stub === "off" ? null : stub ?? STAGING_COLLECT.stubUrl };
}

function describeBrowsers(b: BrowserOpts, worstMs: number): string {
  if (b.endpoint === "local") return "local Chromium";
  const maxMin = (b.remoteBrowsers * worstMs) / 60_000;
  return `Azure Playwright workspace, ${b.remoteBrowsers} remote browser(s) x ${b.contextsPerBrowser} contexts, ` +
    `open for the whole run: worst case ~${maxMin.toFixed(0)} browser-minutes (~$${(maxMin * AZURE_PRICE_PER_MIN).toFixed(2)} at $${AZURE_PRICE_PER_MIN}/min); ` +
    `PLAYWRIGHT_SERVICE_URL ${process.env.PLAYWRIGHT_SERVICE_URL ? "set" : "NOT set"}`;
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

type Opts = Map<string, string | true>;

function parseArgs(argv: string[]): { cmd: string; opts: Opts } {
  const opts: Opts = new Map();
  let cmd = "run";
  let i = 0;
  if (argv[0] && !argv[0].startsWith("--")) { cmd = argv[0]; i = 1; }
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) throw new Error(`unexpected argument "${a}"`);
    const eq = a.indexOf("=");
    if (eq > 0) { opts.set(a.slice(2, eq), a.slice(eq + 1)); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) { opts.set(key, next); i++; }
    else opts.set(key, true);
  }
  return { cmd, opts };
}

const str = (o: Opts, k: string, d?: string): string | undefined => {
  const v = o.get(k);
  return v === undefined ? d : v === true ? "true" : v;
};
const num = (o: Opts, k: string, d: number): number => {
  const v = str(o, k);
  if (v === undefined) return d;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`--${k} must be a number`);
  return n;
};
const flag = (o: Opts, k: string): boolean => {
  const v = o.get(k);
  return v === true || v === "true" || v === "1" || v === "yes";
};
const list = (o: Opts, k: string): string[] => (str(o, k) ?? "").split(",").map((s) => s.trim()).filter(Boolean);

const KNOWN = new Set([
  "scenario", "target", "tc-url", "run-id", "out", "dry-run", "start-rate", "step-factor", "step-add", "max-rate", "max-steps",
  "step-duration", "cooldown", "drain", "arrival", "browser-pool", "concurrency", "max-queue", "abort-error-rate",
  "break-error-rate", "knee-p95-mult", "knee-throughput", "client-cpu", "client-queue-wait", "realms", "realms-from",
  "seats-per-realm", "users-from", "users-file", "realm", "refresh-ratio", "engine", "headless", "email-domain",
  "setup-retries", "setup-retry-delay", "watch-restarts", "watch-prom", "prom-error-threshold", "ork-apps",
  "confirm-stripe-test", "incident-ratios", "home-ork", "nav-timeout", "no-token", "count", "no-browser-check", "run", "help", "basic", "tide-full", "expect-eddsa", "browser-endpoint", "remote-browsers", "contexts-per-browser", "collect", "collect-wait", "stripe-stub-url", "recollect", "strict-signatures",
]);

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

const SCENARIOS = ["setup", "signup", "login", "incident"] as const;
type Scenario = typeof SCENARIOS[number];

interface Common {
  target: Target;
  runId: string;
  outBase: string;
  dryRun: boolean;
  emailDomain: string;
  headless: boolean;
  browser: BrowserOpts;
}

function browserOpts(o: Opts, target: string): BrowserOpts {
  return resolveBrowserOpts(str(o, "browser-endpoint"), target, num(o, "remote-browsers", 4), num(o, "contexts-per-browser", 5));
}

function common(o: Opts, prefix: string): Common {
  const t = str(o, "target");
  if (!t) throw new Error("--target is required (staging or local)");
  const target = resolveTarget(t, str(o, "tc-url"), list(o, "ork-apps"));
  return {
    target,
    runId: str(o, "run-id") ?? newRunId(prefix),
    outBase: resolve(str(o, "out", "runs")!),
    dryRun: flag(o, "dry-run"),
    emailDomain: str(o, "email-domain", "invalid.tide.test")!,
    headless: str(o, "headless", "true") !== "false",
    browser: browserOpts(o, target.name),
  };
}

function adminCreds(required: boolean): { user: string; password: string } | null {
  const user = process.env.TC_ADMIN_USER ?? "admin";
  const password = process.env.TC_ADMIN_PASSWORD;
  if (!password) {
    if (required) throw new Error("TC_ADMIN_PASSWORD is not set (master admin password for the target TideCloak)");
    return null;
  }
  return { user, password };
}

function requireStripeTest(o: Opts, target: Target, dryRun: boolean): void {
  if (target.name !== "staging" || dryRun) return;
  if (!flag(o, "confirm-stripe-test")) {
    throw new Error("realm setup creates Stripe subscriptions on the staging payers. Confirm they run in Stripe TEST mode " +
      "(sk_test_ key) and pass --confirm-stripe-test. See README, Safety.");
  }
}

function makeLogger(path: string): (s: string) => void {
  return (s: string) => {
    const line = `${new Date().toISOString()} ${s}`;
    console.log(line);
    try { appendFileSync(path, line + "\n"); } catch { /* log dir gone */ }
  };
}

interface RealmInfo { realms: PoolRealm[]; seats: number; source: string; names: string[] }

function loadRealms(o: Opts, outBase: string): RealmInfo {
  const seats = num(o, "seats-per-realm", 5);
  const explicitTide = flag(o, "expect-eddsa");
  const byName = new Map<string, PoolRealm>();
  for (const r of list(o, "realms")) byName.set(r, { realm: r, seats, tideFull: explicitTide });
  let source = byName.size ? "--realms" : "";
  const from = str(o, "realms-from");
  if (from) {
    for (const id of from.split(",")) {
      const p = join(outBase, id.trim(), "realms.json");
      if (!existsSync(p)) throw new Error(`no realm pool file at ${p}`);
      const f = readJson<RealmsFile>(p);
      for (const r of f.realms.filter((x) => x.ready)) {
        // Older pool files have no per-realm seats or mode.
        const left = str(o, "seats-per-realm") ? seats : (typeof r.seats === "number" ? r.seats : f.seatsPerRealm);
        byName.set(r.realm, { realm: r.realm, seats: left, tideFull: !!r.tideFull });
      }
    }
    source = source ? `${source} + ${from}` : `realms-from ${from}`;
  }
  const realms = [...byName.values()];
  const avg = realms.length ? realms.reduce((a, r) => a + r.seats, 0) / realms.length : seats;
  return { realms, seats: Math.max(1, Math.floor(avg)), source, names: realms.map((r) => r.realm) };
}

function loadUsers(o: Opts, outBase: string): { users: SecretUser[]; source: string } {
  const users: SecretUser[] = [];
  const sources: string[] = [];
  const from = str(o, "users-from");
  if (from) {
    for (const id of from.split(",")) {
      const p = join(outBase, id.trim(), "users.secret.json");
      if (!existsSync(p)) throw new Error(`no users file at ${p}`);
      users.push(...(readJson<{ users: SecretUser[] }>(p).users ?? []));
    }
    sources.push(`users-from ${from}`);
  }
  const file = str(o, "users-file");
  if (file) {
    const defRealm = str(o, "realm");
    const raw = readJson<{ users: Array<{ userId?: string; password?: string; realm?: string }> }>(file).users ?? [];
    for (const u of raw) {
      if (!u.userId || !u.password) continue;
      const realm = u.realm ?? defRealm;
      if (!realm) throw new Error(`${file}: user without realm; pass --realm`);
      users.push({ userId: u.userId, password: u.password, realm });
    }
    sources.push(`users-file ${file}`);
  }
  return { users, source: sources.join(" + ") };
}

function thresholds(o: Opts): Thresholds {
  return {
    ...DEFAULT_THRESHOLDS,
    abortErrorRate: num(o, "abort-error-rate", DEFAULT_THRESHOLDS.abortErrorRate),
    breakErrorRate: num(o, "break-error-rate", DEFAULT_THRESHOLDS.breakErrorRate),
    kneeP95Mult: num(o, "knee-p95-mult", DEFAULT_THRESHOLDS.kneeP95Mult),
    kneeThroughput: num(o, "knee-throughput", DEFAULT_THRESHOLDS.kneeThroughput),
    clientCpuPct: num(o, "client-cpu", DEFAULT_THRESHOLDS.clientCpuPct),
    clientQueueWaitMs: num(o, "client-queue-wait", DEFAULT_THRESHOLDS.clientQueueWaitMs),
    strictSignatures: flag(o, "strict-signatures"),
  };
}

const DEFAULT_START: Record<Scenario, string> = { setup: "1/min", signup: "2/min", login: "15/min", incident: "2/min" };

function parseRatios(s: string): { signup: number; login: number; setup: number } {
  const [a, b, c] = s.split(":").map(Number);
  if (![a, b, c].every((x) => Number.isFinite(x) && x >= 0)) throw new Error("--incident-ratios must be signup:login:setup, e.g. 1:10:0.05");
  return { signup: a, login: b, setup: c };
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

async function cmdRun(o: Opts): Promise<number> {
  const scenario = str(o, "scenario") as Scenario;
  if (!SCENARIOS.includes(scenario)) throw new Error(`--scenario must be one of ${SCENARIOS.join("|")} (crash repro is intentionally not offered)`);
  const c = common(o, "s");
  // setup defaults to the http driver, but to the browser driver when cloud browsers are chosen
  // (so the load comes from Azure, not this machine). Other browser scenarios default to browser.
  const engineDefault = scenario === "setup" ? (c.browser.endpoint === "azure" ? "browser" : "http") : "browser";
  const engineKind = str(o, "engine") ?? engineDefault;
  if (engineKind !== "browser" && engineKind !== "http" && engineKind !== "node") throw new Error("--engine must be browser, http or node");
  const stepMs = parseDuration(str(o, "step-duration", "5m")!);
  const cooldownMs = parseDuration(str(o, "cooldown", "2m")!);
  const drainMs = parseDuration(str(o, "drain", "5m")!);
  const startRate = parseRate(str(o, "start-rate", DEFAULT_START[scenario])!);
  const factor = num(o, "step-factor", 2);
  const add = str(o, "step-add") ? parseRate(str(o, "step-add")!) : 0;
  const maxRate = str(o, "max-rate") ? parseRate(str(o, "max-rate")!) : startRate * Math.pow(factor, 7);
  const maxSteps = num(o, "max-steps", 8);
  const steps = planSteps({ startRate, factor, add, maxRate, maxSteps, stepMs, cooldownMs });
  // With remote browsers the pool is spread across them: N browsers x M contexts.
  const browserPool = c.browser.endpoint === "azure" ? c.browser.remoteBrowsers * c.browser.contextsPerBrowser : num(o, "browser-pool", 10);
  if (c.browser.endpoint === "azure" && str(o, "browser-pool")) console.log("  note: --browser-pool is ignored with --browser-endpoint azure (pool = remote browsers x contexts per browser)");
  const httpConc = num(o, "concurrency", 4);
  const ratios = scenario === "incident" ? parseRatios(str(o, "incident-ratios", "1:10:0.05")!) : null;
  const refreshRatio = num(o, "refresh-ratio", 0);
  const th = thresholds(o);
  const needsBrowser = scenario === "signup" || scenario === "incident" || (scenario === "login" && engineKind === "browser") || (scenario === "setup" && engineKind === "browser");
  const needsAdmin = scenario === "setup" || (scenario === "incident" && ratios!.setup > 0);
  const needsRealms = scenario === "signup" || scenario === "incident";
  const needsUsers = scenario === "login";

  // Op rates as ratios of the base step rate.
  const opRatios: Array<{ op: string; ratio: number }> =
    scenario === "incident" ? [{ op: "signup", ratio: ratios!.signup }, { op: "login", ratio: ratios!.login }, { op: "setup", ratio: ratios!.setup }]
    : [{ op: scenario, ratio: 1 }];
  if (refreshRatio > 0 && (scenario === "login" || scenario === "incident")) opRatios.push({ op: "refresh", ratio: refreshRatio * (ratios?.login ?? 1) });

  const realmInfo = needsRealms ? loadRealms(o, c.outBase) : null;
  const userInfo = (needsUsers || str(o, "users-from") || str(o, "users-file")) ? loadUsers(o, c.outBase) : null;

  // ------- plan (always printed) -------
  const stepMin = stepMs / 60_000;
  const signupRatio = opRatios.find((x) => x.op === "signup")?.ratio ?? 0;
  const totalSignups = Math.ceil(steps.reduce((a, s) => a + s.baseRate * signupRatio * stepMin, 0));
  const totalSetups = Math.ceil(steps.reduce((a, s) => a + s.baseRate * (opRatios.find((x) => x.op === "setup")?.ratio ?? 0) * stepMin, 0));
  const seats = realmInfo?.seats ?? num(o, "seats-per-realm", 5);
  console.log(`PLAN ${scenario} run=${c.runId} target=${c.target.name} tc=${c.target.tcBase}`);
  console.log(`  engine=${needsBrowser ? `browser (pool ${browserPool} contexts, headless=${c.headless})` : engineKind} http-concurrency=${httpConc} arrivals=${str(o, "arrival", "poisson")}`);
  if (scenario === "setup" && engineKind === "browser") console.log(`  setup runs through the tide-console create-realm wizard as the master admin; it measures through setUpTideRealm (the workspace-setup load) and stops at the wizard's human Tide-account-link step`);
  if (needsBrowser) console.log(`  browsers: ${describeBrowsers(c.browser, steps.length * (stepMs + cooldownMs) + drainMs)}`);
  console.log(`  client=${OIDC_CLIENT_ID} redirect=${CALLBACK_URL} (intercepted in-process)`);
  console.log(`  steps: ${steps.length} x ${fmtDuration(stepMs)} + ${fmtDuration(cooldownMs)} cooldown, factor ${add > 0 ? "+" + fmtRate(add) : "x" + factor}, worst case ${fmtDuration(steps.length * (stepMs + cooldownMs))} plus one confirm step`);
  let cumSignups = 0;
  for (const s of steps) {
    cumSignups += s.baseRate * (opRatios.find((x) => x.op === "signup")?.ratio ?? 0) * stepMin;
    const realmsNote = cumSignups > 0 ? `  [realms to finish this step: ~${Math.ceil(cumSignups / (realmInfo?.seats ?? num(o, "seats-per-realm", 5)))}]` : "";
    console.log(`  step ${s.index}: ` + opRatios.map((r) => `${r.op} ${fmtRate(s.baseRate * r.ratio)} (~${(s.baseRate * r.ratio * stepMin).toFixed(1)}/step)`).join(", ") + realmsNote);
  }
  console.log(`  knee: p95 > ${th.kneeP95Mult}x baseline or on-time < ${th.kneeThroughput * 100}%; break: errors > ${th.breakErrorRate * 100}% or a hard server failure signature${th.strictSignatures ? " (strict: soft ones too)" : "; soft ones (gateway, statement timeout) only warn"}`);
  console.log(`  abort: rolling ${th.abortWindowMs / 1000}s errors > ${th.abortErrorRate * 100}%${flag(o, "watch-restarts") ? ", any ORK restart" : ""}${flag(o, "watch-prom") ? `, ORK error rate > ${num(o, "prom-error-threshold", 0.5)}/s` : ""}`);
  console.log(`  client-bound: CPU avg > ${th.clientCpuPct}%, queue wait p95 > ${th.clientQueueWaitMs}ms, or dropped arrivals`);
  if (signupRatio > 0) {
    const need = Math.ceil(totalSignups / seats);
    console.log(`  sign-ups if every step runs: ~${totalSignups}; at ${seats} seats/realm that needs ~${need} realms` +
      (realmInfo ? ` (have ${realmInfo.realms.length} from ${realmInfo.source || "nothing"})` : ""));
    if (realmInfo && realmInfo.realms.length < need) console.log(`  NOTE: the realm pool runs out before the last step; S1 stops with "need more realms" (prepare-realms --count ${need - realmInfo.realms.length}).`);
  }
  if (totalSetups > 0) console.log(`  realm setups if every step runs: ~${totalSetups} (each creates a realm + a Stripe test subscription; cleanup is manual)`);
  if (userInfo) console.log(`  login users: ${userInfo.users.length} from ${userInfo.source || "none"} across ${new Set(userInfo.users.map((u) => u.realm)).size} realm(s)`);
  console.log(`  output: ${join(c.outBase, c.runId)}/`);
  if (c.dryRun) {
    if (needsAdmin && !process.env.TC_ADMIN_PASSWORD) console.log(`  (live run needs TC_ADMIN_PASSWORD${c.target.name === "staging" ? " and --confirm-stripe-test" : ""})`);
    console.log("DRY RUN: nothing was sent.");
    return 0;
  }

  // ------- preflight -------
  if (needsRealms && (!realmInfo || realmInfo.realms.length === 0)) throw new Error("no realms: pass --realms a,b,c or --realms-from <prepare runId>");
  if (needsUsers && (!userInfo || userInfo.users.length === 0)) throw new Error("no login users: pass --users-from <signup runId> and/or --users-file");
  if (needsAdmin) requireStripeTest(o, c.target, c.dryRun);
  const creds = adminCreds(needsAdmin);
  const homeOrk = str(o, "home-ork", c.target.name === "staging" ? "https://sork1.tideprotocol.com" : "http://localhost:1001")!;
  if (engineKind === "node") assertAllowedUrl(c.target.name, homeOrk);

  const dir = runDir(c.outBase, c.runId);
  const log = makeLogger(join(dir, "sim.log"));
  const manifest = new ManifestWriter(dir, {
    runId: c.runId, createdAt: new Date().toISOString(), target: c.target.name, tcBase: c.target.tcBase,
    command: `run --scenario ${scenario}`, args: Object.fromEntries(o), emailPattern: `lt-${c.runId}-*@${c.emailDomain}`,
  });
  const secret = new UsersSecret(dir);
  const events = new Jsonl(join(dir, "events.jsonl"));
  const stepsLog = new Jsonl(join(dir, "steps.jsonl"));

  const browserSlots = new Pool("browser", browserPool);
  const httpSlots = new Pool("http", httpConc);
  const monitor = new ClientMonitor([browserSlots, httpSlots]);
  let engine: Engine | null = null;
  const host = needsBrowser ? new BrowserHost({
    headless: c.headless, target: c.target.name, log, onProdHit: (h) => engine?.abort(`browser tried to reach production host ${h}`),
    endpoint: c.browser.endpoint, remoteBrowsers: c.browser.remoteBrowsers, contextsPerBrowser: c.browser.contextsPerBrowser,
  }) : null;
  const admin = creds ? new AdminClient(c.target.tcBase, creds) : null;
  const loginPool = new LoginUserPool();
  userInfo?.users.forEach((u) => loginPool.add(u));
  const refresh = refreshRatio > 0 ? new RefreshStore() : undefined;
  const password = newRunPassword();
  const maxQueue = (p: Pool) => num(o, "max-queue", p.capacity * 4);
  const navTimeoutMs = parseDuration(str(o, "nav-timeout", "60s")!);

  const ops: OpSpec[] = [];
  for (const r of opRatios) {
    if (r.ratio <= 0) continue;
    if (r.op === "setup") {
      if (engineKind === "browser" && scenario === "setup") {
        ops.push({ name: "setup", ratio: r.ratio, pool: browserSlots, maxQueue: maxQueue(browserSlots), run: makeConsoleSetupOp({
          host: host!, tcBase: c.target.tcBase, runId: c.runId, emailDomain: c.emailDomain, creds: creds!, manifest,
          retries: num(o, "setup-retries", 1), log,
        }) });
      } else {
        let n = 0;
        ops.push({ name: "setup", ratio: r.ratio, pool: httpSlots, maxQueue: maxQueue(httpSlots), run: () => setupOnce({
          admin: admin!, manifest, runId: c.runId, emailDomain: c.emailDomain,
          retries: num(o, "setup-retries", 2), retryDelayMs: parseDuration(str(o, "setup-retry-delay", "5s")!),
          realmPrefix: "lt-ws", purpose: "s3-setup",
        }, ++n) });
      }
    } else if (r.op === "signup") {
      ops.push({ name: "signup", ratio: r.ratio, pool: browserSlots, maxQueue: maxQueue(browserSlots), run: makeSignupOp({
        host: host!, tcBase: c.target.tcBase, runId: c.runId, emailDomain: c.emailDomain, password,
        realms: new RealmPool(realmInfo!.realms), manifest, secret,
        loginPool: scenario === "incident" ? loginPool : undefined, exchangeToken: !flag(o, "no-token"), log,
      }) });
    } else if (r.op === "login") {
      if (engineKind === "node") {
        const clients = new Map<string, NodeCmkClient>();
        ops.push({ name: "login", ratio: r.ratio, pool: httpSlots, maxQueue: maxQueue(httpSlots), run: async (): Promise<OpOutcome> => {
          const u = loginPool.next();
          if (!u) return { ok: false, code: "NO_LOGIN_USERS", expected: true };
          let cl = clients.get(u.realm);
          if (!cl) {
            cl = new NodeCmkClient({ tcBase: c.target.tcBase, tcRealm: u.realm, clientId: OIDC_CLIENT_ID, callbackUrl: CALLBACK_URL, homeOrkUrl: homeOrk });
            clients.set(u.realm, cl);
          }
          const res = await cl.login(u, { realm: u.realm, vvkid: "-", vvkPublic: "-", voucherURL: "-", homeOrkUrl: homeOrk, orks: [] });
          const phases = { fetch1_ms: res.phases.fetch1Ms ?? 0, crypto_ms: res.phases.cryptoMs ?? 0, fetch2_ms: res.phases.fetch2Ms ?? 0 };
          return res.ok ? { ok: true, phases } : { ok: false, code: "NODE_LOGIN_FAILED", message: res.message, phases };
        } });
      } else {
        ops.push({ name: "login", ratio: r.ratio, pool: browserSlots, maxQueue: maxQueue(browserSlots), run: makeLoginOp({ host: host!, tcBase: c.target.tcBase, users: loginPool, refresh, navTimeoutMs, expectEddsa: flag(o, "expect-eddsa") }) });
      }
    } else if (r.op === "refresh") {
      ops.push({ name: "refresh", ratio: r.ratio, pool: httpSlots, maxQueue: maxQueue(httpSlots), run: makeRefreshOp(c.target.tcBase, refresh!) });
    }
  }

  const ccfg = await collectConfig(o, c.target.name, log);
  const collector = ccfg ? new RunCollector(ccfg, dir, HARNESS_DIR, log) : null;
  if (collector) await collector.start();

  engine = new Engine({
    runId: c.runId, scenario, steps, stepMs, cooldownMs, drainMs, arrival: str(o, "arrival", "poisson") === "uniform" ? "uniform" : "poisson",
    thresholds: th, events, stepsLog, monitor, log,
    secrets: () => [password, ...loginPool.passwords(), ...(admin?.secrets() ?? [])],
    onStepStart: async (n) => { await collector?.snap(n, "start"); },
    onStepEnd: async (n) => { await collector?.snap(n, "end"); },
  }, ops);

  const watch = new ServerWatch({
    restarts: flag(o, "watch-restarts"), prom: flag(o, "watch-prom"), promErrorThreshold: num(o, "prom-error-threshold", 0.5),
    // Every sork* app the inventory found, unless --ork-apps names them; empty means discover at start.
    rg: c.target.resourceGroup, apps: list(o, "ork-apps").length ? c.target.orkApps : (collector?.meta.start?.apps ?? []).map((a) => a.name).filter((n) => /^sork\d+$/.test(n)),
    promJob: c.target.promJob, intervalMs: 60_000,
    onAbort: (r) => engine?.abort(r), log,
  });

  let sigints = 0;
  process.on("SIGINT", () => {
    sigints++;
    if (sigints === 1) engine?.abort("SIGINT from operator (Ctrl-C again to exit without a report)");
    // Still close the browsers first so remote sessions stop billing.
    else void Promise.race([host?.stop() ?? Promise.resolve(), sleep(5000)]).then(() => process.exit(130));
  });

  log(`############## RUN ${c.runId} START ${utcStamp()} ##############`);
  let result: EngineResult;
  try {
    if (c.target.name === "local" && (flag(o, "watch-restarts") || flag(o, "watch-prom"))) log("note: Azure watchers are for staging; they will likely fail on a local target");
    await watch.start();
    monitor.start();
    await host?.start();
    if (admin) await admin.getToken();
    result = await engine.run();
  } finally {
    watch.stop();
    monitor.stop();
    await host?.stop();
    events.close();
    stepsLog.close();
  }
  log(`############## RUN ${c.runId} END ${utcStamp()} ##############`);

  let server: StepServer[] = [];
  if (collector) {
    const windows: StepWindow[] = result.steps.map((st) => ({ step: st.step, kind: st.kind, startMs: st.startMs, endMs: st.endMs }));
    try {
      server = await collector.finish(windows, parseDuration(str(o, "collect-wait", "3m")!));
    } catch (e) {
      log(`collect: failed (${(e as Error).message}); re-pull with report --run ${c.runId} --recollect`);
    }
  }

  const rep = writeReport({
    dir, runId: c.runId, scenario, target: c.target.name, promJob: c.target.promJob,
    config: { steps: steps.length, stepMs, cooldownMs, startRate, factor, add, maxRate, browserPool, httpConc, opRatios, thresholds: th, engine: engineKind },
    result, manifest: manifest.data, watch: { restarts: watch.restartLog, prom: watch.promLog },
    browserUsage: host?.usage(),
    server, serverMeta: collector?.meta ?? null,
  });
  console.log(`\nreport: ${rep.md}\nevents: ${join(dir, "events.jsonl")}\n`);
  console.log(cleanupChecklist(manifest.data, manifest.path));
  return result.abortReason ? 2 : 0;
}

// ---------------------------------------------------------------------------
// prepare-realms
// ---------------------------------------------------------------------------

async function cmdPrepare(o: Opts): Promise<number> {
  const c = common(o, "p");
  const count = num(o, "count", 0);
  if (count < 1) throw new Error("--count N is required");
  const seats = num(o, "seats-per-realm", 5);
  const conc = num(o, "concurrency", 1);
  console.log(`PLAN prepare-realms run=${c.runId} target=${c.target.name} tc=${c.target.tcBase}`);
  const tideFull = !flag(o, "basic");
  if (tideFull && flag(o, "no-browser-check")) throw new Error("--tide-full verifies with a real sign-up and login, so it cannot skip the browser; use --basic for that");
  const usable = tideFull ? seats - 1 : seats;
  console.log(`  mode: ${tideFull ? "tide-full (IGA on, iga.attestor=tide, EdDSA, ORK-signed tokens)" : "basic (IGA off, RS256 tokens, no PreSign)"}`);
  console.log(`  ${count} realm(s) lt-pool-${c.runId}-1..${count}, concurrency ${conc}, ${seats} seats each, ${usable} left for load after ${tideFull ? "the probe user" : "setup"} = ${count * usable} sign-ups of capacity`);
  console.log(`  per realm: create realm, registration on + verifyEmail off, setUpTideRealm (FreeTier, email lt-${c.runId}-pool<n>@${c.emailDomain}), licence check,`);
  console.log(tideFull
    ? `    iga.attestor=tide, link-tide-account-action, client ${OIDC_CLIENT_ID}, sign IdP settings, toggle-iga, approve pending ADOPT CRs (firstAdmin), sign IdP settings`
    : `    client ${OIDC_CLIENT_ID}, sign IdP settings`);
  console.log(`  ready check: ${tideFull ? "IGA on + attestor tide + EdDSA, sign-up screen renders, probe sign-up + login both mint EdDSA tokens" : flag(o, "no-browser-check") ? "licence active (sign-up screen check skipped)" : "licence active + Tide sign-up screen renders"}`);
  if (!flag(o, "no-browser-check")) console.log(`  browsers: ${describeBrowsers(c.browser, count * 120_000)}`);
  console.log(`  this is workspace-setup load on the target; it is logged separately and not part of any S1 measurement`);
  console.log(`  output: ${join(c.outBase, c.runId)}/realms.json + manifest.json`);
  if (c.dryRun) {
    console.log("DRY RUN: nothing was sent.");
    return 0;
  }
  requireStripeTest(o, c.target, false);
  const creds = adminCreds(true)!;
  const dir = runDir(c.outBase, c.runId);
  const log = makeLogger(join(dir, "prepare.log"));
  const manifest = new ManifestWriter(dir, {
    runId: c.runId, createdAt: new Date().toISOString(), target: c.target.name, tcBase: c.target.tcBase,
    command: "prepare-realms", args: Object.fromEntries(o), emailPattern: `lt-${c.runId}-*@${c.emailDomain}`,
  });
  const secret = new UsersSecret(dir);
  let prodHit: string | null = null;
  const host = flag(o, "no-browser-check") ? null : new BrowserHost({
    headless: c.headless, target: c.target.name, log, onProdHit: (h) => { prodHit = h; },
    endpoint: c.browser.endpoint, remoteBrowsers: c.browser.remoteBrowsers, contextsPerBrowser: c.browser.contextsPerBrowser,
  });
  const admin = new AdminClient(c.target.tcBase, creds);
  let file: RealmsFile;
  const ccfg = await collectConfig(o, c.target.name, log);
  const collector = ccfg ? new RunCollector(ccfg, dir, HARNESS_DIR, log) : null;
  if (collector) { await collector.start(); await collector.snap(1, "start"); }
  const t0 = Date.now();
  try {
    await host?.start();
    await admin.getToken();
    file = await prepareRealms({
      admin, manifest, secret, host, runId: c.runId, target: c.target.name, tcBase: c.target.tcBase, count, concurrency: conc,
      seatsPerRealm: seats, tideFull, emailDomain: c.emailDomain, retries: num(o, "setup-retries", 2),
      retryDelayMs: parseDuration(str(o, "setup-retry-delay", "5s")!), outPath: join(dir, "realms.json"), log,
    });
  } finally {
    await host?.stop();
  }
  if (prodHit) log(`WARNING: a production host (${prodHit}) was requested and blocked`);
  if (host && host.endpoint === "azure") {
    const u = host.usage();
    log(`remote browser-minutes: ${u.browserMinutes.toFixed(2)} (est. $${u.estCostUsd.toFixed(3)})`);
  }
  const ready = file.realms.filter((r) => r.ready).length;
  const t1 = Date.now();
  if (collector) {
    await collector.snap(1, "end");
    try {
      const server = await collector.finish([{ step: 1, kind: "prepare", startMs: t0, endMs: t1 }], parseDuration(str(o, "collect-wait", "3m")!));
      const rep = writeReport({
        dir, runId: c.runId, scenario: "prepare-realms", target: c.target.name, promJob: c.target.promJob, config: { count, concurrency: conc },
        result: { steps: [], abortReason: null, stopReason: null, baselineP95: {} }, manifest: manifest.data,
        browserUsage: host?.usage(), server, serverMeta: collector.meta,
        window: { start: new Date(t0).toISOString(), end: new Date(t1).toISOString() },
      });
      log(`report: ${rep.md}`);
    } catch (e) { log(`collect: failed (${(e as Error).message}); re-pull with report --run ${c.runId} --recollect`); }
  }
  const seatTotal = file.realms.filter((r) => r.ready).reduce((a, r) => a + r.seats, 0);
  log(`prepared ${ready}/${count} ready realm(s) = ${seatTotal} sign-up seats. Use: --realms-from ${c.runId}`);
  console.log(`\n${cleanupChecklist(manifest.data, manifest.path)}`);
  return ready > 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// report / checklist
// ---------------------------------------------------------------------------

// Step windows for a run: steps.jsonl, or the prepare.log span for a prepare-realms run.
function runWindows(dir: string): { windows: StepWindow[]; steps: StepSummaryLite[] } {
  const stepsPath = join(dir, "steps.jsonl");
  if (existsSync(stepsPath)) {
    const steps = readFileSync(stepsPath, "utf8").split("\n").filter(Boolean).map((l: string) => JSON.parse(l) as StepSummaryLite);
    return { steps, windows: steps.map((st) => ({ step: st.step, kind: st.kind, startMs: st.startMs, endMs: st.endMs })) };
  }
  const logPath = join(dir, "prepare.log");
  if (existsSync(logPath)) {
    const ts = readFileSync(logPath, "utf8").split("\n").map((l) => Date.parse(l.slice(0, 24))).filter((t) => Number.isFinite(t));
    if (ts.length) return { steps: [], windows: [{ step: 1, kind: "prepare", startMs: Math.min(...ts) - 5_000, endMs: Math.max(...ts) + 5_000 }] };
  }
  throw new Error(`no steps.jsonl or prepare.log in ${dir}`);
}
type StepSummaryLite = import("./engine.js").StepSummary;

async function cmdReport(o: Opts, onlyChecklist: boolean): Promise<number> {
  const id = str(o, "run");
  if (!id) throw new Error("--run <runId> is required");
  const dir = join(resolve(str(o, "out", "runs")!), id);
  const manifest = readJson<Manifest>(join(dir, "manifest.json"));
  if (onlyChecklist) {
    console.log(cleanupChecklist(manifest, join(dir, "manifest.json")));
    return 0;
  }
  const { steps, windows } = runWindows(dir);
  const prev = existsSync(join(dir, "summary.json")) ? readJson<{ abortReason: string | null; stopReason: string | null; baselineP95: Record<string, number>; scenario: string; target: string; browser?: BrowserUsage | null }>(join(dir, "summary.json")) : null;
  let meta: ServerMeta | null = readMeta(dir);
  let server: StepServer[] = (await import("./collect/index.js")).readServer(dir);
  if (flag(o, "recollect")) {
    const log = makeLogger(join(dir, "collect.log"));
    if (manifest.target !== "staging") throw new Error("--recollect needs a staging run (server data comes from Azure)");
    const cfg = await collectConfig(o, "staging", log);
    if (!cfg) throw new Error("server collection unavailable (az not logged in, or --collect off)");
    if (meta?.config.stubUrl !== undefined && !str(o, "stripe-stub-url")) cfg.stubUrl = meta.config.stubUrl;
    if (!meta?.start) {
      // Older run without a start inventory: use the current one and say so.
      const inv = await inventory(cfg, HARNESS_DIR);
      meta = { collect: "auto", config: { rg: cfg.rg, pgName: cfg.pgName, promJob: cfg.promJob, stubUrl: cfg.stubUrl }, start: null, end: inv, notes: [`no inventory was taken during the run; app list and revisions are from recollect time ${inv.at}`] };
      writeFileSync(join(dir, "server-meta.json"), JSON.stringify(meta, null, 2));
    }
    server = await collectAll(cfg, dir, meta.start ?? meta.end, windows, readSnaps(dir), log);
  }
  const w = windows.length ? { start: new Date(windows[0].startMs).toISOString(), end: new Date(windows[windows.length - 1].endMs).toISOString() } : undefined;
  const rep = writeReport({
    dir, runId: id, scenario: prev?.scenario ?? (steps.length ? "?" : "prepare-realms"), target: prev?.target ?? manifest.target, promJob: "sork-env/ork", config: {},
    result: { steps, abortReason: prev?.abortReason ?? null, stopReason: prev?.stopReason ?? null, baselineP95: prev?.baselineP95 ?? {} },
    manifest, browserUsage: prev?.browser ?? undefined, server, serverMeta: meta, window: w,
  });
  console.log(`report: ${rep.md}`);
  return 0;
}

const HELP = `staging incident simulator

  run --scenario setup|signup|login|incident --target staging|local [options]
  prepare-realms --count N --target staging|local [--seats-per-realm 5] [--concurrency 1]
  report --run <runId> [--recollect]   rebuild summary.md; --recollect re-pulls server data from Azure
  checklist --run <runId>     print the manual cleanup checklist

Add --dry-run to any run or prepare-realms to print the plan without sending anything.
Full options and examples: load-harness/README.md, "Staging incident simulator".`;

async function main(): Promise<number> {
  const { cmd, opts } = parseArgs(process.argv.slice(2));
  if (cmd === "help" || opts.has("help")) { console.log(HELP); return 0; }
  for (const k of opts.keys()) if (!KNOWN.has(k)) throw new Error(`unknown option --${k}`);
  if (cmd === "run") return cmdRun(opts);
  if (cmd === "plan") { opts.set("dry-run", true); return cmdRun(opts); }
  if (cmd === "prepare-realms") return cmdPrepare(opts);
  if (cmd === "report") return cmdReport(opts, false);
  if (cmd === "checklist") return cmdReport(opts, true);
  throw new Error(`unknown command "${cmd}"\n\n${HELP}`);
}

main().then((code) => process.exit(code), async (e) => {
  console.error(`ERROR ${(e as Error)?.message ?? String(e)}`);
  await sleep(10);
  process.exit(1);
});
