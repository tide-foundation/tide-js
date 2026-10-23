// Run-level server evidence: inventory at start and end, Stripe stub snapshots around each step,
// and the per-step collection after the run (Azure metrics lag 1 to 3 minutes).

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { inventory, collectStep, stubSnapshot, type CollectConfig, type Inventory, type StepServer, type StepWindow, type StubStats } from "./collectors.js";
import { sleep } from "../util.js";

export interface ServerMeta {
  collect: "auto" | "off";
  config: { rg: string; pgName: string; promJob: string; stubUrl: string | null };
  start: Inventory | null;
  end: Inventory | null;
  notes: string[];
}

interface Snap { step: number; phase: "start" | "end"; t: string; stats: StubStats }

export class RunCollector {
  private snaps: Snap[] = [];
  meta: ServerMeta;

  constructor(private cfg: CollectConfig, private dir: string, private harnessDir: string, private log: (s: string) => void) {
    this.meta = { collect: "auto", config: { rg: cfg.rg, pgName: cfg.pgName, promJob: cfg.promJob, stubUrl: cfg.stubUrl }, start: null, end: null, notes: [] };
  }

  private saveMeta(): void {
    writeFileSync(join(this.dir, "server-meta.json"), JSON.stringify(this.meta, null, 2));
  }

  async start(): Promise<void> {
    try {
      this.meta.start = await inventory(this.cfg, this.harnessDir);
      this.log(`collect: inventory ${this.meta.start.apps.length} app(s), ${this.meta.start.workspaces.length} log workspace(s), postgres ${this.meta.start.pg ? "ok" : "missing"}${this.meta.start.missing.length ? `, missing: ${this.meta.start.missing.join("; ")}` : ""}`);
    } catch (e) {
      this.meta.notes.push(`start inventory failed: ${(e as Error).message}`);
    }
    this.saveMeta();
  }

  async snap(step: number, phase: "start" | "end"): Promise<void> {
    if (!this.cfg.stubUrl) return;
    try {
      const stats = await stubSnapshot(this.cfg.stubUrl);
      const s: Snap = { step, phase, t: new Date().toISOString(), stats };
      this.snaps.push(s);
      appendFileSync(join(this.dir, "stub-snapshots.jsonl"), JSON.stringify(s) + "\n");
    } catch (e) {
      this.meta.notes.push(`stub snapshot step ${step} ${phase}: ${(e as Error).message}`);
    }
  }

  // Waits for metric ingestion, then pulls every step window.
  async finish(windows: StepWindow[], waitMs: number): Promise<StepServer[]> {
    const lastEnd = Math.max(0, ...windows.map((w) => w.endMs));
    const wait = lastEnd + waitMs - Date.now();
    if (wait > 0) {
      this.log(`collect: waiting ${Math.round(wait / 1000)}s for Azure metrics to land (press Ctrl-C twice to exit without it; re-pull later with report --recollect)`);
      await sleep(wait);
    }
    try { this.meta.end = await inventory(this.cfg, this.harnessDir); } catch (e) { this.meta.notes.push(`end inventory failed: ${(e as Error).message}`); }
    this.saveMeta();
    return collectAll(this.cfg, this.dir, this.meta.start ?? this.meta.end, windows, this.snaps, this.log);
  }
}

export async function collectAll(cfg: CollectConfig, dir: string, inv: Inventory | null, windows: StepWindow[], snaps: Snap[], log: (s: string) => void): Promise<StepServer[]> {
  const out: StepServer[] = [];
  if (!inv) {
    log("collect: no inventory, skipping server collection");
    return out;
  }
  const token: { t?: string } = {};
  const file = join(dir, "server-metrics.jsonl");
  writeFileSync(file, "");
  for (const w of windows) {
    const pair = { start: snaps.find((s) => s.step === w.step && s.phase === "start")?.stats, end: snaps.find((s) => s.step === w.step && s.phase === "end")?.stats };
    const s = await collectStep(inv, cfg, w, cfg.stubUrl ? pair : null, token);
    appendFileSync(file, JSON.stringify(s) + "\n");
    log(`collect: step ${w.step}: ${Object.keys(s.apps).length} app metric set(s), postgres ${s.pg ? "ok" : "missing"}, logs ${s.logs ? `${s.logs.exec.length} exec rows` : "missing"}, prometheus ${s.prom ? "ok" : "missing"}, stub ${s.stub ? (s.stub.ok ? "ok" : "UNEXPECTED PASSTHROUGH") : "n/a"}${s.missing.length ? `, ${s.missing.length} missing item(s)` : ""}`);
    out.push(s);
  }
  return out;
}

export function readSnaps(dir: string): Snap[] {
  const p = join(dir, "stub-snapshots.jsonl");
  if (!existsSync(p)) return [];
  return readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Snap);
}

export function readMeta(dir: string): ServerMeta | null {
  const p = join(dir, "server-meta.json");
  return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as ServerMeta) : null;
}

export function readServer(dir: string): StepServer[] {
  const p = join(dir, "server-metrics.jsonl");
  if (!existsSync(p)) return [];
  return readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as StepServer);
}
