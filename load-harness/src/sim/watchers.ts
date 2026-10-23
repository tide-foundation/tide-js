// Optional read-only server watchers. Both shell out to the Azure CLI and never change anything.
//   restarts: sum of container restartCount per ORK app (az containerapp replica list)
//   prom:     ORK outbound error rate from Azure Managed Prometheus

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

export const PROM_QUERY_BASE = "https://ork-prometheus-adehanchbsf2ctfn.australiaeast.prometheus.monitor.azure.com/api/v1";

async function az(args: string[]): Promise<string> {
  const { stdout } = await run("az", args, { timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
  return stdout.trim();
}

export async function restartCounts(rg: string, apps: string[]): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  await Promise.all(apps.map(async (app) => {
    const raw = await az([
      "containerapp", "replica", "list", "-n", app, "-g", rg,
      "--query", "[].properties.containers[].restartCount", "-o", "json",
    ]);
    const arr = JSON.parse(raw || "[]") as Array<number | null>;
    out[app] = arr.reduce<number>((a, b) => a + (b ?? 0), 0);
  }));
  return out;
}

export async function promErrorRate(job: string): Promise<number> {
  const token = await az(["account", "get-access-token", "--resource", "https://prometheus.monitor.azure.com", "--query", "accessToken", "-o", "tsv"]);
  const q = `sum(rate(tide_ork_outbound_duration_seconds_count{job="${job}",status="error"}[2m]))`;
  const res = await fetch(`${PROM_QUERY_BASE}/query?query=${encodeURIComponent(q)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`prometheus HTTP ${res.status}`);
  const j = (await res.json()) as { data?: { result?: Array<{ value: [number, string] }> } };
  const v = j.data?.result?.[0]?.value?.[1];
  return v ? parseFloat(v) : 0;
}

export interface WatchOpts {
  restarts: boolean;
  prom: boolean;
  promErrorThreshold: number; // errors per second
  rg: string;
  apps: string[];
  promJob: string;
  intervalMs: number;
  onAbort: (reason: string) => void;
  log: (s: string) => void;
}

// Polls until stopped. A watcher error is logged, not fatal, so a flaky az call never aborts a run.
export class ServerWatch {
  private timer: NodeJS.Timeout | null = null;
  private baseline: Record<string, number> | null = null;
  readonly restartLog: Array<{ t: string; counts: Record<string, number> }> = [];
  readonly promLog: Array<{ t: string; errPerSec: number }> = [];

  constructor(private o: WatchOpts) {}

  async start(): Promise<void> {
    if (!this.o.restarts && !this.o.prom) return;
    if (this.o.restarts) {
      this.baseline = await restartCounts(this.o.rg, this.o.apps);
      this.restartLog.push({ t: new Date().toISOString(), counts: this.baseline });
      this.o.log(`restart baseline ${JSON.stringify(this.baseline)}`);
    }
    this.timer = setInterval(() => void this.tick(), this.o.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async tick(): Promise<void> {
    if (this.o.restarts && this.baseline) {
      try {
        const now = await restartCounts(this.o.rg, this.o.apps);
        this.restartLog.push({ t: new Date().toISOString(), counts: now });
        const bumped = Object.keys(now).filter((k) => now[k] > (this.baseline![k] ?? 0));
        if (bumped.length) this.o.onAbort(`ORK restart detected on ${bumped.join(",")}`);
      } catch (e) {
        this.o.log(`restart watch error: ${(e as Error).message}`);
      }
    }
    if (this.o.prom) {
      try {
        const r = await promErrorRate(this.o.promJob);
        this.promLog.push({ t: new Date().toISOString(), errPerSec: r });
        if (r > this.o.promErrorThreshold) this.o.onAbort(`ORK outbound error rate ${r.toFixed(3)}/s above ${this.o.promErrorThreshold}/s`);
      } catch (e) {
        this.o.log(`prometheus watch error: ${(e as Error).message}`);
      }
    }
  }
}
