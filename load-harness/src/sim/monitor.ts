// Client-side saturation sampling: whole-machine CPU, event loop delay, pool occupancy.
// Chromium runs in separate processes, so CPU is measured machine-wide, not per process.

import { cpus, loadavg } from "node:os";
import { monitorEventLoopDelay } from "node:perf_hooks";
import type { Pool } from "./pool.js";

export interface ClientSample {
  t: number;
  cpuPct: number;
  load1: number;
  loopLagMs: number;
  pools: Record<string, { busy: number; queued: number; capacity: number }>;
}

function cpuTotals(): { idle: number; total: number } {
  let idle = 0;
  let total = 0;
  for (const c of cpus()) {
    const t = c.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.idle + t.irq;
  }
  return { idle, total };
}

export class ClientMonitor {
  readonly samples: ClientSample[] = [];
  private timer: NodeJS.Timeout | null = null;
  private last = cpuTotals();
  private loop = monitorEventLoopDelay({ resolution: 20 });

  constructor(private pools: Pool[], private intervalMs = 2000) {}

  start(): void {
    this.loop.enable();
    this.timer = setInterval(() => this.sample(), this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.loop.disable();
  }

  private sample(): void {
    const now = cpuTotals();
    const dIdle = now.idle - this.last.idle;
    const dTotal = now.total - this.last.total;
    this.last = now;
    const cpuPct = dTotal > 0 ? Math.round((1 - dIdle / dTotal) * 1000) / 10 : 0;
    const loopLagMs = Math.round(this.loop.percentile(95) / 1e6);
    this.loop.reset();
    const pools: ClientSample["pools"] = {};
    for (const p of this.pools) pools[p.name] = { busy: p.busy, queued: p.queued, capacity: p.capacity };
    this.samples.push({ t: Date.now(), cpuPct, load1: loadavg()[0], loopLagMs, pools });
  }

  window(from: number, to: number): ClientSample[] {
    return this.samples.filter((s) => s.t >= from && s.t <= to);
  }
}
