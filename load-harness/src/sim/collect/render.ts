// Markdown for the server evidence and run metadata sections of summary.md.

import type { StepSummary } from "../engine.js";
import type { Inventory, StepServer } from "./collectors.js";
import type { ServerMeta } from "./index.js";

const n = (v: number | null | undefined, unit = "") => (v === null || v === undefined ? "-" : `${v}${unit}`);

const KEY_OPS = /^(Master\.SubmitUser|Create\.|Key\.PreSign|Key\.Sign|Auth\.|Subscription\.Validate|Subscription\.CreateFreeTierLicense|Users\.UserInfo)/;

export function metadataMarkdown(meta: ServerMeta | null): string[] {
  const lines = ["## Run metadata", ""];
  if (!meta || (!meta.start && !meta.end)) return [...lines, "- server collection was off or failed (no inventory)", ""];
  const s = meta.start;
  const e = meta.end;
  lines.push(`- harness commit: ${s?.harnessCommit ?? e?.harnessCommit ?? "-"}`);
  lines.push(`- inventory taken: start ${s?.at ?? "-"}, end ${e?.at ?? "-"}`);
  const payers = (s ?? e)!.apps.filter((a) => a.stripeApiBase);
  lines.push(`- Stripe stub: ${payers.length ? `ON, ${payers.map((a) => `${a.name} -> ${a.stripeApiBase}`).join(", ")}` : "OFF (no payer has --stripe-api-base)"}${meta.config.stubUrl ? `; stats from ${new URL(meta.config.stubUrl).host}` : ""}`);
  if (s?.pg) lines.push(`- Postgres: ${s.pg.name} ${s.pg.sku ?? ""} (${s.pg.tier ?? ""}), max_connections ${s.pg.maxConnections ?? "-"}`);
  lines.push("", "| app | role | image | revision (start) | revision (end) | cpu limit | memory | replicas min-max |", "|---|---|---|---|---|---|---|---|");
  for (const a of (s ?? e)!.apps) {
    const b = e?.apps.find((x) => x.name === a.name);
    const changed = b && (b.revision !== a.revision || b.image !== a.image);
    lines.push(`| ${a.name} | ${a.role} | ${a.image ?? "-"} | ${a.revision ?? "-"} | ${b ? `${b.revision}${changed ? " **CHANGED**" : ""}` : "-"} | ${n(a.cpu)} | ${n(a.memoryGi, "Gi")} | ${n(a.minReplicas)}-${n(a.maxReplicas)} |`);
  }
  if (e && s && e.apps.some((b) => { const a = s.apps.find((x) => x.name === b.name); return a && (a.revision !== b.revision || a.image !== b.image); })) {
    lines.push("", "WARNING: an app changed revision or image during the run (deploy or restart); results across that point are not comparable.");
  }
  for (const note of meta.notes) lines.push(`- note: ${note}`);
  lines.push("");
  return lines;
}

export function phaseMarkdown(steps: StepSummary[]): string[] {
  const lines = ["## Client phase p95 per step (ms)", ""];
  const keys = new Set<string>();
  for (const s of steps) for (const o of s.ops) for (const p of Object.keys(o.phaseP95)) keys.add(`${o.op}.${p}`);
  if (!keys.size) return [...lines, "- no phase data", ""];
  const cols = [...keys];
  lines.push(`| step | ${cols.join(" | ")} |`, `|---|${cols.map(() => "---").join("|")}|`);
  for (const s of steps) {
    lines.push(`| ${s.step} | ${cols.map((c) => { const [op, ph] = [c.slice(0, c.indexOf(".")), c.slice(c.indexOf(".") + 1)]; return n(s.ops.find((o) => o.op === op)?.phaseP95[ph] ?? null); }).join(" | ")} |`);
  }
  lines.push("");
  return lines;
}

// Server log signatures per step for "Failure signatures seen"; error_lines is a count, not a signature.
export function serverSignatureLines(server: StepServer[]): string[] {
  const out: string[] = [];
  for (const s of server) {
    const hits = Object.entries(s.logs?.signatures ?? {}).flatMap(([app, sig]) => Object.entries(sig).filter(([k, v]) => v > 0 && k !== "error_lines").map(([k, v]) => `${app} ${k} x${v}`));
    if (hits.length) out.push(`- server step ${s.step}: ${hits.join(", ")}`);
  }
  return out;
}

export function serverMarkdown(server: StepServer[], inv: Inventory | null): string[] {
  const lines = ["## Server evidence per step", ""];
  if (!server.length) return [...lines, "- not collected (use --collect auto, or report --run <id> --recollect)", ""];
  for (const s of server) {
    lines.push(`### Step ${s.step} (${s.kind}) ${s.window.start} to ${s.window.end}`, "");
    lines.push("| app | role | CPU avg/max % of limit | cores max | memory max % | replicas max | restarts | requests | response ms avg/max |", "|---|---|---|---|---|---|---|---|---|");
    for (const [app, m] of Object.entries(s.apps).sort()) {
      const role = inv?.apps.find((a) => a.name === app)?.role ?? "";
      lines.push(`| ${app} | ${role} | ${n(m.cpuPctAvg)} / ${n(m.cpuPctMax)} | ${n(m.cpuCoresMax)} of ${n(m.limitCores)} | ${n(m.memPctMax)} | ${n(m.replicasMax)} | ${n(m.restarts)} | ${n(m.requests)} | ${n(m.respMsAvg)} / ${n(m.respMsMax)} |`);
    }
    if (s.pg) {
      const p = s.pg;
      lines.push("", `Postgres: CPU avg/max ${n(p.cpuPctAvg)}/${n(p.cpuPctMax)}%, memory max ${n(p.memPctMax)}%, active connections max ${n(p.activeConnMax)} of ${n(p.maxConnections)} (${n(p.connPctMax)}%), disk IOPS max ${n(p.iopsPctMax)}%, CPU credits min ${n(p.cpuCreditsMin)}, connections failed ${n(p.connectionsFailed)}`);
    }
    const sigRows = Object.entries(s.logs?.signatures ?? {}).map(([app, sig]) => [app, Object.entries(sig).filter(([, v]) => v > 0)] as const).filter(([, v]) => v.length);
    lines.push("", `Log signatures: ${sigRows.length ? sigRows.map(([app, v]) => `${app} { ${v.map(([k, c]) => `${k}: ${c}`).join(", ")} }`).join("; ") : s.logs ? "none" : "not collected"}`);
    for (const [app, samples] of Object.entries(s.logs?.errorSamples ?? {})) {
      const errs = s.logs?.signatures[app]?.error_lines ?? 0;
      if (samples.length) lines.push(`Top errors ${app} (${errs} error lines): ${samples.map((x) => `\`${x.msg.replace(/[|`]/g, "/")}\` x${x.n}`).join("; ")}`);
    }
    const sys = (s.logs?.system ?? []).filter((e) => /Terminated|BackOff|Crashing|ProbeFailed|Started|Created|RevisionUpdate/i.test(e.reason));
    if (sys.length) lines.push(`Container events: ${sys.map((e) => `${e.app} ${e.reason} x${e.n}${e.exitCodes ? ` (exit ${e.exitCodes})` : ""}`).join("; ")}`);
    const ex = (s.logs?.exec ?? []).filter((r) => KEY_OPS.test(r.op)).sort((a, b) => a.op.localeCompare(b.op) || a.app.localeCompare(b.app));
    if (ex.length) {
      lines.push("", "| ORK op | app | n | p50 ms | p95 ms | max ms |", "|---|---|---|---|---|---|");
      for (const r of ex) lines.push(`| ${r.op} | ${r.app} | ${r.n} | ${r.p50} | ${r.p95} | ${r.max} |`);
    } else if (s.logs) lines.push("", "ORK execution times: no key-op log lines in this window");
    if (s.prom) {
      const p = s.prom;
      lines.push("", `Prometheus (window widened to at least 5 min ending at the step end): outbound ${p.outbound.map((o) => `${o.target}/${o.status} ${o.count}`).join(", ") || "none"}; outbound p95 ms ${JSON.stringify(p.outboundP95)}; outbound avg ms ${JSON.stringify(p.outboundAvg)}; semaphore wait p95 ${n(p.semaphoreWaitP95, "ms")}, waiters max ${n(p.semaphoreWaitersMax)}; throttle rejections ${n(p.throttleRejections)}; thread pool queue max ${n(p.threadPoolQueueMax)}`);
      const proto = Object.entries(p.protocolP95).filter(([, v]) => v > 0);
      if (proto.length) lines.push(`Protocol p95 ms: ${proto.map(([k, v]) => `${k} ${v}`).join(", ")}`);
    }
    if (s.stub) {
      lines.push("", `Stripe stub delta: ${JSON.stringify(s.stub.decisions)}; ${s.stub.ok ? "load-test Stripe calls stubbed, passthrough limited to GET /v1/prices" : `UNEXPECTED passthrough ${JSON.stringify(s.stub.unexpectedPassthrough)}`}`);
      const routes = Object.entries(s.stub.byRoute);
      if (routes.length) lines.push(`Stub routes: ${routes.map(([k, v]) => `${k} x${v}`).join("; ")}`);
    }
    if (s.missing.length) lines.push("", `Missing data: ${s.missing.join("; ")}`);
    lines.push("");
  }
  return lines;
}
