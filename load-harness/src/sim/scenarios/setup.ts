// S3 workspace setup: create a realm, then setUpTideRealm (free tier) the way the console does,
// including its Retry after a failure, which is how VENDOR_ALREADY_CREATED shows up.

import type { AdminClient, HttpResult } from "../admin.js";
import type { OpOutcome } from "../engine.js";
import type { ManifestWriter } from "../sink.js";
import { matchSignatures } from "../signatures.js";
import { sleep } from "../util.js";

export interface SetupOpts {
  admin: AdminClient;
  manifest: ManifestWriter;
  runId: string;
  emailDomain: string;
  retries: number;        // extra attempts after the first, like pressing Retry in the console
  retryDelayMs: number;
  realmPrefix: string;    // "lt-ws" for S3, "lt-pool" for prepare-realms
  purpose: "pool" | "s3-setup";
}

export function setupNames(o: Pick<SetupOpts, "runId" | "emailDomain" | "realmPrefix">, n: number): { realm: string; email: string } {
  return {
    realm: `${o.realmPrefix}-${o.runId}-${n}`,
    email: `lt-${o.runId}-${o.realmPrefix.replace(/^lt-/, "")}${n}@${o.emailDomain}`,
  };
}

// Pull a Tide error code out of a response body, if there is one.
export function errorCode(r: HttpResult): string {
  const m = /"code"\s*:\s*"([A-Z0-9_\-]+)"/.exec(r.text) ?? /(TIDE-[A-Z0-9_\-]+)/.exec(r.text);
  if (m) return m[1];
  return `HTTP_${r.status}`;
}

export async function setupOnce(o: SetupOpts, n: number): Promise<OpOutcome> {
  const { realm, email } = setupNames(o, n);
  const phases: Record<string, number> = {};
  const trail: string[] = [];
  o.manifest.upsertRealm({ realm, email, status: "created", purpose: o.purpose, createdAt: new Date().toISOString() });

  const t0 = Date.now();
  let created: HttpResult;
  try {
    created = await o.admin.createRealm(realm);
  } catch (e) {
    o.manifest.upsertRealm({ realm, email, status: "setup-failed", purpose: o.purpose, createdAt: new Date().toISOString(), error: "create realm request failed" });
    return { ok: false, code: "CREATE_REALM_NET", message: (e as Error).message, phases };
  }
  phases.create_realm_ms = Date.now() - t0;
  if (created.status !== 201) {
    o.manifest.upsertRealm({ realm, email, status: "setup-failed", purpose: o.purpose, createdAt: new Date().toISOString(), error: `create realm HTTP ${created.status}` });
    return { ok: false, code: `CREATE_REALM_${created.status}`, status: created.status, message: `create realm HTTP ${created.status}: ${created.text.slice(0, 300)}`, phases };
  }

  let last: HttpResult | null = null;
  let lastErr = "";
  const s0 = Date.now();
  for (let attempt = 0; attempt <= o.retries; attempt++) {
    if (attempt > 0) await sleep(o.retryDelayMs);
    const a0 = Date.now();
    try {
      last = await o.admin.setUpTideRealm(realm, email);
    } catch (e) {
      lastErr = (e as Error).message;
      trail.push(`NET`);
      continue;
    }
    phases[`setup_attempt${attempt + 1}_ms`] = Date.now() - a0;
    const body = last.text.trim();
    if (last.status === 200 && /CREATED/.test(body)) {
      trail.push("CREATED");
      break;
    }
    trail.push(last.status === 200 ? body.slice(0, 40) : errorCode(last));
    // Payment-gated answers will not change on retry for a free-tier realm.
    if (last.status === 303 || /NEED_PAYMENT/.test(body)) break;
  }
  phases.setup_ms = Date.now() - s0;

  const ok = !!last && last.status === 200 && /CREATED/.test(last.text);
  const extra: Record<string, unknown> = { realm, attempts: trail.length, trail };
  let billing: { customerId?: string; subscriptionId?: string } = {};
  try { billing = await o.admin.billingIds(realm); } catch { /* best effort */ }
  o.manifest.upsertRealm({
    realm, email, purpose: o.purpose, createdAt: new Date().toISOString(),
    status: ok ? "setup-ok" : "setup-failed",
    ...billing,
    error: ok ? undefined : trail.join(" > "),
  });
  if (ok) return { ok: true, phases, extra };

  const text = last ? `HTTP ${last.status} ${last.text.slice(0, 400)}` : lastErr;
  // Report the most specific code seen across attempts.
  const sigs = matchSignatures(trail.join(" ") + " " + text).map((s) => s.id);
  let code = sigs.includes("VENDOR_ALREADY_CREATED") ? "VENDOR_ALREADY_CREATED" : last ? (last.status === 303 || /NEED_PAYMENT/.test(last.text) ? "SETUP_NEEDS_PAYMENT" : errorCode(last)) : "SETUP_NET";
  if (trail.length > 1 && code !== "VENDOR_ALREADY_CREATED") code = `${code}_AFTER_RETRY`;
  return { ok: false, code, status: last?.status, message: `trail=${trail.join(">")} last=${text}`, phases, extra };
}
