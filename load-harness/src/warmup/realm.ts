//
// Realm-config bootstrap for the warm-up.
//
// Captures the RealmFixture (vvkid, vvkPublic, voucherURL, homeOrkUrl,
// orks[]) once per warm-up — these are realm-level, identical for every
// user, and don't require any per-user authentication.
//
// Strategy (Round-5 corrected — see brief):
//   1. orks[]:    fetch <homeOrkUrl>/Network/Authentication/Node/Some.
//                 The endpoint returns a BARE JSON array (not wrapped)
//                 of objects with lowercase camelCase fields:
//                   { id, index, publicKey, paymentPublicKey, url }
//                 We map id→orkID, url→orkURL, publicKey→orkPublic,
//                 paymentPublicKey→orkPaymentPublic. `index` is the
//                 cohort position and unused by v1. An empty array on
//                 a 200 is still an error (cohort=0 is wrong).
//   2. vvkid + vvkPublic: do NOT fetch. The Keycloak realm-keys path
//                 (/realms/{r}/keys) is an admin endpoint (404 unauth)
//                 and the public JWKS at
//                 /protocol/openid-connect/certs lists Keycloak's
//                 token-signing keys — the tide-vendor-key is a Tide-
//                 specific realm component and does NOT appear there.
//                 So we initialise both from the operator-supplied
//                 fallback (env WARMUP_VVKID_FALLBACK / fixture sample)
//                 as a placeholder. Path α (oidc.ts onSweUrl) is the
//                 canonical post-first-login source.
//   3. voucherURL: synthesise the pattern from <tcBase> + realm — the
//                 per-session sessionId / tabId placeholders are baked
//                 by runSign() at iteration time, so the pattern lives
//                 in the fixture as a template string. Path α also
//                 backfills the realm-stable clientId post-first-login.
//   4. homeOrkUrl: from configuration (env or default), never sniffed.
//
// Bootstrap success contract (Round-5):
//   * MUST abort if the live ORK fetch fails or returns 0 orks.
//   * MUST NOT abort if vvkid is the fallback placeholder — Path α is
//     expected to patch it from the first SWE URL. The warm-up driver
//     (index.ts) is responsible for verifying Path α actually fired by
//     the end of the loop.
//
// Path α (browser-sniff `gVVK=…&voucherURL=…` from the first user's SWE
// URL) is implemented inside oidc.ts as an opportunistic fill-in for
// fields that are still placeholder values after the bootstrap runs.
//

import type { RealmFixture, OrkInfo } from "../runSign.js";

// fetch() lives on globalThis in Node 18+. We type it explicitly so a
// stale @types/node can't paper over an environment that lacks it.
declare const fetch: typeof globalThis.fetch;

// Subset of the shape returned by sork1.tideprotocol.com's
// /Network/Authentication/Node/Some. As of 2026-06-02 staging the
// endpoint returns a bare array whose entries use lowercase camelCase
// names: { id, index, publicKey, paymentPublicKey, url }. We also keep
// the PascalCase aliases as a tolerant fall-through for older ORK builds
// or a future serializer flip — but the PRIMARY path is camelCase.
interface OrkInfoWire {
  // Round-5 confirmed wire names (camelCase, .NET System.Text.Json
  // default with JsonNamingPolicy.CamelCase):
  id?:               string;
  url?:              string;
  publicKey?:        string;
  paymentPublicKey?: string;
  index?:            number;
  // Tolerated PascalCase aliases (older serializer style):
  Id?:               string;
  Url?:              string;
  PublicKey?:        string;
  PaymentPublicKey?: string;
  // Tolerated previously-assumed shapes (kept so a hypothetical
  // serializer flip back to the OrkInfo-named fields doesn't silently
  // break us):
  orkID?:            string;
  OrkID?:            string;
  orkURL?:           string;
  OrkURL?:           string;
  orkPublic?:        string;
  OrkPublic?:        string;
  orkPaymentPublic?: string;
  OrkPaymentPublic?: string;
}

export interface RealmBootstrapOptions {
  tcBase:        string;
  tcRealm:       string;
  homeOrkUrl:    string;
  // If a leg fails (or in the vvk case, by design), we use these. Pass
  // `null` to opt out (CI mode — fail loudly on any missing field).
  fallback?:     Partial<RealmFixture> | null;
  fetchTimeoutMs?: number;
}

// Round-5: pathUsed is now a short descriptive string assembled at the
// call-site rather than a fixed enum. It encodes both the ORK source
// (live | fallback) and the vvk source (fallback | path-α-pending) and
// the voucher source (fallback | path-α-pending). The caller logs it
// verbatim to stdout so the operator can audit Path α success per run.
export interface RealmBootstrapResult {
  realm:    RealmFixture;
  pathUsed: string;
  notes:    string[];
  // True if vvkid was the operator-supplied fallback at bootstrap time —
  // means index.ts MUST verify Path α actually fired (Path α patches it
  // in place on the realm fixture). If still fallback at warm-up end,
  // log a WARN; the doken is still valid but the fixture's vvkid won't
  // match what the SWE actually used for the cohort, which is wrong.
  vvkidFromFallback:      boolean;
  voucherUrlFromFallback: boolean;
}

const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

function pickStr(raw: OrkInfoWire, names: readonly (keyof OrkInfoWire)[]): string {
  for (const n of names) {
    const v = raw[n];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return "";
}

function normaliseOrk(raw: OrkInfoWire): OrkInfo | null {
  // Preference order: camelCase live wire (Round-5 confirmed) →
  // PascalCase variant → the older Ork-prefixed shapes the previous
  // code knew about.
  const ork: OrkInfo = {
    orkID:            pickStr(raw, ["id", "Id", "orkID", "OrkID"]),
    orkURL:           pickStr(raw, ["url", "Url", "orkURL", "OrkURL"]),
    orkPublic:        pickStr(raw, ["publicKey", "PublicKey", "orkPublic", "OrkPublic"]),
    orkPaymentPublic: pickStr(raw, ["paymentPublicKey", "PaymentPublicKey", "orkPaymentPublic", "OrkPaymentPublic"]),
  };
  if (!ork.orkID || !ork.orkURL) return null;
  return ork;
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// GET <homeOrkUrl>/Network/Authentication/Node/Some
//
// The endpoint returns a BARE JSON array (no wrapper object). We treat
// the bare-array shape as the canonical primary path. If a future ORK
// build wraps the array in { orks: [...] }, we tolerate that as a
// fall-through purely for forward-compat — but a populated bare array
// from an HTTP 200 is what we currently expect.
async function fetchOrks(homeOrkUrl: string, timeoutMs: number): Promise<OrkInfo[]> {
  const base = homeOrkUrl.replace(/\/+$/, "");
  const url = `${base}/Network/Authentication/Node/Some`;
  const res = await fetchWithTimeout(url, timeoutMs);
  if (!res.ok) {
    throw new Error(`orks endpoint ${res.status} ${res.statusText} at ${url}`);
  }
  const body = (await res.json()) as unknown;
  // Primary path: bare array (live wire shape on staging as of 2026-06-02).
  // Fall-through: an object that wraps the array under .orks / .Orks / .nodes.
  let arr: unknown[] | null = null;
  if (Array.isArray(body)) {
    arr = body;
  } else if (body && typeof body === "object") {
    const obj = body as Record<string, unknown>;
    for (const k of ["orks", "Orks", "nodes", "Nodes"]) {
      if (Array.isArray(obj[k])) {
        arr = obj[k] as unknown[];
        break;
      }
    }
  }
  if (!arr) {
    throw new Error(`orks endpoint returned non-array body at ${url}`);
  }
  const orks = arr
    .map((raw) => normaliseOrk(raw as OrkInfoWire))
    .filter((o): o is OrkInfo => o !== null);
  if (orks.length === 0) {
    // Empty cohort from a 200 is wrong — abort. The brief is explicit
    // that even an empty 200 must fail bootstrap.
    throw new Error(`orks endpoint returned 0 orks at ${url}`);
  }
  return orks;
}

function buildVoucherUrlPattern(tcBase: string, tcRealm: string): string {
  // The clientId query param on the voucher URL is realm-stable; we
  // don't have it here unless we go through an OIDC roundtrip, so we
  // emit just the path with sessionId/tabId placeholders. runSign()
  // will need to bake clientId as well at iteration time, OR Path α in
  // oidc.ts can sniff it from the first SWE URL and patch this field.
  const base = tcBase.replace(/\/+$/, "");
  return (
    `${base}/realms/${encodeURIComponent(tcRealm)}` +
    `/tidevouchers/fromAuthSession?sessionId=<PER_SESSION>&tabId=<PER_TAB>&clientId=<PER_REALM>`
  );
}

export async function bootstrapRealmFixture(
  opts: RealmBootstrapOptions,
): Promise<RealmBootstrapResult> {
  const timeoutMs = opts.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const notes: string[] = [];
  const fb = opts.fallback ?? null;

  // 1. ORK fetch — REQUIRED. Bootstrap aborts on any failure here.
  let orks: OrkInfo[] | null = null;
  let orksLive = false;
  try {
    orks = await fetchOrks(opts.homeOrkUrl, timeoutMs);
    orksLive = true;
    notes.push(
      `orks: fetched ${orks.length} via ${opts.homeOrkUrl}/Network/Authentication/Node/Some`,
    );
  } catch (e) {
    notes.push(`orks: live fetch failed (${(e as Error).message})`);
  }
  if (!orks) {
    // Fallback ORKs only kick in if the live fetch genuinely failed
    // (network outage / 5xx). This is the LAST resort; the brief is
    // clear that 0-orks is a hard fail, but if the operator supplied
    // a fallback for offline-CI we'll use it.
    const fbOrks = fb?.orks;
    if (Array.isArray(fbOrks) && fbOrks.length > 0) {
      orks = fbOrks;
      notes.push(`orks: using fallback (${fbOrks.length} orks)`);
    }
  }
  if (!orks) {
    throw new Error(
      `realm bootstrap failed: orks MISSING (notes: ${notes.join("; ")})`,
    );
  }

  // 2. vvkid + vvkPublic — placeholder by design. The Keycloak admin
  //    realm-keys path requires auth (404 unauth) and the public JWKS
  //    does not contain the tide-vendor-key. Path α (oidc.ts onSweUrl)
  //    is the canonical source post-first-login. We seed with the
  //    operator fallback (env override → fixture sample) so the warm-up
  //    can proceed even before any user has logged in.
  const envVvkid = (process.env.WARMUP_VVKID_FALLBACK ?? "").trim();
  const envVvkPub = (process.env.WARMUP_VVKPUBLIC_FALLBACK ?? "").trim() || envVvkid;
  let vvkid = "";
  let vvkPublic = "";
  let vvkidFromFallback = true;
  if (envVvkid) {
    vvkid = envVvkid;
    vvkPublic = envVvkPub;
    notes.push(`vvk: seeded from WARMUP_VVKID_FALLBACK (vvkid=${vvkid.slice(0, 12)}…)`);
  } else if (fb?.vvkid && fb?.vvkPublic) {
    vvkid = fb.vvkid;
    vvkPublic = fb.vvkPublic;
    notes.push(`vvk: seeded from fallback (vvkid=${vvkid.slice(0, 12)}…) — Path α will patch from first SWE URL`);
  } else {
    // No fallback at all. We still don't abort — Path α may fill it in.
    // But warn loudly so the operator notices.
    notes.push(`vvk: NO fallback supplied; vvkid empty until Path α patches it`);
    vvkidFromFallback = false; // not technically fallback, just empty
  }

  // 3. voucherURL — same story: fallback first, Path α patches.
  let voucherUrlFromFallback = false;
  let voucherURL: string;
  if (typeof fb?.voucherURL === "string" && fb.voucherURL.length > 0) {
    voucherURL = fb.voucherURL;
    voucherUrlFromFallback = true;
    notes.push(`voucherURL: seeded from fallback — Path α will patch realm-specific clientId`);
  } else {
    voucherURL = buildVoucherUrlPattern(opts.tcBase, opts.tcRealm);
    notes.push(`voucherURL: synthesised pattern from tcBase+realm — Path α will patch from first SWE URL`);
  }

  const realm: RealmFixture = {
    realm:      opts.tcRealm,
    vvkid,
    vvkPublic,
    voucherURL,
    homeOrkUrl: opts.homeOrkUrl,
    orks,
  };

  // Compose a descriptive pathUsed marker. Format matches Round-5 brief:
  //   beta-orks+(live|fallback)+vvk+(fallback|empty)+voucher+(fallback|synth)
  const orksTag    = orksLive ? "live" : "fallback";
  const vvkTag     = vvkid ? "fallback" : "empty";
  const voucherTag = voucherUrlFromFallback ? "fallback" : "synth";
  const pathUsed = `beta-orks=${orksTag}+vvk=${vvkTag}+voucher=${voucherTag}`;

  return { realm, pathUsed, notes, vvkidFromFallback, voucherUrlFromFallback };
}
