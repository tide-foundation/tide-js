//
// One-time global undici dispatcher install.
//
// We deliberately install ONE shared Agent at module load so every
// `fetch(...)` issued by the protocol module (Fetch 1, ORK fan-out in
// R4, Fetch 2) reuses the same connection pool. With 1000-10000 VUs
// hammering a small number of origins (TideCloak + 5-ish ORKs), per-VU
// `new Agent()` would (a) blow up FD usage and (b) defeat keep-alive.
//
// Pool sizing rationale:
//   - connections: 256 per origin. The hot origin is TideCloak (Fetch 1
//     + Fetch 2 both hit it). 256 gives headroom above the operational
//     CONCURRENCY=200 target without leaning on autoscaling.
//   - pipelining: 1 — Keycloak/Wildfly does NOT support HTTP/1.1
//     pipelining; setting >1 produces correctness bugs (response
//     interleaving). Keep at 1.
//   - keepAliveTimeout: 30s — comfortably above the SWE URL params'
//     KC_AUTH_SESSION_HASH cookie Max-Age (60s, but only one Fetch 2
//     per iteration uses it).
//
// Call `installGlobalDispatcher()` ONCE at entry-point boot. It is
// idempotent — repeated calls just reinstall the same Agent.
//
import { Agent, setGlobalDispatcher } from "undici";

let installed = false;

export function installGlobalDispatcher(): void {
  if (installed) return;
  const agent = new Agent({
    connections:        256,
    pipelining:         1,
    keepAliveTimeout:   30_000,
    keepAliveMaxTimeout: 30_000,
  });
  setGlobalDispatcher(agent);
  installed = true;
}

// Auto-install on import — keeps the call-sites cheap (a single
// `import "./undici-setup.js"` in cli.ts / nodeCmkClient.ts is enough).
installGlobalDispatcher();
