//
// Boot-time shims for running tide-js inside Node.
//
// IMPORTANT: this module must be imported FIRST in every entry point
// (server.ts, warmup/index.ts) — before any `@tideorg/js` import — so the
// globals it installs are visible when tide-js modules execute their
// top-level code.
//
import { webcrypto } from "node:crypto";

// tide-js uses globalThis.crypto.* in its source (post-polyfill).
// Node 19+ already has globalThis.crypto, but pre-19 does not; this
// guarantees the global is present regardless of host version.
if (!globalThis.crypto) {
  (globalThis as any).crypto = webcrypto;
}

// tide-js Tools/Utils.ts CurrentTime() reads timeSkew from
// globalThis.localStorage if defined; otherwise it returns 0-skew.
// We don't need a real store — the Tide protocol doesn't care about
// clock skew during a load test against a single staging endpoint.
// (Intentional no-op shim; leave globalThis.localStorage undefined.)
