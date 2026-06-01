//
// Sign-iteration driver for the load harness.
//
// Each call to runSign() should perform exactly one
// AuthorizedSigningFlow.signv2() against the live ORK network, using
// the credentials baked into the UserFixture by the Playwright warm-up
// pass. Locust calls this once per VU per task.
//
// The body is a clearly-marked TODO: the actual wiring needs the real
// tide-js (de)serialization signatures for Doken / TideKey / etc., which
// will be confirmed by the Main Agent against the live API in v1.1.
// The interface (UserFixture / RunResult) is the contract Locust and the
// warm-up agree on, so it stays stable even while the body changes.
//

// The following imports are intentional — they fix the v1.1 wiring
// surface and make `tsc` complain loudly the moment any of these export
// names drift in tide-js. The unused-import suppression is in tsconfig
// (`noUnusedLocals` not set), so this compiles clean today.
import {
  // @ts-expect-error TODO(v1.1): confirm Flow.SigningFlows export name
  Flow,
  // @ts-expect-error TODO(v1.1): confirm Models export shape for Doken / BaseTideRequest
  Models,
  // @ts-expect-error TODO(v1.1): confirm Cryptide.TideKey / Point export path
  Cryptide,
} from "@tideorg/js";

export interface UserFixture {
  userId: string;
  vuid: string;
  doken: string; // serialized Doken (format TBD — see warmup)
  sessKey: string; // serialized TideKey (format TBD — see warmup)
  vvkid: string;
  vvkPublic: string; // base64-encoded Point
  orks: Array<{
    orkID: string;
    orkURL: string;
    orkPublic: string;
    orkPaymentPublic: string;
  }>;
  voucherURL: string;
  homeOrkUrl: string;
}

export interface RunResult {
  ok: boolean;
  durationMs: number;
  requestCount?: number;
  code?: string;
  message?: string;
}

export async function runSign(f: UserFixture): Promise<RunResult> {
  const start = performance.now();
  try {
    // TODO(v1.1): implement against real tide-js API:
    //   1. Reconstruct tide-js types from the fixture's serialized fields:
    //        - Doken.fromString(f.doken)   (or whatever the deserializer is)
    //        - TideKey.deserialize(f.sessKey)
    //        - Point.fromBase64(f.vvkPublic)
    //        - OrkInfo[] from f.orks
    //   2. Build an AuthorizedSigningFlow(homeOrk, orks, doken, sessKey, ...).
    //   3. Build a BaseTideRequest for a fixed test JWT-shape claim payload
    //      (load test only — content doesn't matter, shape does).
    //   4. await flow.signv2(request, /*waitForAll*/ false);
    //   5. Return { ok: true, durationMs, requestCount: f.orks.length }.
    //
    // The skeleton intentionally throws so anyone running the harness
    // server before v1.1 wiring lands sees a clear error rather than a
    // silent success.
    void f;
    void Flow;
    void Models;
    void Cryptide;
    throw new Error(
      "TODO(v1.1): implement runSign once tide-js Doken.fromString + TideKey.deserialize signatures are confirmed by Main Agent",
    );
  } catch (e: any) {
    return {
      ok: false,
      durationMs: performance.now() - start,
      code: e?.code ?? "TIDE-HARNESS-UNKNOWN",
      message: String(e?.message ?? e),
    };
  }
}
