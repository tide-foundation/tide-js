# tide-load-harness

Load-test harness for the Tide network. Lives inside `tide-js` so it can
import `@tideorg/js` via a relative `file:..` dependency without the
file-dep round-trip pain. The harness exposes a tiny Express server that
Locust hammers from the same machine; the server reuses real tide-js
protocol code to drive ORK traffic, so what Locust measures is what a
real client would experience.

## v1 scope

- Scaffolding only. The "real" pieces (Playwright warm-up of staging
  users, runSign() wiring against the live tide-js API) are explicitly
  TODO and gated on runtime confirmation of a few serialization
  signatures — see "Known unknowns" below.
- See the orchestrator-level `LOAD-TESTING.md` (when it lands) for the
  full design and the rationale for the Locust-on-Azure-Load-Testing
  shape.

## Quickstart (local dev)

From `tide-js/load-harness/`:

```bash
npm install
npm run build

# 1. Start the harness server (also hosts the OIDC /callback route the
#    warm-up needs). Default realm = tide-metrics-load on staging.
npm start                              # http://localhost:3000

# 2. Prepare the list of pre-enrolled test users.
cp load-test-users-sample.json load-test-users.json
$EDITOR load-test-users.json           # add / adjust { userId, password }

# 3. Run the warm-up. Spawns a Chromium per user, drives the SWE login,
#    and writes ./fixtures.json. Use WARMUP_HEADLESS=false to watch.
npm run warmup

# 4. Point Locust at the now-warmed harness.
cd locust
pip install -r requirements.txt
locust -f locustfile.py -H http://localhost:3000
```

Sanity-check the server before pointing Locust at it:

```bash
curl http://localhost:3000/health
# → {"ok":true,"fixturesLoaded":5,"realmLoaded":"tide-metrics-load",...}
```

### Warm-up env

| Var | Default | Meaning |
|---|---|---|
| `HARNESS_URL` | `http://localhost:3000` | Harness server origin to talk to |
| `LOAD_TEST_USERS_PATH` | `./load-test-users.json` | JSON `{users:[{userId,password}]}` |
| `FIXTURES_OUT_PATH` | `./fixtures.json` | Atomic write target |
| `WARMUP_HEADLESS` | `true` | `false` to launch visible Chromium |
| `WARMUP_HOME_ORK` | `https://sork1.tideprotocol.com` | Home ORK for `/Network/Authentication/Node/Some` |

If a single user's OIDC capture fails (bad creds, captcha, timeout) the
warm-up logs and skips it but keeps going. The driver exits 1 only if
zero users were captured or realm config was missing; otherwise 0.

## Load test (Option F — login-flow load driver)

Drives N concurrent OIDC logins continuously for a fixed duration and
emits per-iteration latency JSONL + a trailing summary. No fixture is
written; this is purely a latency/throughput probe of the SWE → CMK →
broker → token-exchange chain.

The harness server must already be running (the load driver hits its
`/warmup/oidc/begin` + `/warmup/oidc/await` endpoints exactly like the
warm-up does).

```bash
# 1. Start the harness server pointed at the load-test realm.
cd tide-js/load-harness
PORT=3000 \
  TIDECLOAK_BASE_URL=https://staging.dauth.me \
  TIDECLOAK_REALM=tide-metrics-load \
  OIDC_CLIENT_ID=tide-loadtest-harness \
  npm start &

# 2. Run the load test. Defaults: 10 VUs, 30s ramp, 120s steady.
CONCURRENCY=10 RAMP_S=30 DURATION_S=120 \
  RESULTS_PATH=./loadtest-results.jsonl \
  npm run loadtest

# 3. Inspect output.
wc -l loadtest-results.jsonl
# Trailing summary block is also printed to stdout as `{ "summary": ... }`.
```

### Load-test env

| Var | Default | Meaning |
|---|---|---|
| `HARNESS_URL` | `http://localhost:3000` | Harness server origin (must match the one you started) |
| `LOAD_TEST_USERS_PATH` | `./load-test-users.json` | Same file the warm-up reads |
| `CONCURRENCY` | `10` | Max parallel BrowserContexts (= logical VUs) |
| `RAMP_S` | `30` | Seconds to ramp from 1 to CONCURRENCY VUs |
| `DURATION_S` | `120` | Seconds to run flat at CONCURRENCY after ramp |
| `RESULTS_PATH` | `./loadtest-results.json` | JSONL output path |
| `LOADTEST_HEADLESS` | `true` | `false` to launch visible Chromium |
| `WARMUP_HOME_ORK` | `https://sork1.tideprotocol.com` | Used only for fail-fast realm bootstrap |

### Output schema

Each JSONL row:
```json
{"ts":"2026-06-02T12:34:56.789Z","vu":7,"iter":3,"userId":"metrics-load-001",
 "ok":true,
 "phases":{"oidc_begin_ms":12,"nav_to_swe_ms":800,"swe_form_fill_ms":350,
           "swe_sign_in_click_ms":50,"wait_for_callback_ms":4200,
           "oidc_await_ms":30,"total_ms":5442}}
```

On completion the driver prints a `{"summary":{...}}` block with
`successCount`, `failureCount`, `successRate`, `peakConcurrency`, and
`total_ms` p50/p90/p95/p99/min/max/mean across successful iterations,
plus `failuresByPhase` so you can see whether failures are at
`wait_for_callback_ms` (SWE flakes) vs `oidc_begin_ms` (harness/server
issues) vs anywhere else.

### Concurrency ceiling

A single Playwright Chromium process can comfortably host ~10–20
BrowserContexts as logical VUs. Each context is a fresh cookie jar and
shares no state with siblings. Going beyond ~20 VUs in one Node process
is not recommended — spawn multiple Node processes if you need more
concurrency.

The SWE login form selectors are at the top of
`src/warmup/oidc.ts` (`SWE_SELECTORS`). They are marked
`VERIFY ON FIRST RUN` and may need adjustment after the first successful
flow against the live SWE.

## Fixture schema

`fixtures.json` (produced by warm-up, consumed by both the server and
the Locust task):

```ts
interface UserFixture {
  userId: string;
  vuid: string;
  doken: string;            // serialized Doken (format TBD — see warmup)
  sessKey: string;          // serialized TideKey (format TBD — see warmup)
  vvkid: string;
  vvkPublic: string;        // base64-encoded Point
  orks: Array<{
    orkID: string;
    orkURL: string;
    orkPublic: string;
    orkPaymentPublic: string;
  }>;
  voucherURL: string;
  homeOrkUrl: string;
}

interface FixturesFile {
  schemaVersion: "1";
  realm: string;
  createdAt: string;
  users: UserFixture[];
}
```

## TODOs (v1.1+)

- [ ] **Playwright warm-up flow** (`src/warmup/index.ts`) — drive the
      real SWE sign-up + login against staging. Iterative work with QA.
- [ ] **runSign() tide-js wiring** (`src/runSign.ts`) — reconstruct
      Doken / TideKey / OrkInfo from the fixture's serialized fields,
      build `AuthorizedSigningFlow`, call `signv2()`. Blocked on the
      serialization-format unknowns below.
- [ ] **ALT pipeline integration** — wire this harness into the Azure
      Load Testing engine init script so the server starts before
      Locust spawns.
- [ ] **Workspace integration** — promote `load-harness/` to an npm
      workspace of the root tide-js package when stable.

## Known unknowns (carried forward from Phase 1)

- **Doken serialization format.** `Models.Doken` is the in-memory shape;
  the on-wire / on-storage encoding needs to be confirmed via runtime
  inspection during the first successful warm-up run. The fixture stores
  it as an opaque string today.
- **sessKey serialization format.** Same story for `Cryptide.TideKey`.
  Inspect `localStorage` / the SWE postMessage payload during a real
  login to lock down the format.
