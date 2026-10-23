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

## Staging incident simulator (`dist/sim/cli.js`)

Replays the 2026-10-22 production surge shape against **staging only** and ramps each
scenario until it breaks. Scenarios:

| scenario | what one operation is | driven by |
|---|---|---|
| `setup` (S3) | create realm `lt-ws-<run>-<n>`, then `setUpTideRealm` (free tier), retrying like the console's Retry button | plain HTTP, master admin token |
| `signup` (S1) | a new Tide account through the real enclave sign-up, then the token exchange | Playwright, one Chromium, N contexts |
| `login` (S2) | a full enclave login (authorize, Tide sign-in, callback, token) | Playwright (default) or `--engine node` |
| `incident` (S5) | signup + login + setup together at `--incident-ratios` (default 1:10:0.05, the incident shape) | both |

The malformed-request crash repro is deliberately not included.

### Build

```bash
cd tide-js && npm ci && npm run build          # parent dist first (globalThis.crypto trap)
cd load-harness && npm install && npm run build
npx playwright install chromium                 # once per machine
npm test                                        # unit tests, no network
```

### Before a staging run

1. **Seats.** Staging realms are on Business v2, where free tier is 5 seats, so one realm
   caps sign-ups at 5. S1 spreads sign-ups round-robin over a realm list and skips a realm once
   it is full (5 seats counted locally, plus the server's `exceeded its total user count`
   refusal, reported as the expected `SEAT_CAP`). When every realm is full the run stops with
   "need more realms" so a pool limit is never read as staging breaking. The tool never raises
   capacity. Either prepare enough realms (below), pass your own with `--realms a,b,c`, or raise
   capacity by hand. `--dry-run` prints how many realms each step needs.
   Seats already used by earlier runs are not known up front; the tool finds out from the cap error.
2. **Stripe test mode.** Every realm setup creates a Stripe customer and subscription on the
   staging payers. Confirm the payers run a `sk_test_` key, then pass `--confirm-stripe-test`
   (required for `setup`, `prepare-realms` and `incident` with setups on staging).
3. **Admin password.** `export TC_ADMIN_PASSWORD=...` (master admin of the target TideCloak;
   `TC_ADMIN_USER` defaults to `admin`). Never printed or written to disk.
4. **Port 3000.** The OIDC client redirects to `http://localhost:3000/callback`. The browser
   reads the code from that request itself, so nothing needs to listen there, but keep the port
   free so no other local app sees the codes.
5. **Infra.** Leave staging as is. Record the pre-state for the report:

   ```bash
   az postgres flexible-server parameter show -g Tide-Staging --server-name dauthme-staging --name max_connections --query value -o tsv
   az containerapp show -n tidecloak-staging -g Tide-Staging --query '{scale: properties.template.scale, sticky: properties.configuration.ingress.stickySessions}' -o json
   for i in 1 2 3 4 5; do az containerapp show -n sork$i -g Tide-Staging --query '{name:name, cpu:properties.template.containers[0].resources.cpu, mem:properties.template.containers[0].resources.memory}' -o tsv; done
   ```

### Commands

Always look at the plan first: add `--dry-run` to any command. Nothing is sent.

```bash
# Realm pool for S1/S2 (runs sequentially by default; this is setup load, logged to prepare.log)
node dist/sim/cli.js prepare-realms --count 20 --target staging --confirm-stripe-test --dry-run
node dist/sim/cli.js prepare-realms --count 20 --target staging --confirm-stripe-test
#   -> runs/<poolRun>/realms.json  (only realms that passed every check, with seats left per realm)
#   --basic for the old IGA-off pool (RS256 tokens, no PreSign)

# S3 workspace-setup surge
node dist/sim/cli.js run --scenario setup --target staging --confirm-stripe-test \
  --start-rate 1/min --concurrency 4 --watch-restarts

# S1 sign-up surge across the pool
node dist/sim/cli.js run --scenario signup --target staging --realms-from <poolRun> \
  --start-rate 2/min --browser-pool 10 --watch-restarts

# S2 login surge using the users S1 created (plus an optional users file)
node dist/sim/cli.js run --scenario login --target staging --users-from <signupRun> \
  [--users-file ./load-test-users.json --realm tide-metrics-load] \
  --start-rate 15/min --browser-pool 10 [--refresh-ratio 2] --watch-restarts

# S5 incident mix (signups feed the login pool as they are created)
node dist/sim/cli.js run --scenario incident --target staging --realms-from <poolRun> \
  --users-from <signupRun> --confirm-stripe-test --start-rate 2/min --watch-restarts

# Afterwards
node dist/sim/cli.js report --run <runId>       # rebuild summary.md
node dist/sim/cli.js checklist --run <runId>    # manual cleanup list
```

`--target local` points everything at the local stack (`http://localhost:8080`, ORKs on
localhost / hostgateway) for a smoke test.

### What `prepare-realms` does

Default mode `--tide-full` gives the same realm a customer gets from the console setup wizard's
keygen block, so Tide users' tokens are minted through the ORKs (EdDSA, Key.PreSign). Per realm,
sequentially:

1. `POST /admin/realms`, then registration on and verifyEmail off (before setup, so the first
   signed IdP settings already carry RegOn).
2. `POST /admin/realms/<r>/vendorResources/setUpTideRealm` (FreeTier, tagged email). Synchronous:
   tide IdP, tide-vendor-key, VRK, wallet, Stripe test subscription.
3. `GET .../vendorResources/getSubscriptionStatus` must be active ("upcoming renewal").
4. Realm attribute `iga.attestor=tide` (without it IGA runs Tideless and users get quarantined).
5. `link-tide-account-action` registered if missing (`POST .../authentication/register-required-action`).
6. Harness client `tide-loadtest-harness` (public, PKCE S256, redirect `http://localhost:3000/callback`),
   created while IGA is still off.
7. `POST .../vendorResources/sign-idp-settings`.
8. `POST .../tide-admin/toggle-iga` (form `isIGAEnabled=true`; it flips, so only called when IGA is off).
   Synchronous: sets EdDSA and the tide attestor, runs the ADOPT scan and the firstAdmin
   sign-defaults sweep.
9. Approve every PENDING change request (`POST .../iga/change-requests/<id>/approve`) until none are
   left. The realm stays in firstAdmin mode (no tide-realm-admin is granted), so each approval is
   a plain admin call; nothing needs the enclave.
10. `sign-idp-settings` again.
11. Verify: IGA on, attestor tide, default algorithm EdDSA, the Tide sign-up screen renders, and a
    probe sign-up plus a probe login both return an access token with header `alg` EdDSA.

Only realms that pass every step are listed as ready. Per-step timings and failures go to
`prepare.log`. `--basic` skips steps 4, 5, 8 to 10 and the probe (IGA off, RS256 tokens).

**EdDSA check during load runs.** Users created on a `--tide-full` realm are marked in
`users.secret.json`. If one of their sign-up, login or refresh tokens comes back RS256, the
operation fails with `NOT_TIDE_SIGNED`, which counts as a break signature. For your own realms or
users files, add `--expect-eddsa` to apply the same check.

### Ramp, knee, break, abort

- Open-loop arrivals (Poisson by default, `--arrival uniform` for fixed gaps) at the step's target
  rate. Each arrival takes a free browser context (or HTTP slot) or queues; queue wait is recorded
  separately so a busy client never looks like a slow server.
- Steps: `--step-duration 5m`, `--cooldown 2m`, doubling (`--step-factor 2`, or `--step-add 2/min`),
  up to `--max-steps 8` / `--max-rate`. In-flight work drains (`--drain 5m`) before a step is judged.
- **Knee**: p95 above 2x the first step's p95 (`--knee-p95-mult`), or fewer than 90% of arrivals
  finished inside the step (`--knee-throughput`). The ramp continues.
- **Break**: error rate above 5% (`--break-error-rate`) or any server failure signature (SQLite
  locked, VENDOR_ALREADY_CREATED, could not find uid, statement timeout, keygen failed, gateway
  errors, not enough ORKs). One confirmation step at the last good rate follows, then the run stops.
- **Client-bound**: client CPU above 85% (`--client-cpu`, machine-wide, Chromium included), queue
  wait p95 above 2 s (`--client-queue-wait`), or arrivals dropped because the queue is full
  (`--max-queue`, default 4x the pool). The run stops and says the load machine is the limit.
- **Hard abort**: rolling 30 s error rate above 20% (`--abort-error-rate`); any ORK restart with
  `--watch-restarts` (read-only `az containerapp replica list` every 60 s); ORK outbound error rate
  above `--prom-error-threshold` (default 0.5/s) with `--watch-prom`; any browser request to a
  production host; Ctrl-C. Expected outcomes (seat cap, empty pools) never count as errors.

### Output (`runs/<runId>/`, gitignored)

- `events.jsonl`: one row per operation: op, step, target rate, ok, code, failure signatures,
  queue wait, latency, phases (sign-up: `enclave_load`, `signup_form`, `email_step`, `keygen_wait`,
  `fbl_submit`, `token_ms`; login: `enclave_load`, `sign_in_to_callback`, `token_ms`; setup:
  `create_realm_ms`, `setup_attemptN_ms`), token `alg`.
- `steps.jsonl` and `summary.md` / `summary.json`: per-step table, verdicts with reasons, the
  ceiling per op (last ok, knee, break, client-bound rates), signature and code totals, client
  CPU/queue, and ready-to-paste KQL (`ContainerAppConsoleLogs_CL`, `ContainerAppSystemLogs_CL`) and
  PromQL for the UTC window.
- `manifest.json`: every realm created (with Stripe customer/subscription ids when readable), every
  user id attempted, the test email pattern. `users.secret.json` (mode 0600) holds passwords for
  created users, for later login runs. `sim.log` / `prepare.log`.
- The cleanup checklist is printed at the end of every run. **Cleanup is manual**: delete the
  realms, cancel/delete the Stripe test customers, optionally remove payer rows. Tide accounts on
  the ORKs have no delete path.

### Safety

- Only `staging.dauth.me` and `sork*.tideprotocol.com` (or localhost for `--target local`) can be
  configured. `login.dauth.me` and `ork*.tideprotocol.com` are refused at startup and blocked in
  the browser (a hit aborts the run). Other unexpected hosts the enclave loads (fonts) are allowed
  and logged once.
- Fresh ids every run: users `lt-<runId>-<n>`, realms `lt-pool-<runId>-<n>` / `lt-ws-<runId>-<n>`,
  emails `lt-<runId>-...@invalid.tide.test`. No index is ever reused, so stale ORK reservations
  from failed attempts cannot collide.
- No infra changes. The az calls are read-only and opt-in.

### Known limits

- **Seat use.** A `--tide-full` realm spends one seat on its probe user, so 4 of 5 are left for
  load; `realms.json` records the seats left per realm and S1 uses that.
- `--engine node` (browserless cmkOnly login) is kept for higher rates later; it stops at the
  OIDC code and is untested in this simulator.
- One Chromium per process. Past roughly 10 to 20 contexts the client CPU usually becomes the
  limit; the run will say so. Run several processes or machines for more.
