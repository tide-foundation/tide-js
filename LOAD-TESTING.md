# Load-Testing Initiative — Design & Reference

> **Status (2026-06-01):** v1 scaffolding committed on `agent/load-test-v1` in both repos. Two iterative wiring tasks remain before first run; staging redeploy required for the OTel collector scale-up.
> **Snapshot branches:** `agent/load-test-v1` in [`tide-js`](https://github.com/tide-foundation/tide-js/tree/agent/load-test-v1) and [`tidecloak-override`](https://github.com/tide-foundation/tidecloak-override/tree/agent/load-test-v1).

---

## 1. Goals

With the metrics dashboard ([METRICS-INITIATIVE.md](./METRICS-INITIATIVE.md)) and SWE error-reporting ([SWE-ERROR-REPORTING.md](./SWE-ERROR-REPORTING.md)) in place, we can finally **observe** the Tide network under stress. Goal: find the first hard bottleneck.

Concretely:
1. Drive a **mixed realistic workload** against Azure staging (heavy on Sign; sign-up + login implicit in the warm-up).
2. Use **Azure Load Testing** as the orchestrator (Locust scripts running on Azure-managed engines).
3. Drive the actual Tide protocol — threshold ORK fan-out, encrypted request bodies, real DH-derived per-ORK keys — not synthetic HTTP. The signal is only as good as the protocol-fidelity of the load.
4. **Find the breaking point**: ramp until p95 latency 5× baseline OR error rate > 5% OR a service falls over. Document the first wall + the next-priority bottleneck.

---

## 2. Architecture (Option D — Playwright warm-up + tide-js Sign load)

The fundamental constraint identified in Phase 1: the CMK login + key-generation flows live in the **ORK SWE Enclave** (`ork/Ork/Ork/Enclave/js/Flows/...`), NOT in `tide-js`. `@tideorg/js` exposes vendor-side primitives (`AuthorizedSigningFlow`, `dVVKSigningFlow`, `dVVKSigningFlow2Step`) but not CMK/keygen. So we split the test in two phases:

```
┌──────────────────── ONE-TIME PREREQS ──────────────────────────┐
│ • tide-js polyfill fixes (C1/C2/C4 — Node Web Crypto path)     │
│ • OTel collector autoscale (HTTP-concurrency KEDA rule)        │
│ • Schedule staging downtime window                             │
│ • Verify Postgres max_connections on dauthme-staging           │
└─────────────────────────────────────────────────────────────────┘

┌─────────── WARM-UP (Playwright, runs locally once) ────────────┐
│  For N test users on tide-metrics-load realm:                  │
│    1. Sign-up via the SWE (real CMK keygen → master SubmitUser)│
│    2. Login via the SWE → capture Doken + sessKey              │
│    3. Persist per-user fixture:                                │
│         { userId, vuid, doken, sessKey, vvkid, vvkPublic,      │
│           orks[], voucherURL }                                 │
│  Output: load-harness/fixtures.json (~50 KB)                   │
└─────────────────────────────────────────────────────────────────┘

┌────────── LOAD (Locust on Azure Load Testing engines) ─────────┐
│  Each engine ALSO runs the Node tide-harness server on :3000   │
│  Locust task → POST /run/sign { fixture } →                    │
│  Express → runSign() → tide-js AuthorizedSigningFlow.signv2()  │
│  → 2N ORK requests fan-out, real protocol traffic              │
│  → Locust collects latency + error rate                        │
│                                                                │
│  Ramp: 1 → 100 VU over 10 min; hold 5 min; cooldown 5 min      │
└─────────────────────────────────────────────────────────────────┘

┌─────────── OBSERVATION (existing Grafana + OTel pipeline) ─────┐
│  • tide_ork_protocol_duration{op=sign} p95          ← primary  │
│  • tide_ork_outbound_duration{target=ork} p95                  │
│  • process_runtime_dotnet_thread_pool_queue_length             │
│  • process_runtime_dotnet_gc_collections_count gen=2 (rate)    │
│  • tide_master_lock_wait p95 (sign-up canary)                  │
│  • tide_master_lock_in_flight (lock queue depth)               │
│  • Locust: VU, requests/sec, p95, error rate                   │
└─────────────────────────────────────────────────────────────────┘
```

### Why this split is necessary, not just convenient

- **`Endpoint.callback` in TideCloak** validates `Midgard.VerifySignIn(userId, userPublic, parentSessionId, vData)` against `vendorEncryptedData` produced by real ORK threshold signing. No shortcut around it without weakening security; explicit Phase-3 design decision was to leave the security boundary intact.
- **`DecryptionMiddleware` on `/Authentication/Key/v1/*`** requires AES-encrypted bodies via the per-ORK DH-derived key. tide-js does that encryption. curl/JMeter can't.
- **`UserIdThrottlingConfig`** at `100 req/min/uid` means a single uid trips the throttle within ~50 logins/min (login fan-out is 2N ≈ 40 calls per uid per iteration). A pool of pre-baked users is the only way to sustain real-world throughput.

---

## 3. Scope — repos, branches, SHAs

### tide-js — [`agent/load-test-v1` @ `c9b946a`](https://github.com/tide-foundation/tide-js/tree/agent/load-test-v1)

| Commit | What |
|---|---|
| `451aee7` | **Polyfill fixes (C1/C2/C4)** — `window.crypto` → `globalThis.crypto` across 5 files; `Tools/Utils.ts CurrentTime()` safe on Node (no `localStorage`); `package.json` adds `prepare: tsc` for `file:` dep auto-compile. NetworkClient constructor intentionally left back-compat (5 SWE callsites rely on `= null` default). |
| `c9b946a` | **`load-harness/` v1 scaffolding** — Node sub-project (Express + Playwright + Locust); 11 files; ~300 LoC. Skeleton-only with two intentional TODO sites. |

### tidecloak-override — [`agent/load-test-v1` @ `22ecf1d`](https://github.com/tide-foundation/tidecloak-override/tree/agent/load-test-v1)

| Commit | What |
|---|---|
| `22ecf1d` | **OTel collector autoscale** in `Tidified/prod/run_conf.sh` create+update paths: `--min-replicas 2 --max-replicas 5` + `--scale-rule-type http --scale-rule-metadata concurrentRequests=50`. Parameterized via `.env1` (`OTEL_COLLECTOR_MIN_REPLICAS`/`MAX_REPLICAS`/`SCALE_TARGET`). Idempotent — same `.env1` produces same scale rule by name. `memory_limiter` in `otel-collector-config.yaml` left at 80%/25% (flag for v1.1 tune if drops appear during load). |

### Not touched

- **ork**: no code changes needed. The 7 canonical saturation indicators are already on the OTel pipeline from [METRICS-INITIATIVE.md](./METRICS-INITIATIVE.md). The `UserIdThrottlingConfig` (100/min) constrains the test but is the right production behavior.
- **tidecloak-idp-extensions**: no code changes for v1. A test-mode VRK-pause toggle was discussed and deferred to v1.1; for v1 we schedule around the scheduled-task windows.
- **Midgard / master-libs / keycloak-IGA**: untouched.

---

## 4. The harness — `tide-js/load-harness/`

Co-located inside tide-js so the file-dep round-trip stays local during development. Can be extracted to a separate repo if it grows.

### Layout

```
tide-js/load-harness/
├── package.json                     ← file:.. dep on @tideorg/js
├── tsconfig.json                    ← ES2022, strict, Bundler resolution
├── .gitignore                       ← node_modules, dist, fixtures.json
├── README.md                        ← quickstart + fixture schema + TODOs
├── src/
│   ├── shims.ts                     ← globalThis.crypto = webcrypto; localStorage no-op
│   ├── server.ts                    ← Express :3000, /health + /run/sign
│   ├── runSign.ts                   ← UserFixture + RunResult; body TODO(v1.1)
│   ├── fixtures.ts                  ← load + validate fixtures.json
│   └── warmup/
│       └── index.ts                 ← Playwright orchestrator; enrollOne() TODO(v1.1)
└── locust/
    ├── locustfile.py                ← single /run/sign task, fixtures loaded at on_test_start
    └── requirements.txt             ← locust==2.31.5
```

### Harness API contract (localhost:3000)

```
GET /health
  → 200 { ok: true, fixturesLoaded: N }

POST /run/sign
  body: { fixture: UserFixture }
  → 200 { ok: true, durationMs: <number>, requestCount?: <number> }
  → 5xx { ok: false, durationMs: <number>, code: "TIDE-*", message: <string> }
```

### Fixture schema (v1)

```jsonc
{
  "schemaVersion": "1",
  "realm": "tide-metrics-load",
  "createdAt": "2026-06-01T…",
  "users": [
    {
      "userId":      "metrics-load-001",
      "vuid":        "<sha-hash-prefix>",
      "doken":       "<opaque serialized Doken>",
      "sessKey":     "<serialized TideKey>",
      "vvkid":       "<vendor key id>",
      "vvkPublic":   "<base64 point>",
      "orks":        [{ "orkID":"…","orkURL":"…","orkPublic":"…","orkPaymentPublic":"…" }],
      "voucherURL":  "https://staging.dauth.me/realms/tide-metrics-load/tidevouchers/fromUserSession",
      "homeOrkUrl":  "https://sork1.tideprotocol.com"
    }
    /* … N total */
  ]
}
```

### Locust task (signature only — actual file at `locust/locustfile.py`)

```python
@task(1)
def run_sign(self):
    fixture = random.choice(self.environment.fixtures)
    with self.client.post("/run/sign", json={"fixture": fixture}, catch_response=True) as r:
        if r.status_code != 200 or not r.json().get("ok"):
            r.failure(r.json().get("code", "harness-error"))
```

### Test parameters (v1)

| Setting | Value | Rationale |
|---|---|---|
| Workload | 100% Sign | tide-js drivable; pre-baked Dokens; doesn't burn the per-uid throttle |
| Warm-up user count | **20** | Headroom: 20 users × ~30 sign/min/user = ~600 signs/min capacity before per-user friction |
| Ramp curve | 1 → 100 VU over 10 min, hold 5 min | Linear ramp catches first wall; hold confirms stability |
| Test duration | 20 min total (10 ramp + 5 hold + 5 cooldown) | Fits ALT free-tier budget |
| Locust engines | 1 (ALT default) | Sufficient for 100 VU |
| Primary perf metric | `tide_ork_protocol_duration{op=sign}` p95 | Direct Sign latency |
| Breaking-point trigger | p95 5× baseline OR error rate > 5% | "Find the first wall" |
| Estimated ALT cost | ~$15-20 USD / run | 100 VU × 20 min ≈ 2000 VU-min |

---

## 5. Load arithmetic from Phase 1

Per-iteration ORK request counts (where N = cohort size, default `Threshold_N=20`):

| Scenario | Calls per iteration | Notes |
|---|---|---|
| **Login** | **2N ≈ 40** | N × `Convert` + N × `Authenticate`. All carry `?uid=` → counted by per-uid throttle. |
| **Sign** | **2N ≈ 40** | N × `PreSign` + N × `Sign`. Carries `?vuid=` (escapes per-uid throttle). PreSign cache is in-process — **PreSign and Sign must hit the SAME replica** (sticky routing). |
| **Sign-up** | **1 + 3N ≈ 61** | 1 × `ReserveUserId` + N × `GenShard` + N × `SetCMK` + N × `Commit`, + N concurrent `POST /Master/SubmitUser` all contending on the **same master `Monitor.Enter(_lock)`** (in-process). Sign-up is the canonical master-saturator. |

### Capacity-estimate math

- Staging: 10 sorks × 1 replica × 0.5 CPU each.
- Realistic sustained ceiling per sork: ~40-80 req/s before CPU saturates → **first wall ≈ 2-4 logins/sec network-wide**.
- Sign-up hits the master lock first; the master is **single-replica by design** (`Monitor.Enter(_lock)` is in-process). Likely < 10 signups/sec sustained.
- Sign at sustained 50 VU = potentially ~25 signs/sec = ~1000 ORK requests/sec across 10 sorks = 100 req/s/sork. Past the sustained ceiling — expect early saturation, which is the point of "find the breaking point."

### Saturation indicators (the 7 canonical metrics — already on OTel)

| # | Metric | What saturates | Alert threshold |
|---|---|---|---|
| 1 | `tide_master_lock_wait` p95 | Master `SubmitUser` lock contention (sign-up canary) | p95 > 250 ms, or > 5× baseline |
| 2 | `tide_master_lock_in_flight` (gauge) | Master lock queue depth | sustained > 5 |
| 3 | `tide_ork_protocol_duration{op,phase}` p95 | Sign-flow latency drift | p95 > 500 ms, or > 5× baseline |
| 4 | `tide_ork_outbound_duration{target,endpoint,status}` p95 | ORK-to-ORK fan-out latency | p95 > 500 ms or `status=error` rate > 1% |
| 5 | `process_runtime_dotnet_thread_pool_queue_length` | .NET threadpool starvation | sustained > 50 |
| 6 | `process_runtime_dotnet_gc_collections_count{generation=2}` (rate) | GC pressure on crypto allocations | gen2 rate > 1/s |
| 7 | `tide_ork_throttle_rejections{scope}` (rate) | Test reusing uids (false-positive signal — means the load gen is misconfigured, not that the ORK is full) | any non-zero on `scope=user` series during steady-state |

---

## 6. Constraints surfaced by Phase 1

### Throttle hazards

- **`UserIdThrottlingConfig` = 100 req/min per uid**. Login at 2N=40 calls/uid means ~50 logins/min/uid before exponential penalty. **A pool of pre-onboarded users is mandatory** for any sustained login or sign load > a few iterations.
- **Sign uses `?vuid=` not `?uid=`** → escapes the per-uid throttle. v1 workload focus.
- **Per-IP throttle is configured but commented out** (`ThrottleMiddleware.cs:41 "SINCE ORKS ARE ON WEBAPP"`). Load gen from a small number of source IPs is safe.

### Master-lock constraint

- Master is **single-replica by design** (`Monitor.Enter(_lock)` in `master-libs/MasterService.cs:314`). Horizontally scaling the master would break `SubmitUser` correctness.
- Lock contention is already instrumented (`tide_master_lock_wait/_hold/_in_flight`). This IS the canonical sign-up bottleneck.

### Sign-up cleanup constraint

- Each sign-up iteration consumes a fresh `uid` (UserAlreadyExistsException otherwise).
- **No `DeleteUser` endpoint** exists on the ORK side. Cleanup = wipe-and-restore-realm.
- Warm-up creates N users once; the load phase re-uses them many times. Sign-up is implicitly stressed only during warm-up (with master-lock contention from N concurrent enrollments).

### Decryption-middleware constraint

- `/Authentication/Key/v1/*` requires AES-encrypted bodies via the per-ORK DH-derived key (`DecryptionMiddleware.cs:27`).
- The harness MUST use `@tideorg/js` for request encryption — no curl/JMeter shortcut.

### Sticky-routing constraint (Sign only)

- `PreSign` caches its state in-process via `LazyCache` (`KeyController.PreSign:54`).
- `PreSign` and `Sign` MUST hit the same ORK replica for the cache lookup.
- Staging has 1 replica per sork → this is automatic. If sorks ever scale-out, sticky-by-vuid routing becomes mandatory.

### VRK scheduled tasks

- `VRKGenerationTask`, `RotateVrkTask`, `SwitchVRKTask`, `VRKWatchdogTask` fire on real billing schedule. **No toggle to disable them** (`DEV_MODE` only accelerates them).
- For v1: **schedule the test around the windows**. Operator computes next gen/rotate/switch from Stripe billing data; harness picks a non-overlapping window.
- v1.1 candidate: a `TIDE_DISABLE_VRK_TASKS=true` env-var early-exit in each task's `run()` method (requires idp-extensions change + security-review confirmation it can't be flipped in production).

### No staging isolation

- Staging is a single Container Apps environment. Running a load test means **the rest of staging is unusable** during the run.
- No `sork-loadtest-*` apps. Realms are tenant-scoped in TideCloak but the underlying Container App + DB pool + JVM + sticky sessions + OTel sidecar are shared.
- v1: schedule a downtime window. v1.1 candidate: provision a separate Container Apps env + Postgres flexible server profiled via a new `.env1.loadtest`.

### Infra ceilings

- **Sorks**: pinned 1 replica, 0.5 CPU, 1 GiB memory. NO autoscale rule. Single-replica saturation per sork is what we measure.
- **TideCloak**: scales 1→3 replicas via Container Apps' implicit HTTP-concurrency heuristic (~10/replica), `stickySessions: sticky` (single Locust worker pins to one replica).
- **DB pools** (no autoscale): master sorks → simdb (10 conns × 2 = 20); payer sorks → zivadb (5 × 2 = 10); TideCloak → dauthme (10 × 3 = 30 at full scale). **Actual Postgres `max_connections` for the live `dauthme-staging` server is NOT set in repo** — `az postgres flexible-server parameter show` to confirm before pushing past 30 simultaneous TC connections.
- **OTel collector**: was pinned 1/1; this initiative scales it to 2/5 with HTTP-concurrency rule (commit `22ecf1d`). `memory_limiter` still drops at 80% / 25% spike — flag for v1.1 if drops appear under load.

---

## 7. v1 work remaining (after the scaffolding ships)

The harness is **skeleton-only**. Two iterative tasks need runtime experimentation against staging that's beyond scaffolding scope:

### v1.1 task A — wire `runSign.ts` against real tide-js APIs

Files: `tide-js/load-harness/src/runSign.ts` (currently throws a tagged TODO).

What needs filling in:
1. Confirm `Models.Doken.fromString` (or equivalent) — wire format for the serialized Doken.
2. Confirm `Cryptide.TideKey.deserialize` — wire format for the serialized session key.
3. Confirm `Models.BaseTideRequest` constructor — shape of a JWT-claim test payload.
4. Confirm `Models.Infos.OrkInfo` constructor — exact field names.
5. Find / confirm `Point.fromBase64` (or equivalent) for `vvkPublic` reconstruction.
6. Drive `Flow.SigningFlows.AuthorizedSigningFlow.signv2(request, /*waitForAll*/ false)` and return `{ ok, durationMs, requestCount }`.

Approach: **spawn QA to drive a real SWE sign-up + login on `tide-metrics-load` once** via Playwright, dump the in-flight `Doken` + `sessKey` + `vvkid` + `vvkPublic` + `orks[]` objects via `browser_evaluate`, save them as `fixtures.json`, then wire `runSign.ts` against the captured shapes. ~half-day.

### v1.1 task B — implement the Playwright warm-up

Files: `tide-js/load-harness/src/warmup/index.ts` (currently `enrollOne` throws fast).

What needs implementing:
1. Spawn headless Chromium, navigate to `staging.dauth.me/realms/tide-metrics-load/account`.
2. Click "Sign in with Tide" → redirected to the SWE.
3. Drive the sign-up form (the SWE's enrollment screen) → real CMK keygen + master SubmitUser fan-out.
4. After enrollment, drive the login flow → capture the Doken + sessKey at the right point (probably an `await page.evaluate(...)` against the SWE's runtime state).
5. Shape into `UserFixture`.
6. Loop for N users (with a small delay between to avoid hammering the master lock during warm-up).
7. Write `fixtures.json`.

~2-3 days, the trickiest piece. Sequence-sensitive against the real SWE. QA needs to nail down the right `page.evaluate(...)` extraction points.

---

## 8. Run recipe (when ready)

```bash
# ── PRE-FLIGHT (one-time per build VM) ──
cd /home/alphega/project/tide-js
git checkout agent/load-test-v1
git pull origin agent/load-test-v1
npm install                                    # also installs load-harness via prepare
cd load-harness && npm install && npm run build

# ── REDEPLOY STAGING WITH OTEL SCALE-UP ──
cd /home/alphega/project/tidecloak-override
git checkout agent/load-test-v1
git pull origin agent/load-test-v1
# force-push staging when ready to roll:
git push --force origin agent/load-test-v1:refs/heads/staging
# In Tidified/prod/.env AND .env1 → TC_RELEASE=<new short SHA>
cd Tidified/prod
./BuildTideStaging.sh          # only need master-stg / ork-stg images, not TideCloak
./gen_conf.sh && ./run_conf.sh # 'y' at the prompt — applies the OTel scale-up

# ── VERIFY OTEL COLLECTOR SCALE ──
az containerapp show -n otel-collector -g Tide-Staging \
  --query "properties.template.scale" -o json
# should show minReplicas: 2, maxReplicas: 5, http rule with concurrentRequests=50

# ── WARM-UP ──
cd /home/alphega/project/tide-js/load-harness
WARMUP_USERS=20 STAGING_BASE=https://staging.dauth.me \
  WARMUP_REALM=tide-metrics-load \
  npm run warmup
# produces ./fixtures.json with 20 users

# ── START HARNESS SERVER LOCALLY (smoke test) ──
PORT=3000 FIXTURES_PATH=./fixtures.json npm start &
curl http://localhost:3000/health     # should report ok + fixturesLoaded:20
# fire one Sign manually to make sure the round-trip works before kicking ALT
curl -X POST http://localhost:3000/run/sign \
  -H "Content-Type: application/json" \
  -d "{\"fixture\":$(jq '.users[0]' fixtures.json)}"
# expect 200 { ok: true, durationMs: <number> }

# ── AZURE LOAD TESTING SETUP ──
# In Azure portal → Create new "Load testing" resource if needed
# Upload locust/locustfile.py + locust/requirements.txt
# Configure test:
#   - Engine instances: 1
#   - VU pattern: linear ramp 1 → 100 over 10 min, hold 5 min, cooldown 5 min
#   - Engine init script: install Node + harness, copy fixtures.json, start server on :3000
#   - Failure criteria: error rate > 5% OR p95 > 5× baseline
# Run.

# ── OBSERVE LIVE IN GRAFANA ──
# Open the Tide Network Performance dashboard
# Watch the 7 saturation panels (see section 5) for the first-wall pattern
# When degradation triggers → ALT stops the test → screenshots + report
```

---

## 9. Parking lot

### v1.1 candidates (after first successful run)

1. **Wire `runSign.ts`** + **Playwright warm-up** (sections 7A + 7B).
2. **Mix in Decrypt + voucher workloads** at lower weights to broaden coverage.
3. **Tune OTel collector `memory_limiter`** to 90% / 15% spike if metric drops show up.
4. **Test isolation** — provision `sork-loadtest-*` apps + separate Postgres so we can load-test without disrupting other staging users.
5. **`TIDE_DISABLE_VRK_TASKS=true` env-var** on idp-extensions so we don't have to schedule around VRK windows.
6. **Distributed Locust workers** — single ALT engine is sufficient for 100 VU; for higher targets we'd add engines.
7. **Compare configurations** — A/B test T=3 vs T=5, 3 sorks vs 10, 1 master vs replicated-with-locking-strategy. Outputs a sensitivity matrix for production sizing.
8. **NetworkClient.ts C3 cleanup** — the polyfill commit kept the `= null` default for SWE back-compat. v1.1 could remove it after updating the 5 SWE callsites in `ork/Ork/Ork/Enclave/js/`.

### Known issues / non-blockers

- **Postgres `max_connections` on live `dauthme-staging` is not set in repo.** Could be Microsoft's default (~100). Check via `az postgres flexible-server parameter show` before pushing TideCloak past ~30 concurrent connections.
- **OTel collector `memory_limiter` defaults (80% / 25% spike)** drop metrics rather than backpressure. If drops appear, we lose visibility right when we need it. Tune values OR add a second dedicated collector for load-test traffic.
- **Single Locust engine** is fine for 100 VU. At higher targets, sticky-routing on TideCloak (`stickySessions: sticky`) might pin a single engine's traffic to one TideCloak replica, blunting scale-up. v1.1 may need cookie rotation per VU.

---

## 10. Related work

- **[METRICS-INITIATIVE.md](./METRICS-INITIATIVE.md)** — the OTel → Azure Managed Prometheus pipeline this load test piggybacks on. The 7 saturation indicators are the metrics shipped by that initiative.
- **[SWE-ERROR-REPORTING.md](./SWE-ERROR-REPORTING.md)** — the structured error infrastructure. The harness emits `TideError`-typed errors that flow into the same observability pipeline (`tide.error.report.id` on submitted reports).
- **Orchestrator memory** — `load-testing-initiative.md` (to be written when v1 first run completes) — cross-session resumption pointers.

---

## v1 results (2026-06-02)

The original design (sections 1-10 above) targeted Option D (Playwright warm-up + tide-js Sign load via Locust on Azure Load Testing). During implementation we pivoted the v1 deliverable to **Option F — the login-flow load driver** — and carved out the signv2 path as an in-tree but blocked path (Option B). What ships and runs in v1 is the login-flow driver. The Sign driver is wired but gated by a downstream Tide-IGA blocker (see Parking lot below).

### Scope shipped

**Option F — login-flow load driver.** End-to-end OIDC login under concurrent load, driving the real SWE login flow against staging through Playwright instances per virtual user. Captures per-phase wall-clock timing for the five distinct phases of an OIDC login round-trip, and writes JSONL results suitable for joining with the Grafana dashboard window.

- Driver: `tide-js/load-harness/src/loadtest/index.ts`
- Harness server: `tide-js/load-harness/src/server.ts` (Express, exposes `/oidc/begin` + `/callback`)
- Per-VU runner uses a fresh Playwright browser context per iteration; collects 5 phase timings + outcome + iteration id.
- Outputs JSONL to `RESULTS_PATH` (one record per iteration).

### Scope parked

**Option B — signv2 path.** The signv2 sign-driver path was carved out of v1 but the scaffolding **is** in the load-harness tree (gated behind realm `tide-metrics-load` + client `tide-loadtest-harness`). It is blocked by a downstream Tide-IGA admin-grant gate. Five technical gates were investigated; four are solved. The fifth (User Client Access proof via the 3-step admin REST flow) is the blocker. See **Parking lot — signv2 path** below.

### First load run results (R24 QA)

**Config:**
- Concurrency: `CONCURRENCY=10`
- Ramp: `RAMP_S=30`
- Duration: `DURATION_S=300`
- Target: `staging.dauth.me`, realm `tide-metrics-load`, client `tide-loadtest-harness`, user `metrics-load-001`
- Run window (UTC): `2026-06-02 06:58:00 → 07:03:30`

**Outcome:**
- 124 iterations over 5.5 min wall clock (328 s active + drain)
- 102/124 (82.3%) reached the `/token` exchange — failed there with the R19 403 gate (parked)
- 22/124 (17.7%) timed out at `wait_for_callback_ms` (Playwright `waitForURL` exceeded the 120 s default)
- 0/124 succeeded end-to-end (R19 gate prevents `/token` completion against this realm/client until the User Client Access proof is solved)

The 0% end-to-end success rate is expected and gated by the parked signv2 path; the value of the run is the per-phase **timing distribution** of everything **up to** the `/token` exchange, which is dominated by server-side redirect chains.

### Per-phase timing — all iterations

All values in milliseconds. The five timed phases are taken end-to-end per iteration.

| Phase | Mean | p50 | p95 | p99 | Max |
|---|---:|---:|---:|---:|---:|
| `oidc_begin_ms`           | 2    | 2    | 3     | 4     | 11    |
| `nav_to_swe_ms`           | 2057 | 984  | 6527  | 8979  | 11818 |
| `swe_form_fill_ms`        | 909  | 875  | 1268  | 1327  | 1391  |
| `swe_sign_in_click_ms`    | 344  | 343  | 509   | 673   | 1069  |
| `wait_for_callback_ms`    | 4385 | 2754 | 10567 | 15493 | 17173 |

### Ramp vs sustained breakdown

The single most interesting view in v1 — it isolates where concurrency-sensitivity actually lives. "Ramp" = the first 30 s while VUs come online; "Sustained" = the remaining ~270 s at full 10 VU.

| Phase | Ramp p50 | Ramp p95 | Sustained p50 | Sustained p95 | Notes |
|---|---:|---:|---:|---:|---|
| `nav_to_swe_ms`         | 5585  | 11818 | 957  | 3454 | **3.4× p95 improvement** post-ramp — looks cold-start-dominated |
| `wait_for_callback_ms`  | ~7300 | 17173 | 2436 | 9737 | Improves post-ramp but remains oscillatory — concurrency-sensitive throughout the run, not just at start |
| `swe_form_fill_ms`      | flat  | flat  | flat | flat | Local browser op — no load sensitivity |
| `swe_sign_in_click_ms`  | flat  | flat  | flat | flat | Local browser op — no load sensitivity |

### Bottleneck conclusion

- **Server-side redirect chains dominate.** Approximately 6.4 s of the ~7 s pre-token p95 wall time is spent in two server-driven phases (`nav_to_swe_ms` + `wait_for_callback_ms`).
- **Local browser ops are flat.** Form-fill and sign-in click are unaffected by concurrency — the bottleneck is not in the driver.
- **Two specific server-side phases are concurrency-sensitive:**
  - `nav_to_swe_ms` — the initial TideCloak → SWE broker hop. Mostly cold-start: massive improvement after ramp completes, suggesting warm-cache / connection-pool / JIT effects.
  - `wait_for_callback_ms` — the SWE → TideCloak → client `/callback` redirect chain. Persists throughout the run (not just ramp) and oscillates under load — this is the **true v1 bottleneck signal** worth chasing in v2.

### Throughput at 10 VUs

~0.38 iterations/sec ≈ **38 full pre-token login cycles per minute** sustained. Per-VU effective rate: ~2.3 cycles/min.

### Grafana correlation window

Run window in UTC for joining with the OTel pipeline panels:

```
2026-06-02 06:58:00 → 07:03:30 UTC
```

Recommended panels to overlay against this window:
- `tide_ork_protocol_duration` (broker-side keycloak metrics, if shipped)
- TideCloak Container App `Requests` + p95 latency
- Container App replica count for TideCloak during ramp vs sustained
- OTel collector ingest rate (confirm no drops during the run)

### Grafana correlation (2026-06-02)

The 06:58–07:04 UTC window was inspected in `tide-metrics-dashboard.json` after the R24 run. The ORK-side panels lit up cleanly; the TideCloak-side panels were uniformly empty (scrape not yet shipped), which forces the attribution to be done by subtraction rather than by per-hop measurement on the broker side.

**ORK-side panels (lit):**

| Panel | Mean | Max | Peak throughput |
|---|---:|---:|---:|
| Crypto `eddsa_standard` (latency)         | 9.75 ms | 11.7 ms | 1.82 ops/s |
| Crypto `eddsa_verify`                     | — | — | no activity (expected — cmkOnly login path does not verify) |
| Protocol `check_payment` (latency)        | 368 ms  | 535 ms  | 1.81 ops/s |
| Protocol `voucher` (latency)              | 117 ms  | 152 ms  | 1.82 ops/s |
| Protocol `sign` / `keygen`                | — | — | zero activity (expected — Sign parked behind R19 gate; no user creation in window) |
| Outbound `payer` (external payment call inside `check_payment`) | 169 ms | 347 ms | — |
| Outbound throughput `status=ok`           | — | — | 1.81 req/s |

ORK latencies on `check_payment` actually **fell** over the 5.5-minute window as caches warmed — the opposite of saturation behaviour.

**TideCloak :9000 panels (dark):** ALL "No data". The TideCloak-side scrape isn't deployed yet — known parking-lot item from [[metrics-initiative]] ("TideCloak JVM/HTTP baseline metrics still filtered out by the metrics-sidecar denylist; separate initiative"). Without this scrape we cannot break down the TideCloak callback chain per-hop.

#### Bottleneck attribution

Subtract the directly-measured ORK cohort time from the load-driver `wait_for_callback_ms` to get the unmeasured TideCloak portion:

| Component | Per-login (mean) | Source |
|---|---:|---|
| ORK cohort total (`check_payment` 368 + `voucher` 117 + crypto 10) | ~500 ms | Grafana |
| Client form fill + click (local browser, flat under concurrency)   | ~1.25 s | Load driver |
| Initial broker hop (`nav_to_swe_ms`)                               | 2.0 s   | Load driver — ramp-sensitive, recovers post-ramp |
| **TideCloak broker callback chain (residual)**                     | **~3.9 s mean / ~10 s p95** | **Load driver `wait_for_callback_ms` minus ORK time = the unmeasured TideCloak portion** |

*[2026-06-03 revision]: the inference here that the ~3.9 s lived in TideCloak's broker chain was wrong — see v1.1 results below.*

**Conclusion.** The ORK cohort is **NOT** the bottleneck at this concurrency. ORKs comfortably handled the 1.82 ops/s peak with smooth ramp behaviour and no saturation signals on any of the 7 canonical indicators. The dominant cost — ~3.9 s mean of the ~10.6 s p95 `wait_for_callback_ms` — lives in **TideCloak's broker callback chain**: Keycloak session minting, IdP-extension processing, and the post-SWE redirect work that follows. Per-hop attribution within that chain requires the TideCloak :9000 scrape to ship (parking-lot item in `metrics-initiative.md`).

See also: [[metrics-initiative]] — the load-test surface that's missing is the TideCloak :9000 scrape. Until it lands, every `wait_for_callback_ms` p95 we measure is a black box with ~3.9 s of unattributable TideCloak time inside it.

---

## v1.1 results (2026-06-03)

### Headline correction

The v1 conclusion that "the unaccounted ~3.9 s of `wait_for_callback_ms` lives in the TideCloak broker callback chain" was **wrong**. With the TideCloak `:9000` scrape now shipping (metrics v2 deployed to staging earlier today) and a fresh load run executed under identical config, we can now measure the broker chain directly:

- **TideCloak broker chain total: ~50 ms per login** (not ~3.9 s).
- ORK cohort total: ~500 ms per login (unchanged from v1, tracking within ~10%).
- That leaves **~4.2 s mean / ~10.5 s p95 of `wait_for_callback_ms` unaccounted on the wire** — and the only thing left on the critical path is the SWE-side browser itself.

New finding: **the bottleneck is the SWE-side browser JavaScript**, not any Tide server component. Scaling ORK or TideCloak will not move p95 latency. Real-user login latency is client-device-bound.

### Metrics v2 deploy summary

- Built `tideorg/otel-collector-tc-stg:1` (no CI builds the TideCloak-side OTel sidecar; pushed manually). Sidecar image digest: `sha256:2c262cf68b01ecb2e536005c8730006372ad8cc7f4b400cdffe2349c3b98df75`.
- Attached as a sidecar to the `tidecloak-staging` Container App via revision swap.
- Scrapes `localhost:9000` (TideCloak's Micrometer Prometheus endpoint) every 15 s and exports every 10 s to Azure Managed Prometheus.
- Result: the previously dark TideCloak panels in `tide-metrics-dashboard.json` now light up.

### Re-run config + outcome

Identical to the v1 run config so the per-phase numbers are directly comparable.

- Concurrency: `CONCURRENCY=10`
- Ramp: `RAMP_S=30`
- Duration: `DURATION_S=300`
- Target: `staging.dauth.me`, realm `tide-metrics-load`, client `tide-loadtest-harness`, user `metrics-load-001`
- Run window (UTC): `2026-06-03 01:17:51 → 01:25:40`
- Results file: `load-harness/loadtest-results-v2.jsonl`
- 108 iterations total; 0 succeeded end-to-end (R19 `/token` 403 gate still parked, as expected); 85 reached `oidc_await`; 23 timed out at `wait_for_callback_ms`.
- Per-phase numbers track within ~10% of the v1 run — see table below.

### TideCloak `:9000` server-side per-login (Grafana — User-workflows row, today's window)

| Panel | Mean | Max | Notes |
|---|---:|---:|---|
| Login phase `callback`                    | 41.5 ms | 51.4 ms | Broker callback handler |
| Login phase `performlogin`                | 1.18 ms | 1.53 ms | Form-post → session mint |
| Token-issue `tide` path                   | ~7 ms   | ~8.5 ms | Fast even though it 403s on the parked R19 gate |
| Voucher `signin` action                   | ~40 ms  | 46 ms   | Voucher mint inside the broker login |
| Callback-hop `decrypt`                    | 3.06 ms | 3.27 ms | Per-hop crypto |
| Callback-hop `verify`                     | 4.80 ms | 5.75 ms | Per-hop crypto |
| Login rate `success` (IdP-side, pre-/token) | 0.313 ops/s | 0.596 ops/s peak | Broker login completes; the 403 happens at `/token` |
| VRK-task panel                            | No data | — | Expected — VRK rotates on a slow cadence, not per login |

**Sum of TideCloak per-login broker work: ~50 ms.** Even at 99th-percentile each panel adds only a few ms; there is no plausible per-hop story that turns this into 3.9 s.

### Client-side per-login (re-run, `loadtest-results-v2.jsonl`, 108 iters)

| Phase | Mean | p95 | p99 |
|---|---:|---:|---:|
| `oidc_begin_ms`        | 2    | 3     | 8     |
| `nav_to_swe_ms`        | 1936 | 5779  | 6673  |
| `swe_form_fill_ms`     | 772  | 990   | 1380  |
| `swe_sign_in_click_ms` | 344  | 474   | 528   |
| `wait_for_callback_ms` | **4808** | **11093** | **12905** |

### Revised bottleneck attribution

| Component | Per-login mean | Source |
|---|---:|---|
| ORK cohort total (`check_payment` + `voucher` + crypto) | ~500 ms | Grafana (v1 + v1.1) |
| TideCloak broker chain total | ~50 ms | Grafana `:9000` (v1.1) |
| Local browser (form fill + click) | ~1.1 s | Load driver |
| Initial broker hop (`nav_to_swe`) | ~1.9 s | Load driver — concurrency-sensitive ramp |
| **SWE-side browser JS (residual)** | **~4.2 s mean / ~10.5 s p95** | **Load driver - all of the above = unaccounted; lives in SWE browser** |

### What the residual ~4.2 s is doing

The SWE-side browser is the only remaining slot on the critical path between `swe_sign_in_click_ms` and the `/callback` redirect arriving at the client. Likely contributors:

- SWE-side JavaScript doing CMK key derivation (Ed25519, scrypt, hash work in pure JS / WebCrypto).
- Multiple sequential SWE → ORK HTTP roundtrips for the threshold protocol (each adds its own RTT to the wall clock).
- Browser-side rendering and event-loop scheduling between the Sign-In click and the final redirect.

### Implications

- **Scaling ORK or TideCloak does not move p95.** Both run with substantial headroom at the v1 load level (1.82 ops/s on ORK; ~0.3 ops/s broker-login on TideCloak; sub-millisecond to low-tens-of-ms per hop on both).
- **Real-user latency is client-device-bound.** A slow phone pays the same ~4 s regardless of how fast Tide's backends run. Performance work that moves the dial for end users is **SWE-side**, not server-side.
- **v2 should change focus.** A higher-concurrency or higher-ramp run will not surface a server bottleneck before it surfaces a client one; v2 work should pivot to SWE profiling (see parking lot below) rather than pushing the load driver harder.

### SWE optimization opportunities (out of load-test scope)

Candidate areas for a future SWE perf initiative. None of these are in scope for the load-test repo; they're flagged here because they're what the data points at.

- **Parallelize SWE→ORK roundtrips.** Confirm whether the threshold protocol calls are currently sequential and, if so, whether any of them can be fanned out concurrently.
- **WebCrypto vs pure-JS for Ed25519 ops.** Measure whether the browser's native subtle-crypto Ed25519 (where available) beats the pure-JS implementation currently in use, and switch where possible.
- **Profile the CMK auth path in browser DevTools.** Get a real flame graph from a SWE login session against staging. The ~4.2 s is currently a single bucket; DevTools would split it into specific functions.
- **Cohort size sensitivity.** Does dropping the cohort from N=5 to N=3 reduce client-side work proportionally? If most of the ~4.2 s is N-linear (e.g. N decrypts, N verifies, N HTTP calls in series), a smaller cohort buys real wall-clock savings on slow devices.

---

## Parking lot — signv2 path

Five gates were discovered during the R14-R22 exploration of the signv2 sign-driver path against the `tide-metrics-load` realm and `tide-loadtest-harness` client. Four are solved; one is a hard blocker requiring upstream changes. Full session detail in `~/.claude/.../memory/loadtest-signv2-sessionkey-blocker.md`.

### 1. Session-key private bytes — **solved** (Option B carve-out, in tree)

The signv2 path needs the per-user session-key **private** material, which is normally never exposed outside the SWE enclave. Solved by an Option B carve-out: the SWE exposes the session-key private bytes only when the broker login is for realm `tide-metrics-load` (gated by realm name). Scaffolding lives in the load-harness tree; no production realm is affected.

### 2. `isIGAEnabled` realm flag — **already on, no action**

Confirmed already enabled on the `tide-metrics-load` realm via Admin REST GET on realm config. No change required.

### 3. EdDSA per-client signature algorithm — **applied via Admin REST PUT in R18**

The client `tide-loadtest-harness` was reconfigured to use EdDSA for both access and id tokens via Admin REST PUT on `/admin/realms/tide-metrics-load/clients/{id}`:

```
attributes["access.token.signed.response.alg"] = "EdDSA"
attributes["id.token.signed.response.alg"]     = "EdDSA"
```

Idempotent — re-applying the PUT is safe. Confirmed in subsequent rounds.

### 4. `TideAuthData` session note — **solved automatically, no action**

The `TideAuthData` session note required by the signv2 flow is set automatically by the SWE broker login. No manual provisioning needed once the broker login succeeds.

### 5. User Client Access proof — **BLOCKER**

The canonical grant path is a 3-step admin REST flow:

```
POST /admin/realms/{realm}/tide-admin/generate-default-user-context  ← succeeds
POST /admin/realms/{realm}/tide-admin/change-set/sign                ← FAILS
POST /admin/realms/{realm}/tide-admin/change-set/commit              ← unreached
```

`generate-default-user-context` succeeds and produces a draft. `change-set/sign` then fails with:

```
Midgard.SignModel: Error with signing model: UserContext:1
```

The draft payload is sparse because the test client has no role mappings, and the Midgard SignModel rejects sparse `accessDraft` payloads. Three tickets to file to unblock:

1. **tidecloak-iga-extensions** — `SignModel` rejection of sparse `accessDraft`. Clients without role mappings produce an insufficient draft payload that Midgard refuses to sign. Either Midgard should accept the sparse case, or IGA-extensions should pad the draft with the minimum schema Midgard expects.
2. **admin tooling** — there is no discard/abort endpoint for orphan drafts in the request queue. Failed `change-set/sign` calls leave dangling drafts visible in the admin UI's request queue with no way to clean them up programmatically.
3. **Alternative** — provision Midgard signing material on staging for this specific realm + client so the sign step succeeds with the existing draft shape.

Until one of these lands, the signv2 path on staging cannot complete the User Client Access grant, and v1's Option B carve-out remains gated. The load-harness Sign driver code is shipped and ready; only the grant gate prevents it from running end-to-end.

---

## How to re-run v1

Operator quickstart for repeating the R24 login-flow run. Tune `CONCURRENCY` / `RAMP_S` / `DURATION_S` to taste; defaults below match the R24 numbers.

```
cd /home/alphega/project/tide-js/load-harness
npm install
npm run build

# 1. Start the harness server
PORT=3000 TIDECLOAK_BASE_URL=https://staging.dauth.me \
  TIDECLOAK_REALM=tide-metrics-load OIDC_CLIENT_ID=tide-loadtest-harness \
  node dist/server.js &

# 2. Run the load driver (tune env to taste)
HARNESS_URL=http://localhost:3000 \
LOAD_TEST_USERS_PATH=./load-test-users.json \
CONCURRENCY=10 RAMP_S=30 DURATION_S=300 \
RESULTS_PATH=./loadtest-results.jsonl \
  node dist/loadtest/index.js
```

**Note:** `load-test-users.json` is gitignored. Populate it from `load-test-users-sample.json` with real credentials for the `tide-metrics-load` realm. Each user record needs a matching seed in the realm — coordinate with the realm operator before adding new test users.

When the driver exits, `loadtest-results.jsonl` contains one JSON object per iteration with the five phase timings + outcome + iteration id. Cross-reference the UTC start/end window with the Grafana panels for the server-side correlation view.
