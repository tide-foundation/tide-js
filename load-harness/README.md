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
npm run warmup        # writes ./fixtures.json (currently a TODO stub)
npm start             # starts http://localhost:3000

# in another shell:
cd locust
pip install -r requirements.txt
locust -f locustfile.py -H http://localhost:3000
```

Sanity-check the server before pointing Locust at it:

```bash
curl http://localhost:3000/health
# → {"ok":true,"fixturesLoaded":5}
```

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
