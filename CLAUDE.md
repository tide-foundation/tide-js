# tide-js

Browser-side TypeScript SDK for interacting with the Tide Cybersecurity Fabric. Zero external dependencies — all cryptography is implemented in-house. Consumed as an npm package by `ork`, `tidecloak/js`, `heimdall-tide`, and other Tide projects.

## Working Rules

1. **Design-First**: Continuously refer to designs when implementing. Designs are PUML files at `~/diagrams/src/id-server/`. Key designs for this project: `LLD-Cryptide.puml` (primary), `LLD-VoucherFlows.puml`, `MATH-AnonVouchers.puml`, `MATH-BlindSig.puml`, `MATH-SignFlow.puml`, `MATH-DecryptFlow.puml`. Each line of implementation code should be traceable to a design step. Verify against the design before modifying protocol code.

2. **Ask When Unsure**: When you are about to make an implementation you are slightly unsure about due to design, documentation or existing code vagueness, ask the caller to clarify before proceeding.

3. **Cryptographic Conventions**: Ignore general cryptographic principles such as Ed25519 only being used for signing. Accept the style of cryptographic use as seen in the code. Do not "correct" non-standard usage (e.g., Ed25519 used for ECDH, ElGamal encryption on Ed25519 points, non-deterministic EdDSA signing with random nonces).

4. **Security Invariant**: Never allow informational data to be used for critical purposes such as deciding if an authentication should pass. All data used for critical purposes must be part of an authentication chain. If unsure about security of a crypto tool or API endpoint, ask the caller.

## Build & Run

```bash
npm install        # Install dev dependencies (typescript only)
npm run build      # Compile to dist/ via tsc
```

No test runner configured. Tests are in `Tests/` but excluded from build.

## Architecture

```
Clients/       HTTP clients for ORK and vendor communication
Contracts/     Policy validation contracts
Cryptide/      Cryptographic primitives (Ed25519, ElGamal, AES, ECDH, BlindSig, Interpolation)
Flow/          Orchestration flows (Voucher, Signing, Encryption, Decryption)
Math/          Key derivation and signature aggregation
Models/        Data structures (BaseTideRequest, OrkInfo, KeyInfo, Doken, Policy)
Tools/         Utilities (TideMemory, WaitForNumberofORKs, threshold constants)
```

## Critical Patterns

### Parallel ORK Queries with WaitForNumberofORKs

All parallel ORK calls MUST use `WaitForNumberofORKs` from `Tools/Utils.ts`. This function races promises, waits for a threshold of responses, tracks which ORKs responded via bitwise array, and prunes non-responding ORKs. Study how existing flows use it:

```typescript
// Pattern: fire all ORK requests, then wait for threshold
const pre_responses = clients.map((client, i) => client.PreSign(i, vvkid, request, vouchers.toORK(i)));
const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(orks, pre_responses, "VVK", Threshold, null, clients);
```

Key behaviors:
- `orkList_Ref` is modified in-place (non-responding ORKs removed)
- `optionalArray` (e.g., `clients`) is also modified in-place to stay in sync
- Returns `{ fulfilledResponses, bitwise }` — bitwise tracks which of the original Max ORKs responded
- The bitwise array is passed to subsequent calls (e.g., `serializeBitArray(bitwise)` in Sign step)
- For sequential multi-step flows, pass the previous bitwise to maintain ORK tracking

**Threshold constants**: `Threshold = 14`, `Max = 20` in production. In local dev environments, use `3/5`.

### BaseTideRequest

This is the core request model. Key things to get right:

- **replicate() is NOT a copy** — it creates a new object pointing to the same TideMemory buffers. Modifying a replicated field modifies the original.
- **Encode field order is strict**: name, version, expiry, draft, authFlow, dynamicData, authorizer, authorization, authorizerCert, policy (indices 0-9)
- **Expiry** is stored as 8-byte LE (Int64 layout matching .NET), not 4-byte
- **Authorization structure**: `TideMemory[ [creationTime, creationSig], [approvalSigs...] ]`
- **dynamicData** field is intentionally spelled `dyanmicData` (typo preserved for compatibility)
- Use `setNewDynamicData()` to replace dynamic data (creates new TideMemory, doesn't mutate)
- Use `addCreationSignature()` before `addApproval()` — approvals require existing creation auth
- `dataToAuthorize()` and `dataToApprove()` return the exact bytes that must be signed

### Flow Pattern (reference: dVVKSigningFlow.ts)

Flows follow this structure:
1. Sort ORKs (`sortORKs`) for deterministic bitwise ordering
2. Create VoucherFlow and start fetching vouchers (can overlap with client setup)
3. Create NodeClients with bearer auth and TideDH encryption
4. Await vouchers
5. Fire parallel ORK requests, await with `WaitForNumberofORKs`
6. Aggregate results (Lagrange interpolation for threshold crypto)
7. Subsequent rounds use the pruned ork/client lists

### TideMemory Serialization

Binary format: `[version(4)][length(4)][data...]`. Nested structures use `GetValue(index)` / `TryGetValue(index, result)` / `CreateFromArray([...])`. Field ordering matters — it must match what C# (ork/Cryptide) expects.

### Client Pattern

All clients extend `ClientBase`. NodeClient adds:
- `AddBearerAuthorization(privKeyBytes, pubKeyBase64, doken)` — sets session auth
- `EnableTideDH(orkPublic)` — enables ECDH-encrypted request/response channel
- Methods return `{ index, ...data }` — the `index` field is required for `WaitForNumberofORKs` sorting

### Naming Conventions

- `g` prefix = public/group element (e.g., `gVRK`, `gCMK`, `gORKi`)
- `d` prefix = distributed key (e.g., `dVVK` = distributed Virtual Voting Key)
- `pre_` prefix = promises not yet awaited (e.g., `pre_PreSignResponses`)

## Voucher System

Vouchers are a cryptographic authorization mechanism (not tokens/coupons):

1. VoucherFlow blurs ORK payment public keys using ECDH shared secrets (`prepVouchersReq`)
2. Vendor endpoint generates voucher packs using VRK
3. VoucherResponse contains per-ORK voucher packs, payer public keys, and blinding data
4. Each ORK receives its voucher via `vouchers.toORK(i)` during flow execution

Key files: `Flow/VoucherFlows/VoucherFlow.ts`, `Clients/VoucherClient.ts`, `Models/Responses/Vendor/VoucherResponse.ts`, `Cryptide/TideKey.ts` (prepVouchersReq)

## TypeScript Notes

This project was originally JavaScript and is progressively adopting TypeScript types. When writing new code, use proper TypeScript types. When modifying existing code, add types where practical but don't refactor unrelated code just to add types.
