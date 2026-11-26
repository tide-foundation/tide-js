// Node unit tests for the component version nibble (low 4 bits of serialized byte 0):
//   1. Ed25519 headers stay byte-identical (every tide-js component is version 0)
//   2. Regression pins captured from the pre-versioning build
//   3. Seed blobs with a non-zero version are rejected (the ORK's version 1
//      RFC 8032 seed is not implemented in tide-js)
//   4. Public / private parsing ignores the nibble (as the ORK's untyped parse does)
//
// Runs against the compiled `dist/` output (see the `test` script in
// package.json — `tsc` is run first).
//
// Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";

// NOTE: Ed25519Components must be imported before BaseComponent. BaseComponent -> ComponentRegistry ->
// Ed25519Components -> BaseComponent is an (existing) import cycle that only resolves from this entry point.
import { Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "../dist/Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { BaseComponent } from "../dist/Cryptide/Components/BaseComponent.js";
import Ed25519Scheme from "../dist/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";
import TideKey from "../dist/Cryptide/TideKey.js";
import { TideError } from "../dist/Errors/TideError.js";
import { TideJsErrorCodes } from "../dist/Errors/codes.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const fromHex = (s) => Uint8Array.from(s.match(/../g).map(b => parseInt(b, 16)));
const toHex = (b) => Buffer.from(b).toString("hex");

const SEED_HEX = "68bf3e0e93e771730dd8261229135abef6b2116541f504288567b2fb225bfeb9";
// Captured from the build BEFORE the version nibble was read/written.
const PINNED_PUBLIC_HEX = "200000a8bad33af92740501ca1ae29e8926c0ae7cf4b62ccfa33dce431631df1ef4599";
const PINNED_PRIVATE_HEX = "10000039a4ae0f71a5a7aad71a83119856c5d8f5b2116541f504288567b2fb225bfe09";

/** byte 0 = (keyType Seed (0) << 4) | version, bytes 1-2 = scheme Ed25519 (0) */
const seedBlob = (version) => fromHex(toHex([version & 0x0F, 0x00, 0x00]) + SEED_HEX);

function assertUnsupportedSeedVersion(fn) {
    assert.throws(fn, (e) => {
        assert.ok(e instanceof TideError);
        assert.equal(e.code, TideJsErrorCodes.CRYPTO_DESERIALIZE_FAILED);
        assert.match(e.displayMessage, /not supported in tide-js/);
        return true;
    });
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

test("Ed25519 components all declare numeric version 0", () => {
    assert.equal(Ed25519SeedComponent.Version, 0);
    assert.equal(Ed25519PrivateComponent.Version, 0);
    assert.equal(Ed25519PublicComponent.Version, 0);
});

test("serialized Ed25519 headers are 00 00 00 (seed), 10 00 00 (private), 20 00 00 (public)", () => {
    const seed = new Ed25519SeedComponent(fromHex(SEED_HEX));
    assert.equal(toHex(seed.Serialize().ToBytes().slice(0, 3)), "000000");
    assert.equal(toHex(seed.GetPrivate().Serialize().ToBytes().slice(0, 3)), "100000");
    assert.equal(toHex(seed.GetPublic().Serialize().ToBytes().slice(0, 3)), "200000");
});

test("pre-versioning regression pins: seed -> serialized public and private are unchanged", () => {
    const seed = new Ed25519SeedComponent(fromHex(SEED_HEX));
    assert.equal(toHex(seed.Serialize().ToBytes()), "000000" + SEED_HEX);
    assert.equal(toHex(seed.GetPublic().Serialize().ToBytes()), PINNED_PUBLIC_HEX);
    assert.equal(toHex(seed.GetPrivate().Serialize().ToBytes()), PINNED_PRIVATE_HEX);
    // string forms: hex for public, base64 for private
    assert.equal(seed.GetPublic().Serialize().ToString(), PINNED_PUBLIC_HEX);
    assert.equal(seed.GetPrivate().Serialize().ToString(), Buffer.from(fromHex(PINNED_PRIVATE_HEX)).toString("base64"));
});

test("a component version above 15 cannot be serialized", () => {
    class TooNewPublicComponent extends Ed25519PublicComponent { static Version = 16; }
    const raw = fromHex(PINNED_PUBLIC_HEX).slice(3);
    assert.throws(() => new TooNewPublicComponent(raw).Serialize(), (e) => e instanceof TideError && e.code === TideJsErrorCodes.MODEL_VALUE_OUT_OF_RANGE);
});

// ---------------------------------------------------------------------------
// Seed version dispatch
// ---------------------------------------------------------------------------

test("a 00 00 00 seed blob deserializes to Ed25519SeedComponent and round-trips byte-identically", () => {
    const blob = seedBlob(0);
    const component = BaseComponent.DeserializeComponent(blob);
    assert.ok(component instanceof Ed25519SeedComponent);
    assert.deepEqual(component.Serialize().ToBytes(), blob);
    assert.equal(toHex(component.GetPublic().Serialize().ToBytes()), PINNED_PUBLIC_HEX);

    // same through the base64 string form and TideKey
    const key = TideKey.FromSerializedComponent(Buffer.from(blob).toString("base64"));
    assert.equal(toHex(key.get_public_component().Serialize().ToBytes()), PINNED_PUBLIC_HEX);
});

test("a 01 00 00 seed blob (ORK version 1) is rejected", () => {
    assertUnsupportedSeedVersion(() => BaseComponent.DeserializeComponent(seedBlob(1)));
    assertUnsupportedSeedVersion(() => BaseComponent.DeserializeComponent(Buffer.from(seedBlob(1)).toString("base64")));
    assertUnsupportedSeedVersion(() => TideKey.FromSerializedComponent(seedBlob(1)));
});

test("every non-zero seed version nibble is rejected", () => {
    for (let version = 1; version <= 0x0F; version++) {
        assertUnsupportedSeedVersion(() => BaseComponent.DeserializeComponent(seedBlob(version)));
    }
});

// ---------------------------------------------------------------------------
// Public / private parsing
// ---------------------------------------------------------------------------

test("public and private blobs still deserialize", () => {
    const pub = BaseComponent.DeserializeComponent(PINNED_PUBLIC_HEX); // hex string, as sent on the wire
    assert.ok(pub instanceof Ed25519PublicComponent);
    assert.equal(toHex(pub.Serialize().ToBytes()), PINNED_PUBLIC_HEX);

    const priv = BaseComponent.DeserializeComponent(fromHex(PINNED_PRIVATE_HEX));
    assert.ok(priv instanceof Ed25519PrivateComponent);
    assert.equal(toHex(priv.Serialize().ToBytes()), PINNED_PRIVATE_HEX);
    assert.equal(toHex(priv.GetPublic().Serialize().ToBytes()), PINNED_PUBLIC_HEX);
});

test("public and private blobs with a non-zero version nibble still parse (nibble ignored)", () => {
    const pubBytes = fromHex(PINNED_PUBLIC_HEX);
    pubBytes[0] |= 0x01; // 21 00 00
    const pub = BaseComponent.DeserializeComponent(pubBytes);
    assert.ok(pub instanceof Ed25519PublicComponent);
    assert.equal(toHex(pub.Serialize().ToBytes()), PINNED_PUBLIC_HEX); // reserializes as version 0

    const privBytes = fromHex(PINNED_PRIVATE_HEX);
    privBytes[0] |= 0x0F; // 1f 00 00
    const priv = BaseComponent.DeserializeComponent(privBytes);
    assert.ok(priv instanceof Ed25519PrivateComponent);
    assert.equal(toHex(priv.Serialize().ToBytes()), PINNED_PRIVATE_HEX);
});

// ---------------------------------------------------------------------------
// TideKey.NewKey
// ---------------------------------------------------------------------------

test("TideKey.NewKey(Ed25519Scheme) is synchronous and yields a version 0 key", async () => {
    const key = TideKey.NewKey(Ed25519Scheme);
    assert.ok(key instanceof TideKey); // not a Promise
    assert.ok(key.component instanceof Ed25519SeedComponent);
    assert.equal(toHex(key.component.Serialize().ToBytes().slice(0, 3)), "000000");

    const pub = key.get_public_component().Serialize().ToBytes();
    assert.equal(pub.length, 35);
    assert.equal(toHex(pub.slice(0, 3)), "200000");

    // still a working signing key
    const msg = new TextEncoder().encode("hello");
    const sig = await key.sign(msg);
    await TideKey.FromSerializedComponent(pub).verify(msg, sig);
});
