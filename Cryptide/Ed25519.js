//
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
//
// This program is free software and is subject to the terms of
// the Tide Community Open Code License as published by the
// Tide Foundation Limited. You may modify it and redistribute
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind,
// including without any implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//
// Some parts of the code were taken from @noble/curves project and are protected under the following license:
//
// The MIT License (MIT)
// 
// Copyright (c) 2022 Paul Miller (https://paulmillr.com)
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
// 
import { base64ToBytes, bytesToBase64 } from "./Serialization.js";
import { SHA256_Digest } from "./Hashing/Hash.js";


const P = 2n ** 255n - 19n; // ed25519 is twisted edwards curve
const N = 2n ** 252n + 27742317777372353535851937790883648493n; // curve's (group) order
const Gx = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an; // base point x
const Gy = 0x6666666666666666666666666666666666666666666666666666666666666658n; // base point y
const _d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const MASK = 2n ** 256n;
/**
 * ed25519 curve parameters. Equation is −x² + y² = -a + dx²y².
 * Gx and Gy are generator coordinates. p is field order, n is group order.
 * h is cofactor.
 */
const CURVE = {
    a: -1n, // -1 mod p
    d: _d, // -(121665/121666) mod p
    p: P, n: N, h: 8, Gx: Gx, Gy: Gy // field prime, curve (group) order, cofactor
};
const err = (m = '') => { throw new Error(m); }; // error helper, messes-up stack trace
const isS = (s) => typeof s === 'string'; // is string
const isB = (s) => typeof s === 'bigint'; // is bigint
const isu8 = (a) => (a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array'));
const au8 = (a, l) => // is Uint8Array (of specific length)
 !isu8(a) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array of valid length expected') : a;
const u8n = (len) => new Uint8Array(len); // creates Uint8Array
const u8fr = (buf) => Uint8Array.from(buf);
const toU8 = (a, len) => au8(isS(a) ? h2b(a) : u8fr(au8(a)), len); // norm(hex/u8a) to u8a
const M = (a, b = P) => { let r = a % b; return r >= 0n ? r : b + r; }; // mod division
const arange = (n, min, max = MASK, msg = 'bad number: out of range') => isB(n) && min <= n && n < max ? n : err(msg);
const apoint = (p) => (p instanceof Point ? p : err('Point expected')); // is xyzt point
/** Point in xyzt extended coordinates. */
class Point {
    constructor(ex, ey, ez, et) {
        this.ex = arange(ex, 0n);
        this.ey = arange(ey, 0n);
        this.ez = arange(ez, 1n);
        this.et = arange(et, 0n);
        Object.freeze(this);
    }
    static fromAffine(p) { return new Point(p.x, p.y, 1n, M(p.x * p.y)); }
    /** RFC8032 5.1.3: hex / Uint8Array to Point. */
    static fromHex(hex) {
        hex = toU8(hex, 32);
        return this.fromBytes(hex);
    }
    static fromBase64(b64string){
        if(isS(b64string)) return this.fromBytes(base64ToBytes(b64string));
        else err("Point.fromBase64 not provided with a string");
    }
    static fromBytes(bytes, zip215 = false){
        const { d } = CURVE;
        const normed = bytes.slice(); // copy the array to not mess it up
        const lastByte = bytes[31];
        normed[31] = lastByte & ~0x80; // adjust first LE byte = last BE byte
        const y = b2n_LE(normed); // decode as little-endian, convert to num
        const max = zip215 ? MASK : P; // RFC8032 prohibits >= p, ZIP215 doesn't
        arange(y, 0n, max); // zip215=true:  0 <= y < 2^256
        // zip215=false: 0 <= y < 2^255-19
        const y2 = M(y * y); // y²
        const u = M(y2 - 1n); // u=y²-1
        const v = M(d * y2 + 1n); // v=dy²+1
        let { isValid, value: x } = uvRatio(u, v); // (uv³)(uv⁷)^(p-5)/8; square root
        if (!isValid)
            err('bad y coord 3'); // not square root: bad point
        const isXOdd = (x & 1n) === 1n; // adjust sign of x coordinate
        const isLastByteOdd = (lastByte & 0x80) !== 0; // x_0, last bit
        if (!zip215 && x === 0n && isLastByteOdd)
            err('bad y coord 4'); // x=0 and x_0 = 1
        if (isLastByteOdd !== isXOdd)
            x = M(-x);
        return new Point(x, y, 1n, M(x * y)); // Z=1, T=xy
    }
    get x() { return this.toAffine().x; } // .x, .y will call expensive toAffine.
    get y() { return this.toAffine().y; } // Should be used with care.
    assertValidity() {
        const { a, d } = CURVE;
        const p = this;
        if (p.is0())
            throw new Error('bad point: ZERO'); // TODO: optimize, with vars below?
        // Equation in affine coordinates: ax² + y² = 1 + dx²y²
        // Equation in projective coordinates (X/Z, Y/Z, Z):  (aX² + Y²)Z² = Z⁴ + dX²Y²
        const { ex: X, ey: Y, ez: Z, et: T } = p;
        const X2 = M(X * X); // X²
        const Y2 = M(Y * Y); // Y²
        const Z2 = M(Z * Z); // Z²
        const Z4 = M(Z2 * Z2); // Z⁴
        const aX2 = M(X2 * a); // aX²
        const left = M(Z2 * M(aX2 + Y2)); // (aX² + Y²)Z²
        const right = M(Z4 + M(d * M(X2 * Y2))); // Z⁴ + dX²Y²
        if (left !== right)
            throw new Error('bad point: equation left != right (1)');
        // In Extended coordinates we also have T, which is x*y=T/Z: check X*Y == Z*T
        const XY = M(X * Y);
        const ZT = M(Z * T);
        if (XY !== ZT)
            throw new Error('bad point: equation left != right (2)');
        return true;
    }
    equals(other) {
        const { ex: X1, ey: Y1, ez: Z1 } = this;
        const { ex: X2, ey: Y2, ez: Z2 } = apoint(other); // isPoint() checks class equality
        const X1Z2 = M(X1 * Z2), X2Z1 = M(X2 * Z1);
        const Y1Z2 = M(Y1 * Z2), Y2Z1 = M(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() { return this.equals(I); }
    negate() {
        return new Point(M(-this.ex), this.ey, this.ez, M(-this.et));
    }
    /** Point doubling. Complete formula. */
    double() {
        const { ex: X1, ey: Y1, ez: Z1 } = this; // Cost: 4M + 4S + 1*a + 6add + 1*2
        const { a } = CURVE; // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
        const A = M(X1 * X1);
        const B = M(Y1 * Y1);
        const C = M(2n * M(Z1 * Z1));
        const D = M(a * A);
        const x1y1 = X1 + Y1;
        const E = M(M(x1y1 * x1y1) - A - B);
        const G = D + B;
        const F = G - C;
        const H = D - B;
        const X3 = M(E * F);
        const Y3 = M(G * H);
        const T3 = M(E * H);
        const Z3 = M(F * G);
        return new Point(X3, Y3, Z3, T3);
    }
    /** Point addition. Complete formula. */
    add(other) {
        const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this; // Cost: 8M + 1*k + 8add + 1*2.
        const { ex: X2, ey: Y2, ez: Z2, et: T2 } = apoint(other); // doesn't check if other on-curve
        const { a, d } = CURVE; // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
        const A = M(X1 * X2);
        const B = M(Y1 * Y2);
        const C = M(T1 * d * T2);
        const D = M(Z1 * Z2);
        const E = M((X1 + Y1) * (X2 + Y2) - A - B);
        const F = M(D - C);
        const G = M(D + C);
        const H = M(B - a * A);
        const X3 = M(E * F);
        const Y3 = M(G * H);
        const T3 = M(E * H);
        const Z3 = M(F * G);
        return new Point(X3, Y3, Z3, T3);
    }
    mul(n, safe = true) {
        if (n === 0n)
            return safe === true ? err('cannot multiply by 0') : I;
        arange(n, 1n, N);
        if (n === 1n || (!safe && this.is0()))
            return this; // safe=true bans 0. safe=false allows 0.
        if (this.equals(G))
            return wNAF(n).p; // use wNAF precomputes for base points
        let p = I, f = G; // init result point & fake point
        for (let d = this; n > 0n; d = d.double(), n >>= 1n) { // double-and-add ladder
            if (n & 1n)
                p = p.add(d); // if bit is present, add to point
            else if (safe)
                f = f.add(d); // if not, add to fake for timing safety
        }
        return p;
    }
    multiply(scalar) { return this.mul(scalar); } // Aliases for compatibilty
    divide(scalar) { return this.mul(invert(scalar, CURVE.n)); }
    clearCofactor() { return this.mul(BigInt(CURVE.h), false); } // multiply by cofactor
    isSmallOrder() { return this.clearCofactor().is0(); } // check if P is small order
    isTorsionFree() {
        let p = this.mul(N / 2n, false).double(); // ensures the point is not "bad".
        if (N % 2n)
            p = p.add(this); // P^(N+1)             // P*N == (P*(N/2))*2+P
        return p.is0();
    }
    /** converts point to 2d xy affine point. (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy). */
    toAffine() {
        const { ex: x, ey: y, ez: z } = this;
        if (this.equals(I))
            return { x: 0n, y: 1n }; // fast-path for zero point
        const iz = invert(z, P); // z^-1: invert z
        if (M(z * iz) !== 1n)
            err('invalid inverse'); // (z * z^-1) must be 1, otherwise bad math
        return { x: M(x * iz), y: M(y * iz) }; // x = x*z^-1; y = y*z^-1
    }
    toRawBytes() {
        const { x, y } = this.toAffine(); // convert to affine 2d point
        this.assertValidity();
        const b = n2b_32LE(y); // encode number to 32 bytes
        b[31] |= x & 1n ? 0x80 : 0; // store sign in first LE byte
        return b;
    }
    toHex() { return b2h(this.toRawBytes()); } // encode to hex string
    toBase64(){ return bytesToBase64(this.toRawBytes()); }
    async hash(){ return M(b2n_LE(await SHA256_Digest(this.toRawBytes())), CURVE.n); }
}
/** Generator / Base point */
Point.BASE = new Point(Gx, Gy, 1n, M(Gx * Gy));
/** Identity / Zero point */
Point.ZERO = new Point(0n, 1n, 1n, 0n);
const { BASE: G, ZERO: I } = Point; // Generator, identity points
const padh = (num, pad) => num.toString(16).padStart(pad, '0');
const b2h = (b) => Array.from(au8(b)).map(e => padh(e, 2)).join(''); // bytes to hex
const C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 }; // ASCII characters
const _ch = (ch) => {
    if (ch >= C._0 && ch <= C._9)
        return ch - C._0; // '2' => 50-48
    if (ch >= C.A && ch <= C.F)
        return ch - (C.A - 10); // 'B' => 66-(65-10)
    if (ch >= C.a && ch <= C.f)
        return ch - (C.a - 10); // 'b' => 98-(97-10)
    return;
};
const h2b = (hex) => {
    const e = 'hex invalid';
    if (!isS(hex))
        return err(e);
    const hl = hex.length, al = hl / 2;
    if (hl % 2)
        return err(e);
    const array = u8n(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) { // treat each char as ASCII
        const n1 = _ch(hex.charCodeAt(hi)); // parse first char, multiply it by 16
        const n2 = _ch(hex.charCodeAt(hi + 1)); // parse second char
        if (n1 === undefined || n2 === undefined)
            return err(e);
        array[ai] = n1 * 16 + n2; // example: 'A9' => 10*16 + 9
    }
    return array;
};
const n2b_32LE = (num) => h2b(padh(num, 32 * 2)).reverse(); // number to bytes LE
const b2n_LE = (b) => BigInt('0x' + b2h(u8fr(au8(b)).reverse())); // bytes LE to num
const concatB = (...arrs) => {
    const r = u8n(arrs.reduce((sum, a) => sum + au8(a).length, 0)); // create u8a of summed length
    let pad = 0; // walk through each array,
    arrs.forEach(a => { r.set(a, pad); pad += a.length; }); // ensure they have proper type
    return r;
};
const invert = (num, md) => {
    if(!isB(num)) throw Error("Expecting bigint");
    if (num === 0n || md <= 0n)
        err('no inverse n=' + num + ' mod=' + md); // no neg exponent for now
    let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
    while (a !== 0n) { // uses euclidean gcd algorithm
        const q = b / a, r = b % a; // not constant-time
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    return b === 1n ? M(x, md) : err('no inverse'); // b is gcd at this point
};
const pow2 = (x, power) => {
    let r = x;
    while (power-- > 0n) {
        r *= r;
        r %= P;
    }
    return r;
};
const pow_2_252_3 = (x) => {
    const x2 = (x * x) % P; // x^2,       bits 1
    const b2 = (x2 * x) % P; // x^3,       bits 11
    const b4 = (pow2(b2, 2n) * b2) % P; // x^(2^4-1), bits 1111
    const b5 = (pow2(b4, 1n) * x) % P; // x^(2^5-1), bits 11111
    const b10 = (pow2(b5, 5n) * b5) % P; // x^(2^10)
    const b20 = (pow2(b10, 10n) * b10) % P; // x^(2^20)
    const b40 = (pow2(b20, 20n) * b20) % P; // x^(2^40)
    const b80 = (pow2(b40, 40n) * b40) % P; // x^(2^80)
    const b160 = (pow2(b80, 80n) * b80) % P; // x^(2^160)
    const b240 = (pow2(b160, 80n) * b80) % P; // x^(2^240)
    const b250 = (pow2(b240, 10n) * b10) % P; // x^(2^250)
    const pow_p_5_8 = (pow2(b250, 2n) * x) % P; // < To pow to (p+3)/8, multiply it by x.
    return { pow_p_5_8, b2 };
};
const RM1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n; // √-1
const uvRatio = (u, v) => {
    const v3 = M(v * v * v); // v³
    const v7 = M(v3 * v3 * v); // v⁷
    const pow = pow_2_252_3(u * v7).pow_p_5_8; // (uv⁷)^(p-5)/8
    let x = M(u * v3 * pow); // (uv³)(uv⁷)^(p-5)/8
    const vx2 = M(v * x * x); // vx²
    const root1 = x; // First root candidate
    const root2 = M(x * RM1); // Second root candidate; RM1 is √-1
    const useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
    const useRoot2 = vx2 === M(-u); // If vx² = -u, set x <-- x * 2^((p-1)/4)
    const noRoot = vx2 === M(-u * RM1); // There is no valid root, vx² = -u√-1
    if (useRoot1)
        x = root1;
    if (useRoot2 || noRoot)
        x = root2; // We return root2 anyway, for const-time
    if ((M(x) & 1n) === 1n)
        x = M(-x); // edIsNegative
    return { isValid: useRoot1 || useRoot2, value: x };
};
const modL_LE = (hash) => M(b2n_LE(hash), N); // modulo L; but little-endian
const sha512a = (...m) => etc.sha512Async(...m); // Async SHA512
const sha512s = (...m) => {
    const fn = etc.sha512Sync;
    if (typeof fn !== 'function')
        err('etc.sha512Sync not set');
    return fn(...m);
};
const hash2extK = (hashed) => {
    const head = hashed.slice(0, 32); // slice creates a copy, unlike subarray
    head[0] &= 248; // Clamp bits: 0b1111_1000,
    head[31] &= 127; // 0b0111_1111,
    head[31] |= 64; // 0b0100_0000
    const prefix = hashed.slice(32, 64); // private key "prefix"
    const scalar = modL_LE(head); // modular division over curve order
    const point = G.mul(scalar); // public key point
    const pointBytes = point.toRawBytes(); // point serialized to Uint8Array
    return { head, prefix, scalar, point, pointBytes };
};
// RFC8032 5.1.5; getPublicKey async, sync. Hash priv key and extract point.
const getExtendedPublicKeyAsync = (priv) => sha512a(toU8(priv, 32)).then(hash2extK);
const getExtendedNonDeterministicPublicKeyAsync = (priv) => {
    const prefix = etc.randomBytes(32); // private key "prefix"
    const point = G.mul(priv); // public key point
    const pointBytes = point.toRawBytes(); // point serialized to Uint8Array
    return { head: undefined, prefix, scalar: priv, point, pointBytes }; // head is undefined as we didn't hash the priv
}
const getExtendedPublicKey = (priv) => hash2extK(sha512s(toU8(priv, 32)));
/** Creates 32-byte ed25519 public key from 32-byte private key. Async. */
const getPublicKeyAsync = (priv) => getExtendedPublicKeyAsync(priv).then(p => p.pointBytes);
/** Creates 32-byte ed25519 public key from 32-byte private key. To use, set `etc.sha512Sync` first. */
const getPublicKey = (priv) => getExtendedPublicKey(priv).pointBytes;
function hashFinish(asynchronous, res) {
    if (asynchronous)
        return sha512a(res.hashable).then(res.finish);
    return res.finish(sha512s(res.hashable));
}
const _sign = (e, rBytes, msg) => {
    const { pointBytes: P, scalar: s } = e;
    const r = modL_LE(rBytes); // r was created outside, reduce it modulo L
    const R = G.mul(r).toRawBytes(); // R = [r]B
    const hashable = concatB(R, P, msg); // dom2(F, C) || R || A || PH(M)
    const finish = (hashed) => {
        const S = M(r + modL_LE(hashed) * s, N); // S = (r + k * s) mod L; 0 <= s < l
        return au8(concatB(R, n2b_32LE(S)), 64); // 64-byte sig: 32b R.x + 32b LE(S)
    };
    return { hashable, finish };
};
/** Signs message (NOT message hash) using private key. Async. */
const signAsync = async (msg, privKey) => {
    const m = toU8(msg); // RFC8032 5.1.6: sign msg with key async
    const e = await getExtendedPublicKeyAsync(privKey); // pub,prfx
    const rBytes = await sha512a(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
    return hashFinish(true, _sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
/** Signs message (NOT message hash) using private key without determinism. Async. */
const signNonDeterministicAsync = async (msg, privKey) => {
    const m = toU8(msg); // RFC8032 5.1.6: sign msg with key async
    const e = await getExtendedNonDeterministicPublicKeyAsync(privKey); // pub,prfx
    const rBytes = await sha512a(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
    return hashFinish(true, _sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
/** Signs message (NOT message hash) using private key. To use, set `etc.sha512Sync` first. */
const sign = (msg, privKey) => {
    const m = toU8(msg); // RFC8032 5.1.6: sign msg with key sync
    const e = getExtendedPublicKey(privKey); // pub,prfx
    const rBytes = sha512s(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
    return hashFinish(false, _sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
const dvo = { zip215: false }; // Julio set this to false
const _verify = (sig, msg, pub, opts = dvo) => {
    sig = toU8(sig, 64); // Signature hex str/Bytes, must be 64 bytes
    msg = toU8(msg); // Message hex str/Bytes
    pub = toU8(pub, 32);
    const { zip215 } = opts; // switch between zip215 and rfc8032 verif
    let A, R, s, SB, hashable = new Uint8Array();
    try {
        A = Point.fromHex(pub, zip215); // public key A decoded
        R = Point.fromHex(sig.slice(0, 32), zip215); // 0 <= R < 2^256: ZIP215 R can be >= P
        s = b2n_LE(sig.slice(32, 64)); // Decode second half as an integer S
        SB = G.mul(s, false); // in the range 0 <= s < L
        hashable = concatB(R.toRawBytes(), A.toRawBytes(), msg); // dom2(F, C) || R || A || PH(M)
    }
    catch (error) { }
    const finish = (hashed) => {
        if (SB == null)
            return false; // false if try-catch catched an error
        if (!zip215 && A.isSmallOrder())
            return false; // false for SBS: Strongly Binding Signature
        const k = modL_LE(hashed); // decode in little-endian, modulo L
        const RkA = R.add(A.mul(k, false)); // [8]R + [8][k]A'
        return RkA.add(SB.negate()).clearCofactor().is0(); // [8][S]B = [8]R + [8][k]A'
    };
    return { hashable, finish };
};
// RFC8032 5.1.7: verification async, sync
/** Verifies signature on message and public key. Async. */
const verifyAsync = async (s, m, p, opts = dvo) => hashFinish(true, _verify(s, m, p, opts));
/** Verifies signature on message and public key. To use, set `etc.sha512Sync` first. */
const verify = (s, m, p, opts = dvo) => hashFinish(false, _verify(s, m, p, opts));
const cr = () => // We support: 1) browsers 2) node.js 19+
 typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
const subtle = () => {
    const c = cr();
    return c && c.subtle || err('crypto.subtle must be defined');
};
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
const etc = {
    bytesToHex: b2h,
    hexToBytes: h2b,
    concatBytes: concatB,
    mod: M,
    invert: invert,
    randomBytes: (len = 32) => {
        const c = cr(); // Can be shimmed in node.js <= 18 to prevent error:
        // import { webcrypto } from 'node:crypto';
        // if (!globalThis.crypto) globalThis.crypto = webcrypto;
        if (!c || !c.getRandomValues)
            err('crypto.getRandomValues must be defined');
        return c.getRandomValues(u8n(len));
    },
    sha512Async: async (...messages) => {
        const s = subtle();
        const m = concatB(...messages);
        return u8n(await s.digest('SHA-512', m.buffer));
    },
    sha512Sync: undefined, // Actual logic below
    bigIntToBytes: n2b_32LE,
    bytesToBigInt: b2n_LE
};
/** ed25519-specific key utilities. */
const utils = {
    getExtendedPublicKeyAsync: getExtendedPublicKeyAsync,
    getExtendedPublicKey: getExtendedPublicKey,
    randomPrivateKey: () => etc.randomBytes(32),
    precompute: (w = 8, p = G) => { p.multiply(3n); w; return p; }, // no-op
};
const W = 8; // Precomputes-related code. W = window size
const scalarBits = 256;
const pwindows = Math.ceil(scalarBits / W) + 1;
const pwindowSize = 2 ** (W - 1);
const precompute = () => {
    const points = []; // 10x sign(), 2x verify(). To achieve this,
    let p = G, b = p; // a lot of points related to base point G.
    for (let w = 0; w < pwindows; w++) { // Points are stored in array and used
        b = p; // any time Gx multiplication is done.
        points.push(b); // They consume 16-32 MiB of RAM.
        for (let i = 1; i < pwindowSize; i++) {
            b = b.add(p);
            points.push(b);
        }
        p = b.double(); // Precomputes don't speed-up getSharedKey,
    } // which multiplies user point by scalar,
    return points; // when precomputes are using base point
};
let Gpows = undefined; // precomputes for base point G
const wNAF = (n) => {
    // Compared to other point mult methods,
    const comp = Gpows || (Gpows = precompute()); // stores 2x less points using subtraction
    const ctneg = (cnd, p) => { let n = p.negate(); return cnd ? n : p; }; // negate
    let p = I, f = G; // f must be G, or could become I in the end
    const pow_2_w = 2 ** W; // W=8 256
    const maxNum = pow_2_w; // W=8 256
    const mask = BigInt(pow_2_w - 1); // W=8 255 == mask 0b11111111
    const shiftBy = BigInt(W); // W=8 8
    for (let w = 0; w < pwindows; w++) {
        let wbits = Number(n & mask); // extract W bits.
        n >>= shiftBy; // shift number by W bits.
        if (wbits > pwindowSize) {
            wbits -= maxNum;
            n += 1n;
        } // split if bits > max: +224 => 256-32
        const off = w * pwindowSize;
        const offF = off, offP = off + Math.abs(wbits) - 1; // offsets, evaluate both
        const isEven = w % 2 !== 0, isNeg = wbits < 0; // conditions, evaluate both
        if (wbits === 0) {
            f = f.add(ctneg(isEven, comp[offF])); // bits are 0: add garbage to fake point
        }
        else { //          ^ can't add off2, off2 = I
            p = p.add(ctneg(isNeg, comp[offP])); // bits are 1: add to result point
        }
    }
    return { p, f }; // return both real and fake points for JIT
}; // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()
// !! Remove the export to easily use in REPL / browser console
export { CURVE, etc, Point, getPublicKey, getPublicKeyAsync, sign, signAsync, signNonDeterministicAsync, utils, verify, verifyAsync };
