/**
 * ed25519 curve parameters. Equation is −x² + y² = -a + dx²y².
 * Gx and Gy are generator coordinates. p is field order, n is group order.
 * h is cofactor.
 */
declare const CURVE: {
    a: bigint;
    d: bigint;
    p: bigint;
    n: bigint;
    h: number;
    Gx: bigint;
    Gy: bigint;
};
/** Point in xyzt extended coordinates. */
declare class Point {
    constructor(ex: any, ey: any, ez: any, et: any);
    static fromAffine(p: any): Point;
    /** RFC8032 5.1.3: hex / Uint8Array to Point. */
    static fromHex(hex: any): Point;
    static fromBase64(b64string: any): Point;
    static fromBytes(bytes: any, zip215?: boolean): Point;
    get x(): bigint;
    get y(): bigint;
    assertValidity(): boolean;
    equals(other: any): boolean;
    is0(): boolean;
    negate(): Point;
    /** Point doubling. Complete formula. */
    double(): Point;
    /** Point addition. Complete formula. */
    add(other: any): Point;
    mul(n: any, safe?: boolean): any;
    multiply(scalar: any): any;
    divide(scalar: any): any;
    clearCofactor(): any;
    isSmallOrder(): any;
    isTorsionFree(): any;
    /** converts point to 2d xy affine point. (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy). */
    toAffine(): {
        x: bigint;
        y: bigint;
    };
    toRawBytes(): Uint8Array<any>;
    toHex(): string;
    toBase64(): string;
    hash(): Promise<bigint>;
}
/** Creates 32-byte ed25519 public key from 32-byte private key. Async. */
declare const getPublicKeyAsync: (priv: any) => Promise<any>;
/** Creates 32-byte ed25519 public key from 32-byte private key. To use, set `etc.sha512Sync` first. */
declare const getPublicKey: (priv: any) => any;
/** Signs message (NOT message hash) using private key. Async. */
declare const signAsync: (msg: any, privKey: any) => Promise<any>;
/** Signs message (NOT message hash) using private key without determinism. Async. */
declare const signNonDeterministicAsync: (msg: any, privKey: any) => Promise<any>;
/** Signs message (NOT message hash) using private key. To use, set `etc.sha512Sync` first. */
declare const sign: (msg: any, privKey: any) => any;
/** Verifies signature on message and public key. Async. */
declare const verifyAsync: (s: any, m: any, p: any, opts?: {
    zip215: boolean;
}) => Promise<any>;
/** Verifies signature on message and public key. To use, set `etc.sha512Sync` first. */
declare const verify: (s: any, m: any, p: any, opts?: {
    zip215: boolean;
}) => any;
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
declare const etc: {
    bytesToHex: (b: any) => string;
    hexToBytes: (hex: any) => Uint8Array<any>;
    concatBytes: (...arrs: any[]) => Uint8Array<any>;
    mod: (a: any, b?: bigint) => bigint;
    invert: (num: any, md: any) => bigint;
    randomBytes: (len?: number) => Uint8Array<any>;
    sha512Async: (...messages: any[]) => Promise<Uint8Array<any>>;
    sha512Sync: any;
    bigIntToBytes: (num: any) => Uint8Array<any>;
    bytesToBigInt: (b: any) => bigint;
};
/** ed25519-specific key utilities. */
declare const utils: {
    getExtendedPublicKeyAsync: (priv: any) => Promise<{
        head: any;
        prefix: any;
        scalar: bigint;
        point: any;
        pointBytes: any;
    }>;
    getExtendedPublicKey: (priv: any) => {
        head: any;
        prefix: any;
        scalar: bigint;
        point: any;
        pointBytes: any;
    };
    randomPrivateKey: () => Uint8Array<any>;
    precompute: (w?: number, p?: any) => any;
};
export { CURVE, etc, Point, getPublicKey, getPublicKeyAsync, sign, signAsync, signNonDeterministicAsync, utils, verify, verifyAsync };
