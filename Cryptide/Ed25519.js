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


import { Serialization } from "../Cryptide/index.js";
import { SHA256_Digest } from "./Hashing/Hash.js";
import { mod_inv } from "./Math.js";
import { BigIntFromByteArray, base64ToBytes, bytesToBase64 } from "./Serialization.js";

const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);

const Gx = BigInt("15112221349535400772501151409588531511454012693041857206046113283949847762202");
const Gy = BigInt("46316835694926478169428394003475163141307993866256225615783033603165251855960");
const Gz = BigInt("46827403850823179245072216630277197565144205554125654976674165829533817101731");

const A = BigInt(-1);
const D = BigInt("37095705934669439343138083508754565189542113879843219016388785533085940283555");
const P = BigInt("57896044618658097711785492504343953926634992332820282019728792003956564819949");
const Order = BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989");
const SQRT_M1 = BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
export default class Point {

    static get a() {return A};
    static get d() {return D;}
    static get d_FOR_Y_FROM_X() {return BigInt("20800338683988658368647408995589388737092878452977063003340006470870624536394");}
    static get p() {return P;}
    static get order() { return Order;}
    static get g() { return new Point(Gx, Gy, _1n, Gz);}
    static get infinity() {return new Point(_0n, _1n, _1n, _0n);} //infinity also known as identity for ed25519
    static get SQRT_M1() {return SQRT_M1;}


    /**
     * @param {bigint} x 
     * @param {bigint} y 
     * @param {bigint} z 
     * @param {bigint} t 
     * @param {Uint8Array}
     */
    constructor(x, y=null, z=null, t=null, compressedBytes=null) {
        this.x = x;
        this.y = y !== null ? y : getYfromX(x);
        this.z = z !== null ? z : _1n;
        this.t = t !== null ? t : mod(this.x * this.y);
        this.compressedBytes = compressedBytes
    }
    
    isInfinity(){
        return this.isEqual(Point.infinity); 
    }

    isEqual(other){
        const X1Z2 = mod(this.x * other.z);
        const X2Z1 = mod(other.x * this.z);
        const Y1Z2 = mod(this.y * other.z);
        const Y2Z1 = mod(other.y * this.z);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }

    negate(){
        return new Point(mod(-this.x), this.y, this.z, mod(-this.t));
    }


    /**
     * 
     * @param {bigint} num 
     * @returns {Point}
     */
    times(num, b) {
        if (typeof num !== 'bigint') throw Error("Can only multiply point by number");
        if(this.isEqual(Point.g) && b){
            return wNAF(num);
        }
        var point = new Point(this.x, this.y, this.z, this.t);
        let newPoint = Point.infinity;
        while (num > _0n) {
            if ((num & _1n) === (_1n)) {
                newPoint = newPoint.add(point);
            }
            point = point.double();
            num = num >> _1n;
        }
        return newPoint;
    }

    /**
     * 
     * @returns {Point}
     */
    double() {
        let A = mod(this.x * this.x);
        let B = mod(this.y * this.y);
        let C = mod(_2n * mod(this.z * this.z));
        let D = mod(Point.a * A);
        let x1y1 = this.x + this.y;
        let E = mod(mod(x1y1 * x1y1) - A - B);
        let G = D + B;
        let F = G - C;
        let H = D - B;
        let X3 = mod(E * F);
        let Y3 = mod(G * H);
        let T3 = mod(E * H);
        let Z3 = mod(F * G);
        return new Point(X3, Y3, Z3, T3);
    }

    /**
     * @param {Point} other 
     * @returns {Point}
     */
    add(other) {
        let A = mod((this.y - this.x) * (other.y + other.x));
        let B = mod((this.y + this.x) * (other.y - other.x));
        let F = mod(B - A);
        if (F == _0n) return this.double();
        let C = mod(this.z * _2n * other.t);
        let D = mod(this.t * _2n * other.z);
        let E = D + C;
        let G = B + A;
        let H = D - C;
        let X3 = mod(E * F);
        let Y3 = mod(G * H);
        let T3 = mod(E * H);
        let Z3 = mod(F * G);
        return new Point(X3, Y3, Z3, T3);
    }

    /**
     * @param {bigint} a 
     * @returns 
     */
    blur(a){
        return this.times(a);
    }
    /**
     * @param {bigint} a 
     * @returns 
     */
    unblur(a){
        return this.times(mod_inv_p(a, Point.order));
    }

    /**
     * 
     * @returns {bigint}
     */
    getX(){
        return mod(this.x * mod_inv_p(this.z));
    }
    /**
     * 
     * @returns {bigint}
     */
    getY(){
        return mod(this.y * mod_inv_p(this.z));
    }
    /**
     * @param {Uint8Array} data
     * @returns {Point}
     */
    static from(data){
        return this.decompress(data);
    }
    /**
     * @param {string} data
     * @returns {Point}
     */
    static fromB64(data){
        return data == null ? null : this.decompress(base64ToBytes(data));
    }

    /** @returns {Uint8Array} */
    toArray(){
        return this.compress();
    }

    async hash(){
        return mod(BigIntFromByteArray(await SHA256_Digest(this.toArray())));
    }

    /**
     * @returns {string}
     */
    toBase64(){
        return bytesToBase64(this.toArray());
    }

    /**@returns {Uint8Array} */
    compress(){
        if(this.compressedBytes != null) {
            return this.compressedBytes.slice();
        }
        const bytes = Serialization.BigIntToByteArray(this.getY());
        bytes[31] |= this.getX() & _1n ? 0x80 : 0;
        this.compressedBytes = bytes.slice();
        return bytes;
    }

    getOpenSSHPublicKey(){
        // these bytes read: 0, 0, 0, 11, "ssh-ed25519", 0, 0, 0, 32
        const staticBytes = new Uint8Array([0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20]);
        const keyBytes = this.toArray();
        const combinedBytesB64 = bytesToBase64(ConcatUint8Arrays([staticBytes, keyBytes]));

        return "ssh-ed25519 " + combinedBytesB64
    }

    /**
     * @param {Uint8Array} point_bytes 
     */
    static decompress(point_bytes){
        // 1.  First, interpret the string as an integer in little-endian
        // representation. Bit 255 of this number is the least significant
        // bit of the x-coordinate and denote this value x_0.  The
        // y-coordinate is recovered simply by clearing this bit.  If the
        // resulting value is >= p, decoding fails.
        const normed = point_bytes.slice();
        normed[31] = point_bytes[31] & ~0x80;
        const y = BigIntFromByteArray(normed);

        if ( y >= Point.p) throw new Error('Decompress: Expected 0 < hex < P');

        // 2.  To recover the x-coordinate, the curve equation implies
        // x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
        // non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
        const y2 = mod(y * y);
        const u = mod(y2 - _1n);
        const v = mod(Point.d * y2 + _1n);
        let { isValid, value: x } = uvRatio(u, v);
        if (!isValid) throw new Error('Decompress: invalid y coordinate');

        // 4.  Finally, use the x_0 bit to select the right square root.  If
        // x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
        // 2, set x <-- p - x.  Return the decoded point (x,y).
        const isXOdd = (x & _1n) === _1n;
        const isLastByteOdd = (point_bytes[31] & 0x80) !== 0;
        if (isLastByteOdd !== isXOdd) {
            x = mod(-x);
        }
        return new Point(x, y, null, null, point_bytes.slice());
    }
}

/**
 * @param {bigint} a 
 * @param {bigint} b 
 * @returns {bigint}
 */
function mod(a, b = Point.p) {
    var res = a % b;
    return res >= _0n ? res : b + res;
}

/**
 * @param {bigint} number 
 * @param {bigint} modulo 
 * @returns {bigint}
 */
function mod_inv_p(number, modulo = Point.p) {
    return mod_inv(number, modulo);
}

/**
 * @param {bigint} x 
 * @returns 
 */
 function getYfromX(x){
    // Always get 'higher' point. Remember there are two possible values, this always picks the first one to remain consistent.
    var x2 = mod(x * x);
    var u = mod(_1n + x2);
    var v = mod(_1n + Point.d_FOR_Y_FROM_X*x2);

    return uvRatio(u, v).value;
}

/**
 * @param {bigint} x 
 * @param {bigint} power 
 * @returns 
 */
function pow2(x, power){
    while (power-- > _0n) {
        x = mod(x * x);
    }
    return x;
}
// Power to (p-5)/8 aka x^(2^252-3)
// Used to calculate y - the square root of y².
// Exponentiates it to very big number.
// We are unwrapping the loop because it's 2x faster.
// (2n**252n-3n).toString(2) would produce bits [250x 1, 0, 1]
// We are multiplying it bit-by-bit
/**
 * 
 * @param {bigint} x 
 * @returns 
 */
//works
function pow_2_252_3(x) {
    const P = Point.p;
    const _5n = BigInt(5);
    const _10n = BigInt(10);
    const _20n = BigInt(20);
    const _40n = BigInt(40);
    const _80n = BigInt(80);
    const x2 = (x * x) % P;
    const b2 = (x2 * x) % P; // x^3, 11
    const b4 = (pow2(b2, _2n) * b2) % P; // x^15, 1111
    const b5 = (pow2(b4, _1n) * x) % P; // x^31
    const b10 = (pow2(b5, _5n) * b5) % P;
    const b20 = (pow2(b10, _10n) * b10) % P;
    const b40 = (pow2(b20, _20n) * b20) % P;
    const b80 = (pow2(b40, _40n) * b40) % P;
    const b160 = (pow2(b80, _80n) * b80) % P;
    const b240 = (pow2(b160, _80n) * b80) % P;
    const b250 = (pow2(b240, _10n) * b10) % P;
    const pow_p_5_8 = (pow2(b250, _2n) * x) % P;
    // ^ To pow to (p+3)/8, multiply it by x.
    return {pow_p_5_8, b2};
}
// this method is incomplete. not ready for ed25519 point decoding
/**
 * 
 * @param {bigint} u 
 * @param {bigint} v 
 * @returns 
 */
function uvRatio(u, v) {
    const v3 = mod(v * v * v);                  // v³
    const v7 = mod(v3 * v3 * v);                // v⁷
    const pow = pow_2_252_3(u * v7).pow_p_5_8;
    let x = mod(u * v3 * pow);                  // (uv³)(uv⁷)^(p-5)/8
    const vx2 = mod(v * x * x);                 // vx²
    const root1 = x;                            // First root candidate
    const root2 = mod(x * Point.SQRT_M1);             // Second root candidate
    const useRoot1 = vx2 === u;                 // If vx² = u (mod p), x is a square root
    const useRoot2 = vx2 === mod(-u);           // If vx² = -u, set x <-- x * 2^((p-1)/4)
    const noRoot = vx2 === mod(-u * Point.SQRT_M1);   // There is no valid root, vx² = -u√(-1)
    if (useRoot1) x = root1;
    if (useRoot2 || noRoot) x = root2;          // We return root2 anyway, for const-time
    if (edIsNegative(x)) x = mod(-x);
    return { isValid: useRoot1 || useRoot2, value: x };
  }
// Little-endian check for first LE bit (last BE bit);
function edIsNegative(num) {
    return (mod(num) & _1n) === _1n;
}

const W = 8; // Precomputes-related code. W = window size
const precompute = () => {
    console.log("precomputing...")
    const points = []; // 10x sign(), 2x verify(). To achieve this,
    const windows = 256 / W + 1; // app needs to spend 40ms+ to calculate
    let p = Point.g, b = p; // a lot of points related to base point G.
    for (let w = 0; w < windows; w++) { // Points are stored in array and used
        b = p; // any time Gx multiplication is done.
        points.push(b); // They consume 16-32 MiB of RAM.
        for (let i = 1; i < 2 ** (W - 1); i++) {
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
    const neg = (cnd, p) => { let n = p.negate(); return cnd ? n : p; }; // negate
    let p = Point.infinity;
    const windows = 1 + 256 / W; // W=8 17 windows
    const wsize = 2 ** (W - 1); // W=8 128 window size
    const mask = BigInt(2 ** W - 1); // W=8 will create mask 0b11111111
    const maxNum = 2 ** W; // W=8 256
    const shiftBy = BigInt(W); // W=8 8
    for (let w = 0; w < windows; w++) {
        const off = w * wsize;
        let wbits = Number(n & mask); // extract W bits.
        n >>= shiftBy; // shift number by W bits.
        if (wbits > wsize) {
            wbits -= maxNum;
            n += 1n;
        } // split if bits > max: +224 => 256-32
        const off2 = off + Math.abs(wbits) - 1; // offsets, evaluate both
        const cnd2 = wbits < 0; // conditions, evaluate both

        if (wbits !== 0) {
            p = p.add(neg(cnd2, comp[off2])); // bits are 1: add to result point
        }
    }
    return p; // return both real and fake points for JIT
};