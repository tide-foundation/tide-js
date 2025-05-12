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

import { Point } from "../Ed25519.js";
import { ConcatUint8Arrays, BigIntFromByteArray } from "../Serialization.js";
import { mod, mod_inv } from "../Math.js";
import { SHA512_Digest } from "./Hash.js";

const curveP = BigInt("57896044618658097711785492504343953926634992332820282019728792003956564819949");


const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2);


function Fp_FpInvertBatch(nums) {
    const tmp = new Array(nums.length);
    // Walk from first to last, multiply them by each other MOD p
    const lastMultiplied = nums.reduce((acc, num, i) => {
        if (num===_0n)
            return acc;
        tmp[i] = acc;
        return multiply_nums(acc, num);
    }, _1n);
    // Invert last element
    const inverted = mod_inv(lastMultiplied,curveP);
    // Walk from last to first, multiply them by inverted each other MOD p
    nums.reduceRight((acc, num, i) => {
        if (num===_0n)
            return acc;
        tmp[i] = multiply_nums(acc, tmp[i]);
        return multiply_nums(acc, num);
    }, inverted);
    return tmp;
}; 

//functions from field
function cmov(a,b,c){return(c ? b : a);}; //returns b if c is true and returns a if c is false
function add_nums(num1,num2,modulus=curveP){return mod(num1+num2,modulus);}; //adds 2 numbers together then uses mod to ensure that they are not greater than the curveP value
function multiply_nums(num1,num2,modulus=curveP){return mod(BigInt(num1*num2),modulus);}; //multiplies numbers then reduces them below curveP
function to_the_power_of(number,power,modulus=curveP){
    if (power < _0n)
        throw new Error('Expected power > 0');
    if (power === _0n)
        return _1n;
    if (power === _1n)
        return number;
    let p = _1n;
    let d = number;
    while (power > _0n) {
        if (power & _1n)
            p = multiply_nums(p, d, modulus);
        d = multiply_nums(d, d, modulus);
        power >>= _1n;
    };
    return p;
};// raises a number to a certain power while keeping values below curveP
//constants used in the map_to_curve functions
const ELL2_C1_EDWARDS = BigInt('6853475219497561581579357271197624642482790079785650197046958215289687604742')//hard coded as the field only has one value in this case Fp = Field(ED25519_P, undefined, true); ELL2_C1_EDWARDS = FpSqrtEven(Fp, Fp.neg(BigInt(486664))); // sgn0(c1) MUST equal 0
const ELL2_C1 = (curveP + BigInt(3)) / BigInt(8); // 1. c1 = (q + 3) / 8       # Integer arithmetic
const ELL2_C2 = to_the_power_of(_2n, ELL2_C1); // 2. c2 = 2^c1
const ELL2_C3 = BigInt('38214883241950591754978413199355411911188925816896391856984770930832735035197');//hard coded sqrt value of ELL2_C3 = Fp.sqrt(Fp.neg(Fp.ONE)); // 3. c3 = sqrt(-1)
const ELL2_C4 = (curveP - BigInt(5)) / BigInt(8); // 4. c4 = (q - 5) / 8       # Integer arithmetic
const ELL2_J = BigInt(486662);

function map_to_curve_elligator2_curve25519_(u) {
    let tv1 = multiply_nums(u,u); //  1.  tv1 = u^2
    tv1 = multiply_nums(tv1, _2n); //  2.  tv1 = 2 * tv1
    let xd = add_nums(tv1,_1n); //  3.   xd = tv1 + 1         # Nonzero: -1 is square (mod p), tv1 is not
    let x1n = -ELL2_J; //  4.  x1n = -J              # x1 = x1n / xd = -J / (1 + 2 * u^2)
    let tv2 = multiply_nums(xd,xd); //  5.  tv2 = xd^2
    let gxd = multiply_nums(tv2, xd); //  6.  gxd = tv2 * xd        # gxd = xd^3
    let gx1 = multiply_nums(tv1, ELL2_J); //  7.  gx1 = J * tv1         # x1n + J * xd
    gx1 = multiply_nums(gx1, x1n); //  8.  gx1 = gx1 * x1n       # x1n^2 + J * x1n * xd
    gx1 = add_nums(gx1, tv2); //  9.  gx1 = gx1 + tv2       # x1n^2 + J * x1n * xd + xd^2
    gx1 = multiply_nums(gx1, x1n); //  10. gx1 = gx1 * x1n       # x1n^3 + J * x1n^2 * xd + x1n * xd^2
    let tv3 = multiply_nums(gxd,gxd); //  11. tv3 = gxd^2
    tv2 = multiply_nums(tv3,tv3); //  12. tv2 = tv3^2           # gxd^4
    tv3 = multiply_nums(tv3, gxd); //  13. tv3 = tv3 * gxd       # gxd^3
    tv3 = multiply_nums(tv3, gx1); //  14. tv3 = tv3 * gx1       # gx1 * gxd^3
    tv2 = multiply_nums(tv2, tv3); //  15. tv2 = tv2 * tv3       # gx1 * gxd^7
    let y11 = to_the_power_of(tv2, ELL2_C4); //  16. y11 = tv2^c4        # (gx1 * gxd^7)^((p - 5) / 8)
    y11 = multiply_nums(y11, tv3); //  17. y11 = y11 * tv3       # gx1*gxd^3*(gx1*gxd^7)^((p-5)/8)
    let y12 = multiply_nums(y11, ELL2_C3); //  18. y12 = y11 * c3
    tv2 = multiply_nums(y11,y11); //  19. tv2 = y11^2
    tv2 = multiply_nums(tv2, gxd); //  20. tv2 = tv2 * gxd
    let e1 = (tv2 === gx1); //  21.  e1 = tv2 == gx1
    let y1 = cmov(y12, y11, e1); //  22.  y1 = CMOV(y12, y11, e1)  # If g(x1) is square, this is its sqrt
    let x2n = multiply_nums(x1n, tv1); //  23. x2n = x1n * tv1       # x2 = x2n / xd = 2 * u^2 * x1n / xd
    let y21 = multiply_nums(y11, u); //  24. y21 = y11 * u
    y21 = multiply_nums(y21, ELL2_C2); //  25. y21 = y21 * c2
    let y22 = multiply_nums(y21, ELL2_C3); //  26. y22 = y21 * c3
    let gx2 = multiply_nums(gx1, tv1); //  27. gx2 = gx1 * tv1       # g(x2) = gx2 / gxd = 2 * u^2 * g(x1)
    tv2 = multiply_nums(y21,y21); //  28. tv2 = y21^2
    tv2 = multiply_nums(tv2, gxd); //  29. tv2 = tv2 * gxd
    let e2 = (tv2 === gx2); //  30.  e2 = tv2 == gx2
    let y2 = cmov(y22, y21, e2); //  31.  y2 = CMOV(y22, y21, e2)  # If g(x2) is square, this is its sqrt
    tv2 = multiply_nums(y1,y1); //  32. tv2 = y1^2
    tv2 = multiply_nums(tv2, gxd); //  33. tv2 = tv2 * gxd
    let e3 = (tv2 === gx1); //  34.  e3 = tv2 == gx1
    let xn = cmov(x2n, x1n, e3); //  35.  xn = CMOV(x2n, x1n, e3)  # If e3, x = x1, else x = x2
    let y = cmov(y2, y1, e3); //  36.   y = CMOV(y2, y1, e3)    # If e3, y = y1, else y = y2
    let e4 = ((y&_1n)===_1n); //  37.  e4 = sgn0(y) == 1        # Fix sign of y
    y = cmov(y, -y, e3 !== e4); //  38.   y = CMOV(y, -y, e3 XOR e4)
    return { xMn: xn, xMd: xd, yMn: y, yMd: _1n }; //  39. return (xn, xd, y, 1)
}
function map_to_curve_elligator2_edwards25519_(u) {
    const { xMn, xMd, yMn, yMd } = map_to_curve_elligator2_curve25519_(u); //  1.  (xMn, xMd, yMn, yMd) =
    // map_to_curve_elligator2_curve25519(u)
    let xn = multiply_nums(xMn, yMd); //  2.  xn = xMn * yMd
    xn = multiply_nums(xn, ELL2_C1_EDWARDS); //  3.  xn = xn * c1
    let xd = multiply_nums(xMd, yMn); //  4.  xd = xMd * yMn    # xn / xd = c1 * xM / yM
    let yn = mod(xMn - xMd,curveP); //  5.  yn = xMn - xMd
    let yd = add_nums(xMn, xMd); //  6.  yd = xMn + xMd    # (n / d - 1) / (n / d + 1) = (n - d) / (n + d)
    let tv1 = multiply_nums(xd, yd); //  7. tv1 = xd * yd
    let e = (tv1 === _0n); //  8.   e = tv1 == 0
    xn = cmov(xn, _0n, e); //  9.  xn = CMOV(xn, 0, e)
    xd = cmov(xd, _1n, e); //  10. xd = CMOV(xd, 1, e)
    yn = cmov(yn, _1n, e); //  11. yn = CMOV(yn, 1, e)
    yd = cmov(yd, _1n, e); //  12. yd = CMOV(yd, 1, e)
    const inv = Fp_FpInvertBatch([xd, yd]); // batch division
    return { x: multiply_nums(xn, inv[0]), y: multiply_nums(yn, inv[1]) }; //  13. return (xn, xd, yn, yd)
}

function i2osp(value, length) {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8;
    }
    return new Uint8Array(res);
}//takes a value and a length, an array is created with that length. Then takes the smallest 8 bits from the value and places it at the end of the array. 
//Repeats this with the next 8 bits and places them in the next last value in the array for the rest of the value  
function strxor(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
    }
    return arr;
}; //does bitwise xor on all values in 2 arrays and returns a new array with the results

/**
 * 
 * @param {Uint8Array} msg 
 * @param {Uint8Array} DST 
 * @param {number} len_in_bytes 
 * @returns 
 */
async function expand_message_xmd(msg, DST, len_in_bytes){
    const b_in_bytes = 64;
    const r_in_bytes = 128;
    const ell = Math.ceil(len_in_bytes/b_in_bytes);
    if (ell > 255) throw new Error('Invalid xmd length');
    const DST_prime = ConcatUint8Arrays([DST, i2osp(DST.length, 1)]);
    const Z_pad = i2osp(0,r_in_bytes);
    const len_in_bytes_str = i2osp(len_in_bytes,2);
    const b = new Array(ell);
    const arr = ConcatUint8Arrays([Z_pad, msg, len_in_bytes_str, i2osp(0, 1), DST_prime])
    const b_0 = await SHA512_Digest(arr);
    const promise_b = SHA512_Digest((ConcatUint8Arrays([b_0, i2osp(1, 1), DST_prime])));
    b[0] = await promise_b
    for (let i = 1; i <= ell; i++){
        const args = [strxor(b_0, b[i-1]),i2osp(i+1, 1), DST_prime];
        b[i] = await SHA512_Digest(ConcatUint8Arrays(args));
    }
    const pseudo_random_bytes = ConcatUint8Arrays(b);
    return pseudo_random_bytes.slice(0, len_in_bytes);
}; //a message and a DST that are encoded into Uint8arrays are hashed into a certain number of values according to len_in_bytes
async function hashtofield(msg){
    const _DST = 'QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_', m = 1, count = 2, k = 128, p = BigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949');
    const DST = new TextEncoder().encode(_DST);
    const log2p = p.toString(2).length;
    const L = Math.ceil((log2p+k)/8);
    const len_in_bytes = count * m * L;
    let prb = await expand_message_xmd(msg, DST, len_in_bytes);
    const u = new Array(count)
    for (let i = 0; i < count; i++) {
        const e = new Array(m);
        for (let j = 0; j < m; j++) {
            const elm_offset = L * (j + i * m);
            const tv = prb.subarray(elm_offset, elm_offset + L);
            e[j] = mod(BigIntFromByteArray(tv.reverse()), p);
        }
        u[i] = e;
    }
    return u;
}; //takes in a message hashes it with expand_message_xmd and splits the resulting value into 2 parts
/**
 * Hashes a msg to a point on the ed25519 curve.
 * @param {string|Uint8Array} msg 
 * @returns {Promise<Point>}
 */
export default async function HashToPoint(msg){
    const arr = typeof (msg) === 'string' ? new TextEncoder().encode(msg) : msg;
    const u = await hashtofield(arr)
    const x0y0 = map_to_curve_elligator2_edwards25519_(u[0][0]);
    const x1y1 = map_to_curve_elligator2_edwards25519_(u[1][0]);
    const p0 = Point.fromAffine(x0y0);
    const p1 = Point.fromAffine(x1y1);
    const P = p0.add(p1).clearCofactor();
    return P;
}; //hashtofield takes an Uint8array encoded message and gives back 2 values. the map_to_curve function then uses those values to generate 2 x and y values
// 2 Points are created using the x and y values. The points are added to each other and then are muliplied by 8 to give the final point.