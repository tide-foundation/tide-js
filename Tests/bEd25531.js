import { Point as bPoint } from "../Cryptide/Components/Schemes/bEd25531/bEd25531.js";
import { Point } from "../Cryptide/Ed25519.js";

export function Matt_Test(){
    for(let o = 0; o < 10; o++){
    const g = bPoint.fromHex("0800000000000000000000000000000000000000000000000000000000000000");
    const p1 = bPoint.fromHex("ba534985ba1d4bd87283985994c1db89039b79f4ae2a87bd5b3e0c300bf1e274");
    const p2 = bPoint.fromHex("1da92bbed8ecd09c5d1dbd4a8f373631488c71222ce153bd8bbb82fcda29b9b1");
    const p3 = bPoint.fromHex("e42500f638e451a3ab5b4cf263acfdbb0b2c57fe6d45992d5fce2bb91fb89164");
    const p4 = bPoint.fromHex("80440d650471f716415374fccd0eaf15adda48a025d5eab83ccbe8e855321ec3");

    
    // Start Ed25519 performance
    let j2 = Point.BASE.double();
    const start2 = performance.now();
    for(let i2 = 0; i2 < 20000; i2++){
        j2 = j2.double();
        const p1 = Point.fromHex(j2.toHex());
    }
    const end2 = performance.now();
    console.log(`executed 19 in ${ (end2 - start2).toFixed(3) } ms`);
    console.log("------");

    // Start bEd25531 performance
    let j = g.double();
    const start = performance.now();
    for(let i = 0; i < 20000; i++){
        j = j.double();
        const u = bPoint.fromHex(j.toHex());
    }
    const end = performance.now();
    console.log(`executed 31 in ${ (end - start).toFixed(3) } ms`);
console.log("------");
    }
}