import { Point } from "./index.js";
import { GetPublic, RandomBigInt } from "./Math.js";
import { BigIntFromByteArray, BigIntToByteArray, Bytes2Hex, bytesToBase64 } from "./Serialization.js";

export default class TideKey{

    static NewKey(){
        return new TideKey(RandomBigInt());
    }

    constructor(data){
        // check if data is byte array, bigint or point
        if (data instanceof Uint8Array) {
            this.priv = BigIntFromByteArray(data);
            this.pub = GetPublic(this.priv);
        } else if (typeof data === 'bigint') {
            this.priv = data;
            this.pub = GetPublic(this.priv);
        } else if (data instanceof Point) {
            this.priv = null;
            this.pub = data;
        } else {
            throw Error("Data type not supported to construct Tide Key")
        }
    }

    serializePrivateKey(prefix){
        if(!this.priv) throw Error("Tide Key requires private component to serialize");
        return "tide" + prefix + "key" + bytesToBase64(BigIntToByteArray(this.priv));
    }

    serializeNetworkKey(){
        return Bytes2Hex(this.pub.toArray());
    }

    GetPublicKey(){
        return this.pub;
    }

    GetPrivateKey(){
        if(!this.priv) throw Error("No private component to this key");
        return this.priv;
    }

    async sign(message){

    }
    secretShare(t, n, ids){

    }
    async dec(message){

    }
    genVouchers(actionRequest, action, blurGOrk, payerPublic){

    }
    testVoucher(voucherFinal, qPub){

    }
    finalizeVoucher(voucherPack, vtagPub, blurer, action){
        
    }
    static newKey(){

    }
}