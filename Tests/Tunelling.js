import EnclaveToMobileTunnelClient from "../Clients/EnclaveToMobileTunnelClient.js";
import WebSocketClientBase from "../Clients/WebSocketClientBase.js";
import Ed25519Scheme from "../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";
import TideKey from "../Cryptide/TideKey.js";


const voucherURL = "http://voucher";
const devicePublicKey = TideKey.FromSerializedComponent("200000e86646e1ce8f1b060d41a0213478f6855d3abc526335f53a85e18ab28b567767");
const appReq = JSON.stringify({appReq: "appReqqq"});
const appReqSig = "appReqSig";
const sessionKey = TideKey.FromSerializedComponent("200000e86646e1ce8f1b060d41a0213478f6855d3abc526335f53a85e18ab28b567767");
const sessionKeySig = "sessKeySig";
const vendorPublicKey = TideKey.FromSerializedComponent("200000e86646e1ce8f1b060d41a0213478f6855d3abc526335f53a85e18ab28b567767");

export async function EnclaveToMobileTunnelling_Enclave(){
    const homeOrkUrl = "ws://localhost:1001";


    // CHANGE FROM HTTP TO WSS






    
    
    // Enclave
    const enclaveClient = new EnclaveToMobileTunnelClient(homeOrkUrl);
    const inviteLink = await enclaveClient.initializeConnection();

    window.alert(inviteLink);

    const mobileDone = await enclaveClient.passEnclaveInfo(voucherURL, devicePublicKey, appReq, appReqSig, sessionKey, sessionKeySig, vendorPublicKey);

    if(mobileDone !== "done done done") throw Error("Mobile done message does not match");

    console.log("[ENCLAVE] TESTS PASSED :D");
}

export async function EnclaveToMobileTunnelling_Mobile(){
    const inviteLink = window.prompt("Whats the invite link?");

    // Mobile
    const mobileClient = new WebSocketClientBase(inviteLink);
    const pre_enclaveInfo = mobileClient.waitForMessage("requested info");

    await mobileClient.sendMessage({
            type: "request info",
            message: ":)"
        });


    const enclaveInfo = await pre_enclaveInfo;
    console.log("[MOBILE] Enclave info: " + pre_enclaveInfo);

    // ASSERT - All enclaveInfo keys match what was sent my enclave client
    if(enclaveInfo.voucherURL !== voucherURL) throw new Error("Voucher URL does not match");
    if(enclaveInfo.devicePublicKey !== devicePublicKey.get_public_component().Serialize().ToString()) throw new Error("Device public key does not match");
    if(enclaveInfo.appReq !== appReq) throw new Error("App request does not match");
    if(enclaveInfo.appReqSignature !== appReqSig) throw new Error("App request signature does not match");
    if(enclaveInfo.sessionKey !== sessionKey.get_public_component().Serialize().ToString()) throw new Error("Session key does not match");
    if(enclaveInfo.sessionKeySignature !== sessionKeySig) throw new Error("Session key signature does not match");
    if(enclaveInfo.vendorPublicKey !== vendorPublicKey.get_public_component().Serialize().ToString()) throw new Error("Vendor public key does not match");


    await mobileClient.sendMessage({
            type: "mobile completed",
            message: "done done done"
        });
    
    console.log("[MOBILE] TESTS PASSED :D");
}