import { SimulatorFlow, Utils } from "../index.js";
import { CreateGPrismAuth, GenSessKey, GetPublic, RandomBigInt } from "../Cryptide/Math.js";
import { base64ToBase64Url, base64ToBytes, BigIntToByteArray, Bytes2Hex, bytesToBase64, GetUID, Hex2Bytes, StringToUint8Array } from "../Cryptide/Serialization.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";

import NetworkClient from "../Clients/NetworkClient.js";
import AuthRequest from "../Models/AuthRequest.js";
import { CurrentTime, Max } from "../Tools/Utils.js";
import { EdDSA, Point, Serialization } from "../Cryptide/index.js";
import BaseTideRequest from "../Models/BaseTideRequest.js";
import dVVKSigningFlow from "../Flow/SigningFlows/dVVKSigningFlow.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { CreateAuthorizerPackage, CreateVRKPackage } from "../Cryptide/TideMemoryObjects.js";
import { AuthorizedEncryptionFlow } from "../Flow/EncryptionFlows/AuthorizedEncryptionFlow.js";


export async function Encrypt_auth_by_jwt(){
    const simClient = new NetworkClient();
    const availableOrks = (await simClient.FindReservers("bl2ah"));
    const orks = (await SimulatorFlow.FilterInactiveOrks(availableOrks)).slice(0, Max);

    const v = window.localStorage.getItem("t");
    const vals = JSON.parse(v);

    const vvkId = vals.id;
    const gVVK = Point.fromB64(vals.pub);
    const vrk = BigInt(vals.vrk);
    const vrk_sig = base64ToBytes(vals.vrk_sig);
    const authorizer = Hex2Bytes(vals.authorizer);

    // Generate signed usercontext
    const userContext = StringToUint8Array(JSON.stringify({
        "resource_access":{
            "dob":{
                "roles":[
                    "encrypt"
                ]
            }
        }
    }));
    const userContextDraft = Serialization.CreateTideMemory(new Uint8Array([0]), 4 + 1 + 4 + userContext.length);
    Serialization.WriteValue(userContextDraft, 1, userContext);
    const userContextRequest = new BaseTideRequest("UserContext", "1", "VRK:1", userContextDraft);
    userContextRequest.addAuthorizer(authorizer);
    userContextRequest.addAuthorizerCertificate(vrk_sig);
    userContextRequest.addAuthorization(base64ToBytes(await EdDSA.sign(await userContextRequest.dataToAuthorize(), vrk)));

    const sessKey = GenSessKey();
    const gSessKey = GetPublic(sessKey);
    const userContextSignFlow = new dVVKSigningFlow(vvkId, gVVK, orks, sessKey, gSessKey, "http://localhost:3000/voucher/new");
    const userContextSig = (await userContextSignFlow.start(userContextRequest))[0];

    // Generate signed jwt
    let requestsedJwt = "eyJhbGciOiJFZERTQSIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJVbnNrdGp5dlNabnhlbTBpaEYwNTQ2NjlEdHdFMjV0dkJ2Y1lSZVBVNUo0In0." + base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify({
        "resource_access":{
            "dob":{
                "roles":[
                    "encrypt"
                ]
            },
            "name":{
                "roles":[
                    "encrypt"
                ]
            }
        },
        // below is so the orks don't reject the jwt
        "exp": CurrentTime() + 100,
        "sid": "testtttt",
        "iat": CurrentTime()
    }))));
    const requestsedJwt_b = StringToUint8Array(requestsedJwt);
    const jwtRequestDraft = Serialization.CreateTideMemory(userContext, 4 + userContext.length + 4 + userContextSig.length + 4 + requestsedJwt_b.length);
    Serialization.WriteValue(jwtRequestDraft, 1, userContextSig);
    Serialization.WriteValue(jwtRequestDraft, 2, requestsedJwt_b);
    const jwtRequest = new BaseTideRequest("AccessToken", "1", "VRK:1", jwtRequestDraft, Serialization.CreateTideMemory(new Uint8Array(), 4)); // set dynamic data to 0 indicating no previous token auth
    jwtRequest.addAuthorizer(authorizer);
    jwtRequest.addAuthorizerCertificate(vrk_sig);
    jwtRequest.addAuthorization(base64ToBytes(await EdDSA.sign(await jwtRequest.dataToAuthorize(), vrk)));
    const jwtSigningFlow = new dVVKSigningFlow(vvkId, gVVK, orks, sessKey, gSessKey, "http://localhost:3000/voucher/new");
    requestsedJwt = requestsedJwt + "." + base64ToBase64Url(bytesToBase64((await jwtSigningFlow.start(jwtRequest))[0]));

    // Test encryption
    console.time('Execution Time');
    const encryptionFlow = new AuthorizedEncryptionFlow({
        dataToEncrypt: [
            {
                "data": "0",
                "tags": ["dob"]
            },
            {
                "data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tags": ["dob",]
            },
            {
                "data": "0",
                "tags": ["dob", "name"]
            },
            {
                "data": "0",
                "tags": ["name"]
            }
        ],
        vendorId: vvkId,
        token: requestsedJwt,
        voucherURL: "http://localhost:3000/voucher/new"
    });
    const encrypted = await encryptionFlow.encrypt();
    console.timeEnd('Execution Time');
    console.log(encrypted);
    console.log("Encrypt TEST SUCCESSFUL");
}