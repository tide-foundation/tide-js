import { SimulatorFlow, Utils } from "../index.js";
import { CreateGPrismAuth, GenSessKey, GetPublic, RandomBigInt } from "../Cryptide/Math.js";
import { base64ToBase64Url, base64ToBytes, BigIntToByteArray, Bytes2Hex, bytesToBase64, GetUID, Hex2Bytes, StringToUint8Array } from "../Cryptide/Serialization.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js";
import { HMAC_forHashing } from "../Cryptide/Hashing/Hash.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow-OLD.js";
import dCMKPasswordFlow from "../Flow/AuthenticationFlows/dCMKPasswordFlow.js";
import EnclaveEntry from "../Models/EnclaveEntry.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import NetworkClient from "../Clients/NetworkClient.js";
import AuthRequest from "../Models/AuthRequest.js";
import { CurrentTime, Max } from "../Tools/Utils.js";
import { EdDSA, Point, Serialization } from "../Cryptide/index.js";
import dTestVVKSigningFlow from "../Flow/SigningFlows/dTestVVkSigningFlow.js";
import BaseTideRequest from "../Models/BaseTideRequest.js";
import dVVKSigningFlow from "../Flow/SigningFlows/dVVKSigningFlow.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { CreateAuthorizerPackage, CreateVRKPackage } from "../Cryptide/TideMemoryObjects.js";
import { AuthorizedEncryptionFlow } from "../Flow/EncryptionFlows/AuthorizedEncryptionFlow";

export async function encrypt_auth_by_jwt(){
    const simClient = new NetworkClient();
    const availableOrks = (await simClient.FindReservers("blah"));
    const orks = (await SimulatorFlow.FilterInactiveOrks(availableOrks)).slice(0, Max);
    const tag = "dob";
   
    const sessKey = GenSessKey();
    const gSessKey = GetPublic(sessKey);

    const VRK = BigInt(123456789);
    const gVRK = GetPublic(VRK);
    const VVKid = "VendorID12345";
    const auth = new AuthRequest(VVKid, "NEW", gSessKey.toBase64(), BigInt(CurrentTime() + 30))
    const authSig = await EdDSA.sign(auth.toString(), VRK);

    // Midgard can replace this line
    const vrkPackage = CreateVRKPackage(new Ed25519PublicComponent(gVRK), Utils.CurrentTime() + 300);
    const authorizerPackage = CreateAuthorizerPackage("VRK:1", ["AccessToken:1", "UserContext:1"], vrkPackage); // NEVER EVER EVER ADD UserContext:1 TO MAIN VRK LIST OF APPROVED MODELS - THIS IS JUST FOR TESTING - IT BASICALLY BYPASSES THE ADMINS
    console.log("AUTHORIZER: " + Bytes2Hex(authorizerPackage));

    const genFlow = new dKeyGenerationFlow(VVKid, gVRK.toBase64(), orks, sessKey, gSessKey, "NEW", "http://localhost:3000/voucher/new");
    const {gK} = await genFlow.GenVVKShard(auth, authSig);
    const signAuth = await genFlow.SetShard(Bytes2Hex(authorizerPackage), "VVK");
    await genFlow.Commit();

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
    const userContextSignFlow = new dVVKSigningFlow(VVKid, gK, orks, sessKey, gSessKey, "http://localhost:3000/voucher/new");
    const userContextSig = (await userContextSignFlow.start(userContextRequest))[0];

    // Generate signed jwt
    let requestsedJwt = "eyJhbGciOiJFZERTQSIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJVbnNrdGp5dlNabnhlbTBpaEYwNTQ2NjlEdHdFMjV0dkJ2Y1lSZVBVNUo0In0." + base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify({
        "resource_access":{
            "dob":{
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
    const jwtRequest = new BaseTideRequest("AccessToken", "1", "VRK:1", jwtRequestDraft, Serialization.CreateTideMemory(new Uint8Array(), 0)); // set dynamic data to 0 indicating no previous token auth
    const jwtSigningFlow = new dVVKSigningFlow(VVKid, gK, orks, sessKey, gSessKey, "http://localhost:3000/voucher/new");
    requestsedJwt = requestsedJwt + "." + base64ToBase64Url(bytesToBase64((await jwtSigningFlow.start(jwtRequest))[0]));

    // Test encryption
    const encryptionFlow = new AuthorizedEncryptionFlow({
        dataToEncrypt: [
            {
                "data": "10/4/2009",
                "tags": ["dob"]
            }
        ],
        vendorId: VVKid,
        token: requestsedJwt,
        voucherURL: "http://localhost:3000/voucher/new"
    });
    const encrypted = await encryptionFlow.encrypt();
    console.log(encrypted);
    console.log("Encrypt TEST SUCCESSFUL");
}