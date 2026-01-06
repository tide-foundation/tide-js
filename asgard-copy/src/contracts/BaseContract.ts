import { ApprovalType, ExecutionType, Policy } from "../models/Policy";
import BaseTideRequest from "../models/TideRequest";
import { StringFromUint8Array } from "../utils/Serialization";
import { TideMemory } from "../utils/TideMemory";

interface PolicyRunResult{
    failed?: unknown;
    success: boolean
}

export abstract class BaseContract{
    public abstract id: string;
    private tideRequest: BaseTideRequest;
    private dokens: Doken[] = []; // change to Doken type
    protected authorizedRequestPayload: TideMemory;
    protected informationalRequestPayload: TideMemory;

    /**
     * Inheritors must implement this
     * @param policy Policy object
     */
    protected abstract validateData(policy: Policy): Promise<void>;

    /**
     * Inheritors must implement this if the policy has set it's approvalType to EXPLICIT
     * @param policy Policy object
     * @param approverDokens Approver Dokens
     */
    protected validateApprovers(policy: Policy, approverDokens: Doken[]): Promise<void>{
        throw `validateApprovers not implemented`;
    }

    /**
     * Inheritors must implement this if the policy has set it's executionType to PRIVATE
     * @param policy Policy object
     * @param executorDoken Executor Doken
     */
    protected validateExecutor(policy: Policy, executorDoken: Doken): Promise<void>{
        throw `validateExecutor not implemented`;
    }

    /**
     * To help with clients testing if their Tide Request will pass their contract's specified contract
     * @param policy Serialized policy from Tide
     * @returns 
     */
    async testPolicy(policy: Uint8Array | Policy, executorDoken : string | undefined = null): Promise<PolicyRunResult> {
        const p = policy instanceof Uint8Array ? Policy.from(policy) : policy;
        if(p.contractId !== this.id) throw `Mismatch between policy provided's contract (${p.contractId}) and this contract's id (${this.id})`;
        if(p.modelId !== this.tideRequest.id() && p.modelId !== "any") throw `Mismatch between policy provided model id (${p.modelId}) and tide request id (${this.tideRequest.id()})`
        try{
            await this.validateData(p);
            if(p.approvalType == ApprovalType.EXPLICIT) await this.validateApprovers(p, this.dokens);
            if(p.executionType == ExecutionType.PRIVATE){
                if(!executorDoken) throw `Policy as set it's execution type to PRIVATE. You must test this with the doken of the executor`;
                await this.validateExecutor(p, new Doken(executorDoken));
            }
            return {
                success: true
            };
        }catch(ex){
            return {
                success: false,
                failed: ex
            };
        }
    }

    constructor(tideRequest: Uint8Array | BaseTideRequest){
        this.tideRequest = tideRequest instanceof Uint8Array ? BaseTideRequest.decode(tideRequest) : tideRequest;
        this.authorizedRequestPayload = this.tideRequest.draft;
        this.informationalRequestPayload = this.tideRequest.dyanmicData;
        
        // deserialize dokens
        let res = {result: new Uint8Array()};
        let i = 0;
        while(this.tideRequest.authorizer.TryGetValue(i, res)){
            this.dokens.push(new Doken(res.result));
            i++;
        }
    }
}




export class Doken{
    private payload: any;
    constructor(d: Uint8Array | string){
        if(!d || d.length === 0){
            throw new Error('Doken constructor: received empty or null Uint8Array');
        }

        const tokenString = typeof d === "string" ? d : StringFromUint8Array(d);
        const s = tokenString.split(".");

        if(s.length !== 3){
            throw new Error(`Doken constructor: invalid token format. Expected 3 parts (header.payload.signature) but got ${s.length} parts in: "${tokenString.substring(0, 50)}..."`);
        }

        try{
            const decodedPayload = base64UrlDecode(s[1]);
            this.payload = JSON.parse(decodedPayload);
        } catch(error){
            throw new Error(`Doken constructor: failed to parse token payload. ${error instanceof Error ? error.message : String(error)}. Raw payload part: "${s[1].substring(0, 50)}..."`);
        }

        if(!this.payload || typeof this.payload !== 'object'){
            throw new Error(`Doken constructor: parsed payload is not a valid object. Got type: ${typeof this.payload}`);
        }
    }
    hasResourceAccessRole(role: string, client: string): boolean{
        if(!role) throw new Error('hasResourceAccessRole: role parameter is empty or undefined');
        if(!client) throw new Error('hasResourceAccessRole: client parameter is empty or undefined');

        if(!this.payload.resource_access){
            return false;
        }

        if(!this.payload.resource_access[client]){
            return false;
        }

        if(!Array.isArray(this.payload.resource_access[client].roles)){
            return false;
        }

        return this.payload.resource_access[client].roles.includes(role);
    }
    hasRealmAccessRole(role: string): boolean{
        if(!role) throw new Error('hasRealmAccessRole: role parameter is empty or undefined');

        if(!this.payload.realm_access){
            return false;
        }

        if(!Array.isArray(this.payload.realm_access.roles)){
            return false;
        }

        return this.payload.realm_access.roles.includes(role);
    }
    hasVuid(vuid: string): boolean{
        if(!vuid) throw new Error('hasVuid: vuid cannot be null');
        if(!this.payload.vuid) throw new Error("hasVuid: cannot find vuid in paylod");
        return this.payload.vuid === vuid;
    }
}


function base64UrlDecode(input: string) {
    let output = input
        .replaceAll("-", "+")
        .replaceAll("_", "/");

    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += "==";
            break;
        case 3:
            output += "=";
            break;
        default:
            throw new Error("Input is not of the correct length.");
    }

    try {
        return b64DecodeUnicode(output);
    } catch (error) {
        return atob(output);
    }
}
function b64DecodeUnicode(input: string) {
    return decodeURIComponent(atob(input).replace(/(.)/g, (m, p) => {
        let code = p.charCodeAt(0).toString(16).toUpperCase();

        if (code.length < 2) {
            code = "0" + code;
        }

        return "%" + code;
    }));
}