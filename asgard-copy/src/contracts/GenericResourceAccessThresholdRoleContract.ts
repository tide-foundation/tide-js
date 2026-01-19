import { Policy } from "../models/Policy";
import { BaseContract, Doken } from "./BaseContract";

export class GenericResourceAccessThresholdRoleContract extends BaseContract{
    public id: string = "GenericResourceAccessThresholdRole:1";
    protected validateData(policy: Policy): Promise<void> {
        console.warn("Validate Data not implemented!");
        return;
    }
    protected async validateApprovers(policy: Policy, approverDokens: Doken[]): Promise<void> {
        let successfulDokens = 0;
        approverDokens.forEach(d => {
            if(d.hasResourceAccessRole(policy.params.getParameter<string>("role"), policy.params.getParameter<string>("resource"))) successfulDokens++;
        })
        const threshold = policy.params.getParameter<number>("threshold");
        if(successfulDokens < threshold) throw 'Not enough successful dokens with requires roles/clients';
    }
}