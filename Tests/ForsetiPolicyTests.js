// tests/ForsetiPolicyTests.js
import NodeClient from "../Clients/NodeClient.js";

export async function Forseti_UploadBindValidate() {
    const baseUrl = window.prompt("Forseti API base URL", "http://localhost:1001");
    const vvkid = window.prompt("Tenant / VVKiD (also vendorId)", "");
    const uploadedBy = window.prompt("Uploaded by (email or user id)", "dev@local");
    const ruleId = window.prompt("Binding Rule ID", "rule-allow");
    const entryType = window.prompt("EntryType (FQN)", "MyPolicy");
    const resource = window.prompt("Resource path to validate", "/demo");
    const action = window.prompt("Action to validate", "read");

    const defaultSource =
        `using Ork.Forseti.Sdk;
public sealed class MyPolicy : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx)
  {
    if (!string.IsNullOrWhiteSpace(ctx.Subject) &&
        ctx.Claims.TryGetValue("stage", out var s) && s == "validate")
      return PolicyDecision.Allow();
    return PolicyDecision.Deny("missing subject or wrong stage");
  }
}`;

    const source = window.prompt("C# Policy Source", defaultSource);
    if (!baseUrl || !vvkid || !entryType || !source) { console.log("[Forseti] Missing inputs."); return; }

    const client = new NodeClient(baseUrl);
    // ← get the exact server stamp
    const sdkVersion = await client.GetForsetiSdkVersion();

    const { bh, entryType: resolvedEntry } = await client.UploadPolicySource(
        vvkid, uploadedBy, entryType, sdkVersion, source
    );
    console.log("[Forseti] Uploaded policy:", { bh, entryType: resolvedEntry });

    await client.UpsertPolicyBinding(
        vvkid, ruleId, "DenyOverrides", "Enforce", bh, resolvedEntry, 0
    );
    console.log("[Forseti] Binding upserted:", { vvkid, ruleId, bh, resolvedEntry });

    const reqId = "forseti-test-" + Date.now();
    const claims = { sub: "alice", stage: "validate", "request.id": reqId };

    const result = await client.ValidateAccess(vvkid, resource, action, claims);
    console.log("[Forseti] Validate result:", result);

    if (result.allowed) {
        alert(`✅ Allowed\n\nbh =${bh}\nentry =${resolvedEntry}\nreq =${reqId}`);
    } else {
        alert(`❌ Denied\n\nerror =${result.error || "(no error)"}\nbh =${bh}\nentry =${resolvedEntry}\nreq =${reqId}`);
    }
}

export async function Forseti_UploadBindExpectDeny() {
    const baseUrl = window.prompt("Forseti API base URL", "http://localhost:1001");
    const vvkid = window.prompt("Tenant / VVKiD (also vendorId)", "");
    const uploadedBy = window.prompt("Uploaded by", "dev@local");
    const ruleId = window.prompt("Binding Rule ID", "rule-deny");
    const entryType = window.prompt("EntryType (FQN)", "AlwaysDeny");
    const resource = window.prompt("Resource path to validate", "/demo");
    const action = window.prompt("Action to validate", "read");

    const defaultDenySource =
        `using Ork.Forseti.Sdk;
public sealed class AlwaysDeny : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx) => PolicyDecision.Deny("nope");
}`;

    const source = window.prompt("C# Policy Source (deny)", defaultDenySource);
    if (!baseUrl || !vvkid || !entryType || !source) { console.log("[Forseti] Missing inputs."); return; }

    const client = new NodeClient(baseUrl);
    const sdkVersion = await client.GetForsetiSdkVersion();

    const { bh, entryType: resolvedEntry } = await client.UploadPolicySource(
        vvkid, uploadedBy, entryType, sdkVersion, source
    );
    console.log("[Forseti] Uploaded deny policy:", { bh, entryType: resolvedEntry });

    await client.UpsertPolicyBinding(
        vvkid, ruleId, "DenyOverrides", "Enforce", bh, resolvedEntry, 0
    );
    console.log("[Forseti] Binding upserted (deny):", { vvkid, ruleId, bh, resolvedEntry });

    const reqId = "forseti-test-deny-" + Date.now();
    const claims = { sub: "bob", stage: "validate", "request.id": reqId };

    const result = await client.ValidateAccess(vvkid, resource, action, claims);
    console.log("[Forseti] Validate (expect deny):", result);

    if (!result.allowed) {
        alert(`✅ Correctly denied\n\nerror =${result.error || "(no error)"}\nreq =${reqId}`);
    } else {
        alert("❌ Unexpectedly allowed");
    }
}

/**
 * Interactive revoke test:
 *  1) Prompt for base URL, vvkid, bh to revoke
 *  2) Revoke
 *  3) Validate again to observe behavior if desired (manual)
 */
export async function Forseti_RevokeBh() {
    const baseUrl = window.prompt("Forseti API base URL", "http://localhost:1001");
    const vvkid = window.prompt("Tenant / VVKiD", "");
    const bh = window.prompt("Code hash (bh) to revoke", "");
    const reason = window.prompt("Reason (optional)", "manual-test");

    if (!baseUrl || !vvkid || !bh) {
        console.log("[Forseti] Missing inputs. Cancelled.");
        return;
    }

    try {
        const client = new NodeClient(baseUrl);
        const res = await client.RevokePolicyBh(vvkid, bh, reason || null);
        console.log("[Forseti] Revocation result:", res);

        if (res?.revoked) {
            alert(`✅ Revoked bh =${bh}
		for ${vvkid}`);
        }
        else {
            alert("❌ Revocation failed");
        }
    }
    catch (err) {
        console.error("[Forseti] Revocation failed:", err);
        alert("Forseti Revoke failed: " + (err?.message || err));
    }
}