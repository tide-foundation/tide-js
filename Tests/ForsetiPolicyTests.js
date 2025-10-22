// --- add at the bottom of tests/ForsetiPolicyTests.js ---
import NodeClient from "../Clients/NodeClient.js";

// Small helper
const h = (html) => {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstChild;
};

export function mountForsetiTester() {
    // Avoid duplicates
    const EXISTING = document.getElementById("forseti-dev-panel");
    if (EXISTING) { EXISTING.remove(); }

    const panel = h(`
<div id="forseti-dev-panel" style="
  position:fixed; inset:auto 12px 12px auto; z-index:2147483647;
  width: 560px; background:#0b1020; color:#e7ecff; border:1px solid #1e2a5a;
  border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.35); font: 13px/1.35 ui-sans-serif,system-ui;
">
  <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; border-bottom:1px solid #1e2a5a;">
    <strong style="font-size:14px">Forseti Dev Panel</strong>
    <button id="fdp-close" style="background:#152054; color:#c9d4ff; border:0; padding:4px 8px; border-radius:8px; cursor:pointer;">✕</button>
  </div>

  <div style="padding:12px; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
    <label>Base URL
      <input id="fdp-base" type="text" value="http://localhost:1001" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>VVKiD / VendorId
      <input id="fdp-vvkid" type="text" placeholder="tenant-123" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>Uploaded By
      <input id="fdp-uploaded" type="text" value="dev@local" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>Mode
      <select id="fdp-mode" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
        <option value="Enforce" selected>Enforce</option>
        <option value="Shadow">Shadow</option>
      </select>
    </label>

    <label>Entry Type (FQN)
      <input id="fdp-entry" type="text" value="MyPolicy" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>(info) Binding is unique per (codeBh, mode)</label>

    <label>Resource
      <input id="fdp-resource" type="text" value="/demo" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>Action
      <input id="fdp-action" type="text" value="read" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <div style="grid-column:1/-1">
      <label>C# Policy Source (implements Ork.Forseti.Sdk.IAccessPolicy)</label>
      <textarea id="fdp-src" spellcheck="false" style="width:100%; height:170px; margin-top:4px; padding:8px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px;">
using Ork.Forseti.Sdk;
public sealed class MyPolicy : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx)
  {
    if (!string.IsNullOrWhiteSpace(ctx.Subject) &&
        ctx.Claims.TryGetValue("stage", out var s) && s == "validate")
      return PolicyDecision.Allow();
    return PolicyDecision.Deny("missing subject or wrong stage");
  }
}
      </textarea>
    </div>

    <div style="grid-column:1/-1; display:flex; gap:8px; flex-wrap:wrap; margin-top:4px;">
      <button id="fdp-allow" style="padding:8px 10px; border-radius:8px; border:0; background:#1c7b46; color:white; cursor:pointer;">Upload + Bind + Validate (expect ALLOW)</button>
      <button id="fdp-deny"  style="padding:8px 10px; border-radius:8px; border:0; background:#8b2635; color:white; cursor:pointer;">Upload + Bind + Validate (expect DENY)</button>
      <button id="fdp-unbind" style="padding:8px 10px; border-radius:8px; border:0; background:#4a4e7a; color:white; cursor:pointer;">(info) Unbind — not supported</button>
    </div>

    <div style="grid-column:1/-1; margin-top:6px;">
      <label>Custom Claims JSON (for /Forseti/Gate/validate)</label>
      <textarea id="fdp-claims" spellcheck="false" placeholder='{"sub":"alice","stage":"validate"}'
        style="width:100%; height:120px; margin-top:4px; padding:8px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px;"></textarea>
      <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
        <button id="fdp-claims-run"   style="padding:6px 10px; border-radius:8px; border:0; background:#2a3a7a; color:white; cursor:pointer;">Validate (show raw response)</button>
        <button id="fdp-claims-allow" style="padding:6px 10px; border-radius:8px; border:0; background:#1c7b46; color:white; cursor:pointer;">Validate (expect ALLOW)</button>
        <button id="fdp-claims-deny"  style="padding:6px 10px; border-radius:8px; border:0; background:#8b2635; color:white; cursor:pointer;">Validate (expect DENY)</button>
      </div>
    </div>

    <div id="fdp-log" style="grid-column:1/-1; margin-top:8px; padding:8px; background:#0f1736; border:1px dashed #2a3a7a; border-radius:8px; white-space:pre-wrap; min-height:84px;"></div>
  </div>
</div>
  `);

    document.body.appendChild(panel);
    const $ = (sel) => panel.querySelector(sel);
    $("#fdp-close").onclick = () => panel.remove();

    let lastBh = null, lastEntry = null;

    const log = (m) => { $("#fdp-log").textContent += (m + "\n"); };
    const resetLog = () => { $("#fdp-log").textContent = ""; };

    function parseClaimsOr(defaultObj) {
        const raw = $("#fdp-claims").value.trim();
        if (!raw) return defaultObj;
        try {
            const obj = JSON.parse(raw);
            if (obj && typeof obj === "object") return obj;
            throw new Error("Claims must be an object");
        } catch (e) {
            log("❌ Invalid claims JSON: " + (e?.message || String(e)));
            return null;
        }
    }

    async function uploadBindValidate(expectAllow) {
        resetLog();

        const baseUrl = $("#fdp-base").value.trim();
        const vvkid = $("#fdp-vvkid").value.trim();
        const uploaded = $("#fdp-uploaded").value.trim();
        const entryType = $("#fdp-entry").value.trim();
        const resource = $("#fdp-resource").value.trim();
        const action = $("#fdp-action").value.trim();
        const source = $("#fdp-src").value;
        const mode = $("#fdp-mode").value; // Enforce | Shadow

        if (!baseUrl || !vvkid || !entryType || !source) {
            log("❌ Missing required inputs (baseUrl, vvkid, entryType, source).");
            return;
        }

        try {
            const client = new NodeClient(baseUrl);
            const sdkVersion = await client.GetForsetiSdkVersion();
            log(`ℹ️ SDK Version: ${sdkVersion}`);

            const { bh, entryType: resolvedEntry } =
                await client.UploadPolicySource(vvkid, uploaded, entryType, sdkVersion, source);
            lastBh = bh; lastEntry = resolvedEntry;
            log(`✅ Uploaded: bh=${bh} entry=${resolvedEntry}`);

            await client.ActivatePolicyBinding(bh, resolvedEntry, mode);
            log(`✅ Activated binding (mode=${mode}) for bh=${bh}`);

            // default claims if the box is empty
            let claims = parseClaimsOr({ sub: "alice", stage: "validate" });
            if (!claims) return;

            const res = await client.ValidateAccess(vvkid, resource, action, claims);
            log(`🧪 Validate → allowed=${res.allowed} error=${res.error ?? "null"}`);

            if (expectAllow === true && !res.allowed) {
                log("❌ Expected ALLOW but got DENY.");
            } else if (expectAllow === false && res.allowed) {
                log("❌ Expected DENY but got ALLOW.");
            } else if (expectAllow != null) {
                log("✅ Behavior matched expectation.");
            }
        } catch (err) {
            console.error(err);
            log("❌ Error: " + (err?.message ?? String(err)));
        }
    }

    async function validateWithCustomClaims(expect) {
        resetLog();

        const baseUrl = $("#fdp-base").value.trim();
        const vvkid = $("#fdp-vvkid").value.trim();
        const resource = $("#fdp-resource").value.trim();
        const action = $("#fdp-action").value.trim();
        if (!baseUrl || !vvkid) {
            log("❌ Need baseUrl and vvkid.");
            return;
        }

        let claims = parseClaimsOr(null);
        if (!claims) return;

        try {
            const client = new NodeClient(baseUrl);
            const res = await client.ValidateAccess(vvkid, resource, action, claims);
            log("↪ Raw response: " + JSON.stringify(res));

            if (expect === true && !res.allowed) {
                log("❌ Expected ALLOW but got DENY.");
            } else if (expect === false && res.allowed) {
                log("❌ Expected DENY but got ALLOW.");
            } else if (expect != null) {
                log("✅ Behavior matched expectation.");
            }
        } catch (e) {
            log("❌ Validate error: " + (e?.message || String(e)));
        }
    }

    // Buttons
    $("#fdp-allow").onclick = () => uploadBindValidate(true);
    $("#fdp-deny").onclick = () => {
        // Quick swap to a deny policy if user hasn't provided one
        if (!$("#fdp-src").value.toLowerCase().includes("policydecision.deny")) {
            $("#fdp-entry").value = "AlwaysDeny";
            $("#fdp-src").value =
                `using Ork.Forseti.Sdk;
public sealed class AlwaysDeny : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx) => PolicyDecision.Deny("nope");
}`;
        }
        uploadBindValidate(false);
    };

    // Unbind info (no-op since revocations/binding deletion aren’t exposed here)
    $("#fdp-unbind").onclick = () => {
        log("ℹ️ Unbind/Revocation is not exposed via this dev panel. Remove/replace binding server-side if needed.");
    };

    // Custom-claims validators
    $("#fdp-claims-run").onclick = () => validateWithCustomClaims(null);
    $("#fdp-claims-allow").onclick = () => validateWithCustomClaims(true);
    $("#fdp-claims-deny").onclick = () => validateWithCustomClaims(false);
}
