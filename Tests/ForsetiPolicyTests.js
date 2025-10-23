// tests/ForsetiPolicyTests.js
import NodeClient from "../Clients/NodeClient.js";

const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };

export function mountForsetiTester() {
  const EXISTING = document.getElementById("forseti-dev-panel");
  if (EXISTING) EXISTING.remove();

  const panel = h(`
<div id="forseti-dev-panel" style="
  position:fixed; inset:auto 12px 12px auto; z-index:2147483647;
  width: 620px; background:#0b1020; color:#e7ecff; border:1px solid #1e2a5a;
  border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.35); font: 13px/1.35 ui-sans-serif,system-ui;">
  <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; border-bottom:1px solid #1e2a5a;">
    <strong style="font-size:14px">Forseti Dev Panel</strong>
    <button id="fdp-close" style="background:#152054; color:#c9d4ff; border:0; padding:4px 8px; border-radius:8px; cursor:pointer;">✕</button>
  </div>

  <div style="padding:12px; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
    <label>Base URL
      <input id="fdp-base" type="text" value="http://localhost:1001" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>VVKiD
      <input id="fdp-vvkid" type="text" placeholder="tenant-123" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>Uploaded By
      <input id="fdp-uploaded" type="text" value="dev@local" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>Entry Type (FQN)
      <input id="fdp-entry" type="text" value="MyPolicy" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>Resource
      <input id="fdp-resource" type="text" value="/demo" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>Action
      <input id="fdp-action" type="text" value="read" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <div style="grid-column:1/-1">
      <label>C# Policy Source (implements Ork.Forseti.Sdk.IAccessPolicy)</label>
      <textarea id="fdp-src" spellcheck="false" style="width:100%; height:180px; margin-top:4px; padding:8px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px;">
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

    <div style="grid-column:1/-1; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
      <label>BH / ContractId (used in validate; defaults to last uploaded bh)
        <input id="fdp-contract" type="text" placeholder="sha256:..." style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
      </label>
      <label>ModelId (BH) (required)
        <input id="fdp-model" type="text" placeholder="sha256:..." style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
      </label>
    </div>

    <div style="grid-column:1/-1; display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
      <button id="fdp-upload-allow" style="padding:8px 10px; border-radius:8px; border:0; background:#1c7b46; color:white; cursor:pointer;">Upload → Validate (expect ALLOW)</button>
      <button id="fdp-upload-deny"  style="padding:8px 10px; border-radius:8px; border:0; background:#8b2635; color:white; cursor:pointer;">Upload → Validate (expect DENY)</button>
      <button id="fdp-validate-only" style="padding:8px 10px; border-radius:8px; border:0; background:#2a3a7a; color:white; cursor:pointer;">Validate ONLY (use entered BH)</button>
    </div>

    <div style="grid-column:1/-1; margin-top:6px;">
      <label>Custom Claims JSON</label>
      <textarea id="fdp-claims" spellcheck="false" placeholder='{"sub":"alice","stage":"validate"}'
        style="width:100%; height:120px; margin-top:4px; padding:8px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px;"></textarea>
    </div>

    <div id="fdp-log" style="grid-column:1/-1; margin-top:8px; padding:8px; background:#0f1736; border:1px dashed #2a3a7a; border-radius:8px; white-space:pre-wrap; min-height:84px;"></div>
  </div>
</div>
  `);

  document.body.appendChild(panel);
  const $ = (sel) => panel.querySelector(sel);
  $("#fdp-close").onclick = () => panel.remove();

  const log = (m) => { $("#fdp-log").textContent += (m + "\n"); };
  const resetLog = () => { $("#fdp-log").textContent = ""; };

  const parseClaimsOr = (def) => {
    const raw = $("#fdp-claims").value.trim();
    if (!raw) return def;
    try {
      const obj = JSON.parse(raw);
      if (obj && typeof obj === "object") return obj;
      throw new Error("Claims must be an object");
    } catch (e) {
      log("❌ Invalid claims JSON: " + (e?.message || String(e)));
      return null;
    }
  };

  async function uploadValidate(expectAllow) {
    resetLog();

    const baseUrl = $("#fdp-base").value.trim();
    const vvkid   = $("#fdp-vvkid").value.trim();
    const uploaded = $("#fdp-uploaded").value.trim();
    const entryType = $("#fdp-entry").value.trim();
    const resource  = $("#fdp-resource").value.trim();
    const action    = $("#fdp-action").value.trim();
    const source    = $("#fdp-src").value;
    const modelId   = $("#fdp-model").value.trim();

    if (!baseUrl || !vvkid || !entryType || !source || !modelId) {
      log("❌ Missing required inputs (baseUrl, vvkid, modelId, entryType, source).");
      return;
    }

    const client = new NodeClient(baseUrl);
    try {
      const sdkVersion = await client.GetForsetiSdkVersion();
      log(`ℹ️ SDK Version: ${sdkVersion}`);

      const { bh, entryType: resolvedEntry } =
        await client.UploadPolicySource(vvkid, modelId, uploaded, entryType, sdkVersion, source);
      log(`✅ Uploaded: bh=${bh} entry=${resolvedEntry}`);

      // Fill BH field if empty
      if (!$("#fdp-contract").value.trim()) $("#fdp-contract").value = bh;

      const contractId = $("#fdp-contract").value.trim() || bh;

      let claims = parseClaimsOr({ sub: "alice", stage: "validate" });
      if (!claims) return;

      const res = await client.ValidateAccess(vvkid, modelId, contractId, resource, action, claims);
      log(`🧪 Validate → allowed=${res.allowed} error=${res.error ?? "null"}`);

      if (expectAllow === true && !res.allowed) log("❌ Expected ALLOW but got DENY.");
      else if (expectAllow === false && res.allowed) log("❌ Expected DENY but got ALLOW.");
      else if (expectAllow != null) log("✅ Behavior matched expectation.");
    } catch (err) {
      console.error(err);
      log("❌ Error: " + (err?.message ?? String(err)));
    }
  }

  async function validateOnly() {
    resetLog();

    const baseUrl = $("#fdp-base").value.trim();
    const vvkid   = $("#fdp-vvkid").value.trim();
    const contractId = $("#fdp-contract").value.trim();
    const modelId    = $("#fdp-model").value.trim();
    const resource   = $("#fdp-resource").value.trim();
    const action     = $("#fdp-action").value.trim();

    if (!baseUrl || !vvkid || !contractId || !modelId) {
      log("❌ Need baseUrl, vvkid, modelId, and BH/ContractId.");
      return;
    }

    let claims = parseClaimsOr({ sub: "alice", stage: "validate" });
    if (!claims) return;

    const client = new NodeClient(baseUrl);
    try {
      const res = await client.ValidateAccess(vvkid, modelId, contractId, resource, action, claims);
      log("↪ Raw response: " + JSON.stringify(res));
    } catch (e) {
      log("❌ Validate error: " + (e?.message || String(e)));
    }
  }

  $("#fdp-upload-allow").onclick = () => uploadValidate(true);
  $("#fdp-upload-deny").onclick  = () => {
    if (!$("#fdp-src").value.toLowerCase().includes("policydecision.deny")) {
      $("#fdp-entry").value = "AlwaysDeny";
      $("#fdp-src").value =
`using Ork.Forseti.Sdk;
public sealed class AlwaysDeny : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx) => PolicyDecision.Deny("nope");
}`;
    }
    uploadValidate(false);
  };
  $("#fdp-validate-only").onclick = () => validateOnly();
}
