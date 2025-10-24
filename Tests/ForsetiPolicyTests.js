// tests/ForsetiPolicyTests.js
import NodeClient from "../Clients/NodeClient.js";

const h = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };

export function mountForsetiTester() {
  const EXISTING = document.getElementById("forseti-dev-panel");
  if (EXISTING) EXISTING.remove();

  const panel = h(`
<div id="forseti-dev-panel" style="
  position:fixed; inset:auto 12px 12px auto; z-index:2147483647;
  width: 700px; background:#0b1020; color:#e7ecff; border:1px solid #1e2a5a;
  border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.35); font:13px/1.35 ui-sans-serif,system-ui;">
  <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; border-bottom:1px solid #1e2a5a;">
    <strong style="font-size:14px">Forseti Dev Panel</strong>
    <button id="fdp-close" style="background:#152054; color:#c9d4ff; border:0; padding:4px 8px; border-radius:8px; cursor:pointer;">✕</button>
  </div>

  <div style="padding:12px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
    <label>Base URL
      <input id="fdp-base" type="text" value="http://localhost:1001" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>VVKiD (vendorId)
      <input id="fdp-vvkid" type="text" placeholder="tenant-123" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>ModelId (required)
      <input id="fdp-model" type="text" placeholder="sha256:..." style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>ContractId / BH (planner looks up by this; leave blank to use last upload BH)
      <input id="fdp-contract" type="text" placeholder="sha256:..." style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>Uploaded By
      <input id="fdp-uploaded" type="text" value="dev@local" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>Entry Type (FQN)
      <input id="fdp-entry" type="text" value="MyPolicy" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>Mode
      <select id="fdp-mode" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
        <option value="Enforce" selected>Enforce</option>
        <option value="Shadow">Shadow</option>
      </select>
    </label>
    <div style="align-self:center; opacity:.8">(Binding is unique per <code>(codeBh, mode)</code>)</div>

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
    if (ctx.Parameters.TryGetParameter<string>("stage", out var s) && s == "validate")
      return PolicyDecision.Allow();
    return PolicyDecision.Deny("wrong stage");
  }
}
      </textarea>
    </div>

    <div style="grid-column:1/-1; display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
      <button id="fdp-upload-allow" style="padding:8px 10px; border-radius:8px; border:0; background:#1c7b46; color:white; cursor:pointer;">Upload → Activate → Validate (expect ALLOW)</button>
      <button id="fdp-upload-deny"  style="padding:8px 10px; border-radius:8px; border:0; background:#8b2635; color:white; cursor:pointer;">Upload → Activate → Validate (expect DENY)</button>
      <button id="fdp-validate-only" style="padding:8px 10px; border-radius:8px; border:0; background:#2a3a7a; color:white; cursor:pointer;">Validate ONLY (use entered ModelId & ContractId)</button>
    </div>

    <div style="grid-column:1/-1; margin-top:6px;">
      <label>Custom Parameters JSON (PolicyParameters)</label>
      <textarea id="fdp-params" spellcheck="false" placeholder='{"stage":"validate"}'
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

  const parseParamsOr = (def) => {
    const raw = $("#fdp-params").value.trim();
    if (!raw) return def;
    try {
      const obj = JSON.parse(raw);
      if (obj && typeof obj === "object") return obj;
      throw new Error("Parameters must be an object");
    } catch (e) {
      log("❌ Invalid parameters JSON: " + (e?.message || String(e)));
      return null;
    }
  };

  async function uploadActivateValidate(expectAllow) {
    resetLog();

    const baseUrl   = $("#fdp-base").value.trim();
    const vendorId  = $("#fdp-vvkid").value.trim();
    const modelIdIn = $("#fdp-model").value.trim();      // REQUIRED by your new API
    const uploaded  = $("#fdp-uploaded").value.trim();
    const entryType = $("#fdp-entry").value.trim();
    const resource  = $("#fdp-resource").value.trim();
    const action    = $("#fdp-action").value.trim();
    const source    = $("#fdp-src").value;
    const mode      = $("#fdp-mode").value;

    if (!baseUrl || !vendorId || !entryType || !source) {
      log("❌ Missing required inputs (baseUrl, vendorId, entryType, source).");
      return;
    }
    if (!modelIdIn) { log("❌ ModelId is required."); return; }

    const client = new NodeClient(baseUrl);
    try {
      const sdkVersion = await client.GetForsetiSdkVersion();
      log(`ℹ️ SDK Version: ${sdkVersion}`);

      // Upload requires vendorId + modelId now
      const { bh, entryType: resolvedEntry } =
        await client.UploadPolicySource(vendorId, modelIdIn, uploaded, entryType, sdkVersion, source);
      log(`✅ Uploaded: bh=${bh} entry=${resolvedEntry}`);

      // If user left ContractId empty, default to the uploaded BH
      if (!$("#fdp-contract").value.trim()) $("#fdp-contract").value = bh;

      // Optional: activate binding (depends on whether your server exposes it)
      if (typeof client.ActivatePolicyBinding === "function") {
        await client.ActivatePolicyBinding(bh, resolvedEntry, mode);
        log(`✅ Activated binding (mode=${mode})`);
      }

      const parameters = parseParamsOr({ stage: "validate" });
      if (!parameters) return;

      const contractId = $("#fdp-contract").value.trim() || bh;
      const modelId    = $("#fdp-model").value.trim();

      const res = await client.ValidateAccess(vendorId, modelId, contractId, resource, action, parameters);
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

    const baseUrl    = $("#fdp-base").value.trim();
    const vendorId   = $("#fdp-vvkid").value.trim();
    const modelId    = $("#fdp-model").value.trim();
    const contractId = $("#fdp-contract").value.trim();
    const resource   = $("#fdp-resource").value.trim();
    const action     = $("#fdp-action").value.trim();

    if (!baseUrl || !vendorId) { log("❌ Need baseUrl and vendorId."); return; }
    if (!modelId)   { log("❌ Need ModelId.");   return; }
    if (!contractId){ log("❌ Need ContractId (BH)."); return; }

    const parameters = parseParamsOr({ stage: "validate" });
    if (!parameters) return;

    const client = new NodeClient(baseUrl);
    try {
      const res = await client.ValidateAccess(vendorId, modelId, contractId, resource, action, parameters);
      log("↪ Raw response: " + JSON.stringify(res));
    } catch (e) {
      log("❌ Validate error: " + (e?.message || String(e)));
    }
  }

  $("#fdp-upload-allow").onclick = () => uploadActivateValidate(true);
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
    uploadActivateValidate(false);
  };
  $("#fdp-validate-only").onclick = () => validateOnly();
}
