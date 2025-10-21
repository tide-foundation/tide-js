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
  width: 520px; background:#0b1020; color:#e7ecff; border:1px solid #1e2a5a;
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
    <label>Rule Id
      <input id="fdp-rule" type="text" value="rule-allow" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>

    <label>Entry Type (FQN)
      <input id="fdp-entry" type="text" value="MyPolicy" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
    </label>
    <label>Priority
      <input id="fdp-priority" type="number" value="0" style="width:100%; padding:6px; border-radius:8px; border:1px solid #1e2a5a; background:#0f1736; color:#e7ecff;">
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

    <div style="grid-column:1/-1; display:flex; gap:8px; flex-wrap:wrap; margin-top:4px;">
      <button id="fdp-allow" style="padding:8px 10px; border-radius:8px; border:0; background:#1c7b46; color:white; cursor:pointer;">Upload + Bind + Validate (expect ALLOW)</button>
      <button id="fdp-deny"  style="padding:8px 10px; border-radius:8px; border:0; background:#8b2635; color:white; cursor:pointer;">Upload + Bind + Validate (expect DENY)</button>
      <button id="fdp-revoke" style="padding:8px 10px; border-radius:8px; border:0; background:#4a4e7a; color:white; cursor:pointer;">Revoke Last bh</button>
    </div>

    <div id="fdp-log" style="grid-column:1/-1; margin-top:8px; padding:8px; background:#0f1736; border:1px dashed #2a3a7a; border-radius:8px; white-space:pre-wrap; min-height:72px;"></div>
  </div>
</div>
  `);

  document.body.appendChild(panel);
  const $ = (id) => panel.querySelector(id);
  $("#fdp-close").onclick = () => panel.remove();

  let lastBh = null, lastEntry = null;

  async function uploadBindValidate(expectAllow) {
    const baseUrl   = $("#fdp-base").value.trim();
    const vvkid     = $("#fdp-vvkid").value.trim();
    const uploaded  = $("#fdp-uploaded").value.trim();
    const ruleId    = $("#fdp-rule").value.trim();
    const entryType = $("#fdp-entry").value.trim();
    const priority  = parseInt($("#fdp-priority").value, 10) || 0;
    const resource  = $("#fdp-resource").value.trim();
    const action    = $("#fdp-action").value.trim();
    const source    = $("#fdp-src").value;

    const log = (m) => { $("#fdp-log").textContent += (m + "\n"); };
    $("#fdp-log").textContent = "";

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

      // Your server currently keeps combiner on binding API; we pass a default but your orchestrator may ignore it.
      await client.UpsertPolicyBinding(
        vvkid, ruleId, "DenyOverrides", "Enforce", bh, resolvedEntry, priority);
      log(`✅ Bound rule=${ruleId} priority=${priority}`);

      const reqId = "fdp-" + Date.now();
      const claims = { sub: "alice", stage: "validate", "request.id": reqId };
      const res = await client.ValidateAccess(vvkid, resource, action, claims);
      log(`🧪 Validate → allowed=${res.allowed} error=${res.error ?? "null"}`);

      if (expectAllow && !res.allowed) {
        log("❌ Expected ALLOW but got DENY.");
      } else if (!expectAllow && res.allowed) {
        log("❌ Expected DENY but got ALLOW.");
      } else {
        log("✅ Behavior matched expectation.");
      }
    } catch (err) {
      console.error(err);
      $("#fdp-log").textContent += "❌ Error: " + (err?.message ?? String(err)) + "\n";
    }
  }

  async function revokeLast() {
    const baseUrl = $("#fdp-base").value.trim();
    const vvkid   = $("#fdp-vvkid").value.trim();
    if (!baseUrl || !vvkid || !lastBh) {
      $("#fdp-log").textContent += "❌ Need baseUrl, vvkid, and a previously uploaded bh.\n";
      return;
    }
    try {
      const client = new NodeClient(baseUrl);
      const res = await client.RevokePolicyBh(vvkid, lastBh, "dev-panel");
      $("#fdp-log").textContent += `🔁 Revoke(${lastBh}): ${JSON.stringify(res)}\n`;
    } catch (err) {
      $("#fdp-log").textContent += "❌ Revoke error: " + (err?.message ?? String(err)) + "\n";
    }
  }

  $("#fdp-allow").onclick = () => uploadBindValidate(true);
  $("#fdp-deny").onclick  = () => {
    // swap source to AlwaysDeny quickly if the current entryType says AlwaysDeny
    const entry = $("#fdp-entry").value.trim();
    if (entry.toLowerCase().includes("alwaysdeny")) {
      // user already prepared deny policy; just run
      uploadBindValidate(false);
    } else {
      // quick replace to deny template
      $("#fdp-entry").value = "AlwaysDeny";
      $("#fdp-src").value =
`using Ork.Forseti.Sdk;
public sealed class AlwaysDeny : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx) => PolicyDecision.Deny("nope");
}`;
      uploadBindValidate(false);
    }
  };
  $("#fdp-revoke").onclick = revokeLast;
}
