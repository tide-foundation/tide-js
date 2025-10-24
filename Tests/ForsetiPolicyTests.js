// tests/ForsetiPolicyTests.js
import NodeClient from "../Clients/NodeClient.js";

/* ============================================================================
   Forseti Dev Panel (real VM/Docker flow)
   - Required: vvkid, modelId, resource, action
   - Optional: contractId (left empty unless user types; during Upload→Validate
     we will use the uploaded BH for that single call without mutating the input)
   - Claims: flat JSON (Dictionary<string, object>)
   ==========================================================================*/

const css = `
#forseti-dev-panel {
  position: fixed; inset: auto 16px 16px auto; z-index: 2147483647;
  width: 760px; max-height: 80vh; overflow: hidden; display: flex; flex-direction: column;
  background: #0b1020; color: #e7ecff; border: 1px solid #1e2a5a; border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0,0,0,.35); font: 13px/1.35 ui-sans-serif, system-ui;
}
#forseti-dev-panel .hdr {
  display:flex; align-items:center; gap:10px; justify-content:space-between;
  padding:10px 12px; border-bottom:1px solid #1e2a5a; background: #0b1533;
}
#forseti-dev-panel .hdr .title { font-weight: 600; font-size: 14px; letter-spacing:.2px;}
#forseti-dev-panel .content {
  padding: 12px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; overflow: auto;
}
#forseti-dev-panel label {
  display:flex; flex-direction:column; gap:6px; font-weight:600; color:#b8c3ff;
}
#forseti-dev-panel input[type="text"],
#forseti-dev-panel select,
#forseti-dev-panel textarea {
  width:100%; padding:8px 10px; border-radius:8px; border:1px solid #1e2a5a;
  background:#0f1736; color:#e7ecff; font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
#forseti-dev-panel textarea { min-height: 160px; resize: vertical; }
#forseti-dev-panel .row { grid-column: 1 / -1; }
#forseti-dev-panel .tips { opacity:.75; font-weight:400; }
#forseti-dev-panel .muted { opacity:.8; font-weight:400; }
#forseti-dev-panel .btns { display:flex; flex-wrap:wrap; gap:8px; }
#forseti-dev-panel button.btn {
  padding:8px 12px; border-radius:8px; border:1px solid transparent; cursor:pointer; font-weight:600;
}
.btn-primary { background:#1c7b46; color:white; }
.btn-secondary { background:#2a3a7a; color:white; }
.btn-danger { background:#8b2635; color:white; }
.btn-ghost { background:transparent; color:#c9d4ff; border-color:#2a3a7a; }
.kv { display:grid; grid-template-columns: 1fr 1fr; gap:10px; }
.input-required { outline: 2px solid #c24141; }
.flex { display:flex; align-items:center; gap:8px; }
.badge { display:inline-flex; align-items:center; gap:6px; padding:3px 8px; border-radius:999px; font-size:11px; }
.badge-ok { background:#13351f; color:#bef7cc; border:1px solid #295b3b; }
.badge-err{ background:#3b1414; color:#ffd6d6; border:1px solid #6b2222; }
.small { font-size: 11px; opacity:.85; }
#fdp-src-drop {
  border:2px dashed #2a3a7a; border-radius:8px; padding:8px; text-align:center; cursor:pointer;
  background:#0f1736; color:#c9d4ff; user-select:none;
}
#fdp-src-drop.dragover { background:#0e1b49; }
#fdp-log {
  background:#0f1736; border:1px dashed #2a3a7a; border-radius:8px; white-space:pre-wrap; min-height:110px; padding:8px;
  font:12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
#forseti-dev-panel .footer {
  padding:10px 12px; border-top:1px solid #1e2a5a; display:flex; align-items:center; gap:8px; justify-content:flex-end;
  background: #0b1533;
}
`;

const html = `
<div id="forseti-dev-panel" aria-live="polite">
  <div class="hdr">
    <div class="flex">
      <span class="title">Forseti Dev Panel — Real VM/Docker</span>
      <span id="fdp-json-badge" class="badge badge-ok">claims: OK</span>
    </div>
    <div class="flex">
      <button id="fdp-help" class="btn btn-ghost small">Help</button>
      <button id="fdp-close" class="btn btn-ghost">✕</button>
    </div>
  </div>

  <div class="content">
    <label>Base URL
      <input id="fdp-base" type="text" placeholder="http://localhost:1001">
    </label>
    <label>VVKiD (vendorId) <span class="muted small">(required)</span>
      <input id="fdp-vvkid" type="text" placeholder="tenant-123">
    </label>

    <label>ModelId <span class="muted small">(required)</span>
      <input id="fdp-model" type="text" placeholder="sha256:... or ForsetiModel:1">
    </label>
    <label>ContractId / BH <span class="muted small">(optional — we do NOT auto-fill)</span>
      <input id="fdp-contract" type="text" placeholder="sha256:...">
    </label>

    <label>Uploaded By
      <input id="fdp-uploaded" type="text" value="dev@local">
    </label>
    <label>Entry Type (FQN)
      <input id="fdp-entry" type="text" value="MyPolicy">
    </label>

    <label>Mode
      <select id="fdp-mode">
        <option value="Enforce" selected>Enforce</option>
        <option value="Shadow">Shadow</option>
      </select>
    </label>
    <div class="tips small">Binding is unique per <code>(codeBh, mode)</code>.</div>

    <label>Resource <span class="muted small">(required)</span>
      <input id="fdp-resource" type="text" value="/demo">
    </label>
    <label>Action <span class="muted small">(required)</span>
      <input id="fdp-action" type="text" value="read">
    </label>

    <div class="row">
      <div class="kv">
        <label>Policy Source (.cs)
          <div id="fdp-src-drop" tabindex="0">
            <div>📄 Drop a .cs file here or click to pick</div>
            <input id="fdp-file" type="file" accept=".cs,text/plain" style="display:none">
          </div>
        </label>
        <label>Or edit inline
          <textarea id="fdp-src" spellcheck="false" placeholder="// C# class implementing Ork.Forseti.Sdk.IAccessPolicy">
using Ork.Forseti.Sdk;
using Ork.Shared.Models.Contracts;
public sealed class MyPolicy : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx)
  {
    // Expect flat claims: {"stage":"validate","sub":"alice"}
    return ctx.Claims.TryGetParameter<string>("stage", out var s) && s == "validate"
      ? PolicyDecision.Allow()
      : PolicyDecision.Deny("wrong stage");
  }
}
          </textarea>
        </label>
      </div>
    </div>

    <div class="row btns">
      <button id="fdp-sample-allow"  class="btn btn-ghost small">Insert Sample: Allow</button>
      <button id="fdp-sample-deny"   class="btn btn-ghost small">Insert Sample: Deny</button>
      <span class="muted small">— Samples overwrite editor only (not file).</span>
    </div>

    <div class="row">
      <label>Claims JSON (flat Dictionary&lt;string, object&gt;) <span class="muted small">(ex: {"stage":"validate","sub":"alice"})</span>
        <textarea id="fdp-params" spellcheck="false" placeholder='{"stage":"validate","sub":"alice"}'></textarea>
      </label>
    </div>

    <div class="row btns">
      <button id="fdp-upload-allow" class="btn btn-primary">Upload → Activate → Validate (expect ALLOW)</button>
      <button id="fdp-upload-deny"  class="btn btn-danger">Upload → Activate → Validate (expect DENY)</button>
      <button id="fdp-validate-only" class="btn btn-secondary">Validate ONLY (use entered IDs)</button>
    </div>

    <div class="row">
      <label>Log</label>
      <div id="fdp-log"></div>
    </div>

  </div>

  <div class="footer">
    <button id="fdp-copy-log" class="btn btn-ghost small">Copy Log</button>
    <button id="fdp-clear" class="btn btn-ghost small">Clear</button>
  </div>
</div>
`;

const samples = {
  allow: `using Ork.Forseti.Sdk;
using Ork.Shared.Models.Contracts;
public sealed class MyPolicy : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx)
  {
    return ctx.Claims.TryGetParameter<string>("stage", out var s) && s == "validate"
      ? PolicyDecision.Allow()
      : PolicyDecision.Deny("wrong stage");
  }
}
`,
  deny: `using Ork.Forseti.Sdk;
using Ork.Shared.Models.Contracts;
public sealed class AlwaysDeny : IAccessPolicy
{
  public PolicyDecision Authorize(AccessContext ctx) => PolicyDecision.Deny("nope");
}
`
};

// mount function (exported)
export function mountForsetiTester() {
  // remove any existing panel
  const EXISTING = document.getElementById("forseti-dev-panel");
  if (EXISTING) EXISTING.remove();

  // style
  const style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  // panel
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  const panel = t.content.firstChild;
  document.body.appendChild(panel);

  // helpers
  const $ = (sel) => panel.querySelector(sel);

  const el = {
    base: $("#fdp-base"),
    vvkid: $("#fdp-vvkid"),
    model: $("#fdp-model"),
    contract: $("#fdp-contract"),
    uploaded: $("#fdp-uploaded"),
    entry: $("#fdp-entry"),
    mode: $("#fdp-mode"),
    res: $("#fdp-resource"),
    act: $("#fdp-action"),
    src: $("#fdp-src"),
    params: $("#fdp-params"),
    log: $("#fdp-log"),
    jsonBadge: $("#fdp-json-badge"),
    drop: $("#fdp-src-drop"),
    file: $("#fdp-file"),
  };

  // persistence
  const KEYS = [
    "fdp-base","fdp-vvkid","fdp-model","fdp-contract","fdp-uploaded","fdp-entry",
    "fdp-mode","fdp-resource","fdp-action","fdp-src","fdp-params"
  ];
  const load = () => {
    KEYS.forEach(k => {
      const v = localStorage.getItem(k);
      const n = $("#"+k);
      if (n && v != null) n.value = v;
    });
    if (!el.params.value) el.params.value = `{"stage":"validate","sub":"alice"}`;
    if (!el.base.value) el.base.value = "http://localhost:1001";
  };
  const save = () => {
    KEYS.forEach(k => {
      const n = $("#"+k);
      if (n) localStorage.setItem(k, n.value);
    });
  };
  panel.addEventListener("input", (e) => { if (e.target && e.target.id) save(); });
  load();

  // UX helpers
  const now = () => new Date().toISOString().replace("T"," ").replace("Z","");
  const log = (m) => { el.log.textContent += `[${now()}] ${m}\n`; el.log.scrollTop = el.log.scrollHeight; };
  const resetLog = () => { el.log.textContent = ""; };

  const requireField = (input, label) => {
    const v = input.value.trim();
    if (v) { input.classList.remove("input-required"); return v; }
    input.classList.add("input-required");
    input.focus();
    throw new Error(`Missing required: ${label}`);
  };

  const claimsOk = () => {
    try {
      const raw = el.params.value.trim();
      if (!raw) return true;
      const obj = JSON.parse(raw);
      return obj && typeof obj === "object" && !Array.isArray(obj);
    } catch { return false; }
  };
  const updateBadge = () => {
    const ok = claimsOk();
    el.jsonBadge.textContent = ok ? "claims: OK" : "claims: INVALID";
    el.jsonBadge.className = "badge " + (ok ? "badge-ok" : "badge-err");
  };
  el.params.addEventListener("input", updateBadge);
  updateBadge();

  const parseClaims = (def) => {
    const raw = el.params.value.trim();
    if (!raw) return def;
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      throw new Error("Claims must be a flat JSON object.");
    }
    return obj;
  };

  // File upload & drag-drop
  const setSource = (text) => { el.src.value = text || ""; save(); };
  const pickFile = () => el.file.click();
  el.drop.addEventListener("click", pickFile);
  el.drop.addEventListener("keydown", (e)=>{ if (e.key === "Enter" || e.key === " ") pickFile(); });
  el.file.addEventListener("change", async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const txt = await f.text();
    setSource(txt);
    log(`📥 Loaded file: ${f.name} (${f.size} bytes)`);
  });
  el.drop.addEventListener("dragover", (e)=> { e.preventDefault(); el.drop.classList.add("dragover"); });
  el.drop.addEventListener("dragleave", ()=> el.drop.classList.remove("dragover"));
  el.drop.addEventListener("drop", async (e)=> {
    e.preventDefault(); el.drop.classList.remove("dragover");
    const f = e.dataTransfer.files?.[0];
    if (!f) return;
    const txt = await f.text();
    setSource(txt);
    log(`📥 Dropped file: ${f.name} (${f.size} bytes)`);
  });

  // Samples
  $("#fdp-sample-allow").onclick = ()=> { setSource(samples.allow); };
  $("#fdp-sample-deny").onclick  = ()=> { setSource(samples.deny); };

  // Actions
  async function uploadActivateValidate(expectAllow) {
    resetLog();
    try {
      const baseUrl   = requireField(el.base, "Base URL");
      const vvkid     = requireField(el.vvkid, "VVKiD");
      const modelId   = requireField(el.model, "ModelId");
      const entryType = requireField(el.entry, "Entry Type");
      const resource  = requireField(el.res, "Resource");
      const action    = requireField(el.act, "Action");
      const source    = el.src.value;
      if (!source.trim()) throw new Error("Policy source is empty. Upload a .cs file or edit inline.");

      const client = new NodeClient(baseUrl);
      const sdkVersion = await client.GetForsetiSdkVersion();
      log(`ℹ️ SDK Version: ${sdkVersion}`);

      // Upload with (vvkid, modelId, uploadedBy, entryType, sdkVersion, source)
      const { bh, entryType: resolvedEntry } =
        await client.UploadPolicySource(vvkid, modelId, el.uploaded.value.trim(), entryType, sdkVersion, source);
      log(`✅ Uploaded: bh=${bh} entry=${resolvedEntry}`);

      // DO NOT mutate the ContractId input. For THIS run only, use BH if input is empty.
      const userEnteredContractId = el.contract.value.trim();
      const contractIdForThisRun  = userEnteredContractId || bh;
      if (!userEnteredContractId) {
        log(`ℹ️ Using uploaded BH as contractId (this run only). Input stays empty.`);
      }

      // Optional: activate binding if API exposes it
      if (typeof client.ActivatePolicyBinding === "function") {
        await client.ActivatePolicyBinding(bh, resolvedEntry, el.mode.value);
        log(`✅ Activated binding (mode=${el.mode.value})`);
      }

      const claims = parseClaims({ stage: "validate", sub: "alice" });

      // IMPORTANT: pass contractIdForThisRun (BH when input empty). Never use modelId as contractId.
      const res = await client.ValidateAccess(vvkid, modelId, contractIdForThisRun, resource, action, claims);
      log(`🧪 Validate → allowed=${res.allowed} error=${res.error ?? "null"}`);

      if (expectAllow === true && !res.allowed) log("❌ Expected ALLOW but got DENY.");
      else if (expectAllow === false && res.allowed) log("❌ Expected DENY but got ALLOW.");
      else if (expectAllow != null) log("✅ Behavior matched expectation.");
    } catch (err) {
      log("❌ " + (err?.message ?? String(err)));
      console.error(err);
    }
  }

  async function validateOnly() {
    resetLog();
    try {
      const baseUrl   = requireField(el.base, "Base URL");
      const vvkid     = requireField(el.vvkid, "VVKiD");
      const modelId   = requireField(el.model, "ModelId");
      const contractId= requireField(el.contract, "ContractId (BH)");
      const resource  = requireField(el.res, "Resource");
      const action    = requireField(el.act, "Action");

      const claims = parseClaims({ stage: "validate" });
      const client = new NodeClient(baseUrl);
      const res = await client.ValidateAccess(vvkid, modelId, contractId, resource, action, claims);
      log("↪ Raw response: " + JSON.stringify(res));
    } catch (e) {
      log("❌ Validate error: " + (e?.message || String(e)));
      console.error(e);
    }
  }

  // buttons
  $("#fdp-upload-allow").onclick = () => uploadActivateValidate(true);
  $("#fdp-upload-deny").onclick = () => {
    if (!el.src.value.toLowerCase().includes("policydecision.deny")) {
      el.entry.value = "AlwaysDeny";
      setSource(samples.deny);
    }
    uploadActivateValidate(false);
  };
  $("#fdp-validate-only").onclick = () => validateOnly();

  // footer + header
  $("#fdp-clear").onclick = () => resetLog();
  $("#fdp-copy-log").onclick = async () => {
    try { await navigator.clipboard.writeText(el.log.textContent || ""); log("📋 Log copied."); }
    catch { log("❌ Clipboard failed."); }
  };
  $("#fdp-help").onclick = () => {
    alert(
`Quick help:
• Required fields: VVKiD, ModelId, Resource, Action
• ContractId input is optional and is NOT auto-filled.
  During Upload → Validate, we use the returned BH as contractId ONLY for that run if the input is empty.
• Claims must be a flat JSON object: {"stage":"validate","sub":"alice"}
• Flow:
  UploadPolicySource(vvkid, modelId, uploadedBy, entryType, sdkVersion, source)
  → (optional) ActivatePolicyBinding(bh, entryType, mode)
  → ValidateAccess(vvkid, modelId, contractId, resource, action, claims)`
    );
  };
  $("#fdp-close").onclick = () => panel.remove();
}
