// TideCloak admin REST calls used by S3 and prepare-realms. Master admin password grant, cached
// until shortly before expiry. Tokens and passwords never leave this module.

import { CALLBACK_URL, OIDC_CLIENT_ID } from "./targets.js";

export interface AdminCreds { user: string; password: string }

export interface HttpResult { status: number; ms: number; text: string; location?: string | null }

export class AdminClient {
  private token: string | null = null;
  private expiresAt = 0;
  private inflight: Promise<string> | null = null;

  constructor(readonly tcBase: string, private creds: AdminCreds) {}

  secrets(): string[] {
    return [this.creds.password, this.token ?? ""].filter(Boolean);
  }

  async getToken(): Promise<string> {
    if (this.token && Date.now() < this.expiresAt - 15_000) return this.token;
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      const body = new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: this.creds.user, password: this.creds.password });
      const res = await fetch(`${this.tcBase}/realms/master/protocol/openid-connect/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });
      if (!res.ok) throw new Error(`admin token HTTP ${res.status}`);
      const j = (await res.json()) as { access_token: string; expires_in: number };
      this.token = j.access_token;
      this.expiresAt = Date.now() + (j.expires_in ?? 60) * 1000;
      return this.token;
    })();
    try {
      return await this.inflight;
    } finally {
      this.inflight = null;
    }
  }

  async call(method: string, path: string, body?: unknown, form?: Record<string, string>): Promise<HttpResult> {
    const token = await this.getToken();
    const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
    let payload: string | undefined;
    if (form) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      payload = new URLSearchParams(form).toString();
    } else if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const t0 = Date.now();
    const res = await fetch(`${this.tcBase}${path}`, { method, headers, body: payload, redirect: "manual" });
    const text = await res.text();
    return { status: res.status, ms: Date.now() - t0, text, location: res.headers.get("location") };
  }

  createRealm(realm: string): Promise<HttpResult> {
    return this.call("POST", "/admin/realms", { realm, enabled: true });
  }

  getRealm(realm: string): Promise<HttpResult> {
    return this.call("GET", `/admin/realms/${encodeURIComponent(realm)}`);
  }

  // Self-registration on, forced email verification off.
  async openRegistration(realm: string): Promise<HttpResult> {
    const cur = await this.getRealm(realm);
    if (cur.status !== 200) return cur;
    const rep = JSON.parse(cur.text) as Record<string, unknown>;
    rep.registrationAllowed = true;
    rep.verifyEmail = false;
    return this.call("PUT", `/admin/realms/${encodeURIComponent(realm)}`, rep);
  }

  // Public PKCE client matching what the harness flows use.
  async ensureHarnessClient(realm: string): Promise<HttpResult> {
    const q = await this.call("GET", `/admin/realms/${encodeURIComponent(realm)}/clients?clientId=${OIDC_CLIENT_ID}`);
    if (q.status === 200 && JSON.parse(q.text).length > 0) return { ...q, status: 204 };
    const cb = new URL(CALLBACK_URL);
    return this.call("POST", `/admin/realms/${encodeURIComponent(realm)}/clients`, {
      clientId: OIDC_CLIENT_ID,
      name: "Tide load-test harness",
      enabled: true,
      publicClient: true,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      redirectUris: [CALLBACK_URL],
      webOrigins: [cb.origin],
      attributes: { "pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+" },
    });
  }

  // Merge attributes into the realm (GET then PUT), like the console's setRealmAttribute.
  async setRealmAttributes(realm: string, attrs: Record<string, string>): Promise<HttpResult> {
    const cur = await this.getRealm(realm);
    if (cur.status !== 200) return cur;
    const rep = JSON.parse(cur.text) as { attributes?: Record<string, string> };
    rep.attributes = { ...(rep.attributes ?? {}), ...attrs };
    return this.call("PUT", `/admin/realms/${encodeURIComponent(realm)}`, rep);
  }

  // Register link-tide-account-action unless it is already there.
  async ensureLinkTideAction(realm: string): Promise<HttpResult> {
    const base = `/admin/realms/${encodeURIComponent(realm)}/authentication`;
    const list = await this.call("GET", `${base}/required-actions`);
    if (list.status === 200) {
      const rows = JSON.parse(list.text) as Array<{ alias?: string; providerId?: string; enabled?: boolean }>;
      if (rows.some((r) => r.alias === "link-tide-account-action" || r.providerId === "link-tide-account-action")) return { ...list, status: 204 };
    }
    return this.call("POST", `${base}/register-required-action`, { providerId: "link-tide-account-action", name: "Link Tide Account" });
  }

  // toggle-iga FLIPS the current state, so only call it when IGA is off.
  // Synchronous: sets EdDSA + iga.attestor=tide on a Tide realm, runs the ADOPT scan and the
  // firstAdmin sign-defaults sweep before it returns.
  toggleIga(realm: string): Promise<HttpResult> {
    return this.call("POST", `/admin/realms/${encodeURIComponent(realm)}/tide-admin/toggle-iga`, undefined, { isIGAEnabled: "true" });
  }

  async pendingChangeRequests(realm: string): Promise<Array<{ id: string; actionType?: string }>> {
    const r = await this.call("GET", `/admin/realms/${encodeURIComponent(realm)}/iga/change-requests?status=PENDING`);
    if (r.status === 404) return [];
    if (r.status !== 200) throw new Error(`list change requests HTTP ${r.status}`);
    const j = JSON.parse(r.text) as unknown;
    const arr = Array.isArray(j) ? j : ((j as { items?: unknown[] }).items ?? []);
    return arr as Array<{ id: string; actionType?: string }>;
  }

  // Approve-and-commit. In firstAdmin mode one approval meets threshold 1 and applies it.
  approveChangeRequest(realm: string, id: string): Promise<HttpResult> {
    return this.call("POST", `/admin/realms/${encodeURIComponent(realm)}/iga/change-requests/${encodeURIComponent(id)}/approve`, {});
  }

  setUpTideRealm(realm: string, email: string): Promise<HttpResult> {
    return this.call("POST", `/admin/realms/${encodeURIComponent(realm)}/vendorResources/setUpTideRealm`, undefined, {
      email,
      isRagnarokEnabled: "true",
      licensingTier: "FreeTier",
    });
  }

  // RegOn is part of the VVK-signed IdP settings the enclave reads, so a registration change
  // needs a re-sign before the sign-up link shows.
  signIdpSettings(realm: string): Promise<HttpResult> {
    return this.call("POST", `/admin/realms/${encodeURIComponent(realm)}/vendorResources/sign-idp-settings`);
  }

  subscriptionStatus(realm: string): Promise<HttpResult> {
    return this.call("GET", `/admin/realms/${encodeURIComponent(realm)}/vendorResources/getSubscriptionStatus`);
  }

  // Customer and subscription ids from the vendor-key component, for the cleanup manifest.
  // Only those two fields are read; the rest of the config is never stored.
  async billingIds(realm: string): Promise<{ customerId?: string; subscriptionId?: string }> {
    const r = await this.call("GET", `/admin/realms/${encodeURIComponent(realm)}/components?providerId=tide-vendor-key`);
    if (r.status !== 200) return {};
    const arr = JSON.parse(r.text) as Array<{ config?: Record<string, string[]> }>;
    const cfg = arr[0]?.config ?? {};
    return { customerId: cfg.customerId?.[0], subscriptionId: cfg.subscriptionId?.[0] };
  }
}
