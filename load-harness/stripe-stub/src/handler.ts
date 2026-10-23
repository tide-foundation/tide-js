// Request routing: decide stub vs passthrough, then serve stub objects. No I/O here except the
// price lookup, which goes to the upstream through the injected fetcher.

import { parseForm, str, strList, strMap, type FormObject, type FormValue } from "./form.js";
import { Store, STUB_ID, STUB_ID_ANYWHERE, makeCustomer, makeSubscription, makeItem, expand, list, stripeError, now, type Obj } from "./store.js";

export interface StubRequest {
  method: string;
  path: string;        // no query
  query: string;       // raw, no leading "?"
  body: string;        // raw form body
  headers: Record<string, string | undefined>;
}

export interface StubResponse {
  status: number;
  body: Obj;
  ids?: string[];
}

export type Decision =
  | { kind: "stub"; reason: string }
  | { kind: "passthrough" }
  | { kind: "refuse"; status: number; body: Obj; reason: string };

export interface Config {
  emailSuffix: string;
}

// Price lookups reuse the caller's key and API version, through the upstream.
export type PriceFetcher = (priceId: string, headers: Record<string, string | undefined>) => Promise<{ status: number; body: Obj }>;

function bearerKey(h: Record<string, string | undefined>): string | null {
  const a = h["authorization"];
  if (!a) return null;
  if (/^bearer /i.test(a)) return a.slice(7).trim();
  if (/^basic /i.test(a)) {
    try { return Buffer.from(a.slice(6).trim(), "base64").toString().split(":")[0]; } catch { return null; }
  }
  return null;
}

export function isLiveKey(h: Record<string, string | undefined>): boolean {
  const k = bearerKey(h);
  return !!k && /^(sk|rk)_live_/.test(k);
}

function segs(path: string): string[] {
  return path.replace(/\/+$/, "").split("/").filter(Boolean);
}

export function decide(req: StubRequest, store: Store, cfg: Config): Decision {
  if (isLiveKey(req.headers)) {
    return { kind: "refuse", reason: "live-key", ...stripeError(403, "livemode_mismatch", "This Stripe stub only accepts test-mode keys.") };
  }
  const s = segs(req.path);
  const q = parseForm(req.query);
  const form = req.method === "POST" ? parseForm(req.body) : {};
  if (s[0] !== "v1") return { kind: "passthrough" };
  const res = s[1];
  const id = s[2];

  if (id && STUB_ID.test(id)) return { kind: "stub", reason: `${res}/${id.split("_lt_")[0]}` };
  if (req.method === "POST" && res === "customers" && !id) {
    const email = str(form.email) ?? "";
    if (email.toLowerCase().endsWith(cfg.emailSuffix.toLowerCase())) return { kind: "stub", reason: "create-customer" };
  }
  if (req.method === "POST" && res === "subscriptions" && !id) {
    const c = str(form.customer) ?? "";
    if (STUB_ID.test(c)) return { kind: "stub", reason: "create-subscription" };
  }
  if (req.method === "GET" && !id && (res === "subscriptions" || res === "invoices")) {
    const c = str(q.customer) ?? str(q.subscription) ?? "";
    if (STUB_ID.test(c)) return { kind: "stub", reason: `list-${res}` };
  }
  // Anything else that names a stub object must never reach Stripe.
  if (STUB_ID_ANYWHERE.test(req.path) || STUB_ID_ANYWHERE.test(req.query) || STUB_ID_ANYWHERE.test(req.body)) {
    return { kind: "refuse", reason: "stub-unsupported", ...stripeError(400, "parameter_unknown", `The Stripe stub does not support ${req.method} ${req.path} for load-test objects.`) };
  }
  return { kind: "passthrough" };
}

function expandList(q: FormObject, form: FormObject): string[] {
  return [...strList(q.expand), ...strList(form.expand)];
}

function itemsInput(v: FormValue | undefined): Array<{ price?: string; quantity?: string; id?: string; deleted?: string }> {
  if (!v || typeof v === "string") return [];
  const arr = Array.isArray(v) ? v : Object.values(v);
  return arr.filter((x): x is FormObject => typeof x === "object" && !Array.isArray(x)).map((x) => ({
    price: str(x.price), quantity: str(x.quantity), id: str(x.id), deleted: str(x.deleted),
  }));
}

function anchor(v: FormValue | undefined): number | undefined {
  const s = str(v);
  if (!s || !/^\d+$/.test(s)) return undefined;
  return parseInt(s, 10);
}

export class StubHandler {
  private priceCache = new Map<string, { at: number; body: Obj }>();

  constructor(private store: Store, private cfg: Config, private fetchPrice: PriceFetcher) {}

  private async price(id: string, headers: Record<string, string | undefined>): Promise<{ ok: true; price: Obj } | { ok: false; status: number; body: Obj }> {
    const key = `${id}|${headers["stripe-version"] ?? ""}`;
    const hit = this.priceCache.get(key);
    if (hit && Date.now() - hit.at < 300_000) return { ok: true, price: hit.body };
    const r = await this.fetchPrice(id, headers);
    if (r.status !== 200) return { ok: false, status: r.status, body: r.body };
    this.priceCache.set(key, { at: Date.now(), body: r.body });
    return { ok: true, price: r.body };
  }

  async handle(req: StubRequest): Promise<StubResponse> {
    const st = this.store.state;
    const s = segs(req.path);
    const res = s[1];
    const id = s[2];
    const action = s[3];
    const q = parseForm(req.query);
    const form = req.method === "POST" ? parseForm(req.body) : {};
    const exp = expandList(q, form);
    const missing = (what: string, v: string) => stripeError(404, "resource_missing", `No such ${what}: '${v}'`, "id");

    // ---- customers
    if (res === "customers") {
      if (!id && req.method === "POST") {
        const c = makeCustomer({ email: str(form.email), name: str(form.name), metadata: strMap(form.metadata), description: str(form.description) });
        st.customers[c.id as string] = c;
        this.store.save();
        return { status: 200, body: c, ids: [c.id as string] };
      }
      const c = id ? st.customers[id] : undefined;
      if (!c) return missing("customer", id ?? "");
      if (req.method === "GET") return { status: 200, body: c, ids: [id] };
      if (req.method === "POST") {
        for (const k of ["email", "name", "description"]) if (str(form[k]) !== undefined) c[k] = str(form[k]);
        if (form.metadata) c.metadata = { ...(c.metadata as Obj), ...strMap(form.metadata) };
        this.store.save();
        return { status: 200, body: c, ids: [id] };
      }
      if (req.method === "DELETE") {
        delete st.customers[id];
        this.store.save();
        return { status: 200, body: { id, object: "customer", deleted: true }, ids: [id] };
      }
    }

    // ---- subscriptions
    if (res === "subscriptions") {
      if (!id && req.method === "POST") {
        const customer = str(form.customer)!;
        if (!st.customers[customer]) return missing("customer", customer);
        const items = [];
        for (const it of itemsInput(form.items)) {
          if (!it.price) return stripeError(400, "parameter_missing", "Missing required param: items[0][price].", "items");
          const p = await this.price(it.price, req.headers);
          if (!p.ok) return { status: p.status, body: p.body };
          items.push({ price: p.price, quantity: it.quantity ? parseInt(it.quantity, 10) : 1 });
        }
        if (!items.length) return stripeError(400, "parameter_missing", "Missing required param: items.", "items");
        const { sub, invoice } = makeSubscription({ customer, items, metadata: strMap(form.metadata), billingCycleAnchor: anchor(form.billing_cycle_anchor), description: str(form.description) });
        st.subscriptions[sub.id as string] = sub;
        st.invoices[invoice.id as string] = invoice;
        this.store.save();
        return { status: 200, body: expand(sub, exp, st), ids: [sub.id as string, invoice.id as string] };
      }
      if (!id && req.method === "GET") {
        const customer = str(q.customer);
        const status = str(q.status);
        const data = Object.values(st.subscriptions)
          .filter((x) => x.customer === customer)
          .filter((x) => (status && status !== "all" ? x.status === status : status === "all" || x.status !== "canceled"))
          .sort((a, b) => (b.created as number) - (a.created as number));
        return { status: 200, body: list(data.map((x) => expand(x, exp.map((e) => e.replace(/^data\./, "")), st)), "/v1/subscriptions"), ids: data.map((x) => x.id as string) };
      }
      const sub = id ? st.subscriptions[id] : undefined;
      if (!sub) return missing("subscription", id ?? "");
      if (req.method === "GET") return { status: 200, body: expand(sub, exp, st), ids: [id] };
      if (req.method === "DELETE" || (req.method === "POST" && action === "cancel")) {
        sub.status = "canceled";
        sub.canceled_at = now();
        sub.ended_at = now();
        this.store.save();
        return { status: 200, body: expand(sub, exp, st), ids: [id] };
      }
      if (req.method === "POST" && !action) {
        if (form.metadata) sub.metadata = { ...(sub.metadata as Obj), ...strMap(form.metadata) };
        for (const k of ["cancel_at_period_end"]) if (str(form[k]) !== undefined) sub[k] = str(form[k]) === "true";
        if (str(form.description) !== undefined) sub.description = str(form.description);
        if (form.items) {
          const cur = (sub.items as Obj).data as Obj[];
          const next: Obj[] = [];
          const touched = new Set<string>();
          for (const it of itemsInput(form.items)) {
            if (it.id) {
              touched.add(it.id);
              if (it.deleted === "true") continue;
              const existing = cur.find((x) => x.id === it.id);
              if (!existing) return stripeError(404, "resource_missing", `No such subscription item: '${it.id}'`, "items");
              if (it.price && it.price !== (existing.price as Obj).id) {
                const p = await this.price(it.price, req.headers);
                if (!p.ok) return { status: p.status, body: p.body };
                existing.price = p.price;
              }
              if (it.quantity) existing.quantity = parseInt(it.quantity, 10);
              next.push(existing);
            } else if (it.price) {
              const p = await this.price(it.price, req.headers);
              if (!p.ok) return { status: p.status, body: p.body };
              next.push(makeItem(id, { price: p.price, quantity: it.quantity ? parseInt(it.quantity, 10) : 1 }, sub.current_period_start as number, sub.current_period_end as number));
            }
          }
          for (const x of cur) if (!touched.has(x.id as string)) next.push(x);
          (sub.items as Obj).data = next;
          (sub.items as Obj).total_count = next.length;
          sub.quantity = next.length === 1 ? next[0].quantity : null;
        }
        this.store.save();
        return { status: 200, body: expand(sub, exp, st), ids: [id] };
      }
    }

    // ---- invoices
    if (res === "invoices") {
      if (!id && req.method === "GET") {
        const customer = str(q.customer);
        const subscription = str(q.subscription);
        const data = Object.values(st.invoices).filter((x) => (customer ? x.customer === customer : true) && (subscription ? x.subscription === subscription : true));
        return { status: 200, body: list(data, "/v1/invoices"), ids: data.map((x) => x.id as string) };
      }
      const inv = id ? st.invoices[id] : undefined;
      if (!inv) return missing("invoice", id ?? "");
      if (req.method === "GET") return { status: 200, body: inv, ids: [id] };
      if (req.method === "POST" && !action) {
        if (form.metadata) inv.metadata = { ...(inv.metadata as Obj), ...strMap(form.metadata) };
        this.store.save();
        return { status: 200, body: inv, ids: [id] };
      }
      if (req.method === "POST" && action === "void") {
        inv.status = "void";
        this.store.save();
        return { status: 200, body: inv, ids: [id] };
      }
    }

    return stripeError(400, "parameter_unknown", `The Stripe stub does not support ${req.method} ${req.path} for load-test objects.`);
  }
}
