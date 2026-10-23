// Stub objects and their in-memory store, optionally persisted to a JSON file.
// Shapes follow the Stripe API version Stripe.net 47.x pins (2025-01-27.acacia): period dates live
// on the subscription; they are also set on each item so newer API readers work too.

import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";

export type Obj = Record<string, unknown>;

export const STUB_ID = /^(cus|sub|si|in)_lt_[A-Za-z0-9]+$/;
export const STUB_ID_ANYWHERE = /\b(cus|sub|si|in)_lt_[A-Za-z0-9]+/;

export function newId(prefix: "cus" | "sub" | "si" | "in"): string {
  return `${prefix}_lt_${randomBytes(9).toString("base64url").replace(/[-_]/g, "x")}`;
}

export const now = (): number => Math.floor(Date.now() / 1000);

// Same day next month, clamped to the month's last day (Stripe's rule).
export function addMonth(ts: number): number {
  const d = new Date(ts * 1000);
  const day = d.getUTCDate();
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1, d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()));
  const last = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 0)).getUTCDate();
  t.setUTCDate(Math.min(day, last));
  return Math.floor(t.getTime() / 1000);
}

export function list(data: Obj[], url: string): Obj {
  return { object: "list", data, has_more: false, url };
}

export function stripeError(status: number, code: string, message: string, param?: string): { status: number; body: Obj } {
  return {
    status,
    body: { error: { type: "invalid_request_error", code, message, ...(param ? { param } : {}), doc_url: `https://stripe.com/docs/error-codes/${code.replace(/_/g, "-")}` } },
  };
}

export interface State {
  customers: Record<string, Obj>;
  subscriptions: Record<string, Obj>;
  invoices: Record<string, Obj>;
}

export class Store {
  state: State = { customers: {}, subscriptions: {}, invoices: {} };
  private timer: NodeJS.Timeout | null = null;

  constructor(private file?: string) {
    if (file && existsSync(file)) {
      const j = JSON.parse(readFileSync(file, "utf8")) as Partial<State>;
      this.state = { customers: j.customers ?? {}, subscriptions: j.subscriptions ?? {}, invoices: j.invoices ?? {} };
    }
  }

  // Debounced write so a burst of creates is one disk write.
  save(): void {
    if (!this.file || this.timer) return;
    this.timer = setTimeout(() => this.flush(), 300);
    this.timer.unref();
  }

  flush(): void {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (!this.file) return;
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state));
    renameSync(tmp, this.file);
  }

  counts(): Record<string, number> {
    return {
      customers: Object.keys(this.state.customers).length,
      subscriptions: Object.keys(this.state.subscriptions).length,
      invoices: Object.keys(this.state.invoices).length,
    };
  }
}

export function makeCustomer(f: { email?: string; name?: string; metadata?: Record<string, string>; description?: string }): Obj {
  return {
    id: newId("cus"),
    object: "customer",
    address: null,
    balance: 0,
    created: now(),
    currency: null,
    default_source: null,
    delinquent: false,
    description: f.description ?? null,
    email: f.email ?? null,
    invoice_prefix: "LT",
    invoice_settings: { custom_fields: null, default_payment_method: null, footer: null, rendering_options: null },
    livemode: false,
    metadata: f.metadata ?? {},
    name: f.name ?? null,
    phone: null,
    preferred_locales: [],
    shipping: null,
    tax_exempt: "none",
  };
}

export function makeInvoice(customer: string, subscription: string, currency: string, start: number, end: number): Obj {
  const t = now();
  return {
    id: newId("in"),
    object: "invoice",
    amount_due: 0,
    amount_paid: 0,
    amount_remaining: 0,
    billing_reason: "subscription_create",
    collection_method: "charge_automatically",
    created: t,
    currency,
    customer,
    hosted_invoice_url: null,
    invoice_pdf: null,
    lines: { object: "list", data: [], has_more: false, url: "/v1/invoices/lines" },
    livemode: false,
    metadata: {},
    number: null,
    paid: true,
    payment_intent: null,
    period_start: start,
    period_end: end,
    status: "paid",
    status_transitions: { finalized_at: t, paid_at: t, voided_at: null, marked_uncollectible_at: null },
    subscription,
    subtotal: 0,
    total: 0,
  };
}

export interface ItemInput { price: Obj; quantity: number; id?: string }

export function makeItem(sub: string, it: ItemInput, start: number, end: number): Obj {
  return {
    id: it.id ?? newId("si"),
    object: "subscription_item",
    created: now(),
    current_period_start: start,
    current_period_end: end,
    metadata: {},
    price: it.price,
    quantity: it.quantity,
    subscription: sub,
  };
}

export function makeSubscription(f: {
  customer: string;
  items: ItemInput[];
  metadata: Record<string, string>;
  billingCycleAnchor?: number;
  description?: string;
}): { sub: Obj; invoice: Obj } {
  const id = newId("sub");
  const start = now();
  // A future billing_cycle_anchor ends the first period early, like Stripe does; otherwise one month.
  const end = f.billingCycleAnchor && f.billingCycleAnchor > start ? f.billingCycleAnchor : addMonth(start);
  const currency = (f.items[0]?.price?.currency as string) ?? "usd";
  const invoice = makeInvoice(f.customer, id, currency, start, end);
  const items = f.items.map((it) => makeItem(id, it, start, end));
  const sub: Obj = {
    id,
    object: "subscription",
    billing_cycle_anchor: end,
    cancel_at: null,
    cancel_at_period_end: false,
    canceled_at: null,
    collection_method: "charge_automatically",
    created: start,
    currency,
    current_period_start: start,
    current_period_end: end,
    customer: f.customer,
    default_payment_method: null,
    description: f.description ?? null,
    discount: null,
    ended_at: null,
    items: { object: "list", data: items, has_more: false, total_count: items.length, url: `/v1/subscription_items?subscription=${id}` },
    latest_invoice: invoice.id,
    livemode: false,
    metadata: f.metadata,
    pause_collection: null,
    plan: null,
    quantity: items.length === 1 ? items[0].quantity : null,
    start_date: start,
    status: "active",
    trial_end: null,
    trial_start: null,
  };
  return { sub, invoice };
}

// Resolve expand paths ("latest_invoice", "latest_invoice.payment_intent", "customer") on a copy.
export function expand(obj: Obj, paths: string[], store: State): Obj {
  const out: Obj = structuredClone(obj);
  for (const p of paths) {
    const [head] = p.split(".");
    const v = out[head];
    if (typeof v !== "string") continue;
    if (head === "latest_invoice" && store.invoices[v]) out[head] = structuredClone(store.invoices[v]);
    else if (head === "customer" && store.customers[v]) out[head] = structuredClone(store.customers[v]);
    // payment_intent on a paid $0 invoice is null, nothing further to expand.
  }
  return out;
}
