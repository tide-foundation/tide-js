// Unit tests: routing, form parsing, expand, period dates, live-key refusal, error shape. No network.

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseForm } from "../src/form.js";
import { Store, addMonth, type Obj } from "../src/store.js";
import { StubHandler, decide, isLiveKey, type StubRequest } from "../src/handler.js";

const cfg = { emailSuffix: "@invalid.tide.test" };
const TEST_KEY = { authorization: "Bearer sk_test_unit" };

const PRICE: Obj = { id: "price_123", object: "price", currency: "usd", unit_amount: 0, metadata: { user_limit: "5" }, tiers: [] };
let priceCalls = 0;
const fakePrice = async (id: string) => {
  priceCalls++;
  return id === "price_123" ? { status: 200, body: PRICE } : { status: 404, body: { error: { type: "invalid_request_error", code: "resource_missing", message: `No such price: '${id}'` } } };
};

function req(method: string, path: string, body = "", query = "", headers: Record<string, string> = TEST_KEY): StubRequest {
  return { method, path, query, body, headers };
}

test("form parsing handles nested keys, arrays and appends", () => {
  const f = parseForm("customer=cus_1&items[0][price]=p1&items[0][quantity]=5&items[1][price]=p2&metadata[VendorData]=%7B%22a%22%3A1%7D&expand[]=latest_invoice&expand[]=customer");
  assert.equal(f.customer, "cus_1");
  assert.deepEqual(f.items, [{ price: "p1", quantity: "5" }, { price: "p2" }]);
  assert.deepEqual(f.metadata, { VendorData: '{"a":1}' });
  assert.deepEqual(f.expand, ["latest_invoice", "customer"]);
});

test("routing: stub only load-test objects, pass the rest through", () => {
  const s = new Store();
  assert.equal(decide(req("POST", "/v1/customers", "email=lt-r1-ws1%40invalid.tide.test"), s, cfg).kind, "stub");
  assert.equal(decide(req("POST", "/v1/customers", "email=real%40customer.com"), s, cfg).kind, "passthrough");
  assert.equal(decide(req("POST", "/v1/subscriptions", "customer=cus_lt_abc&items[0][price]=p"), s, cfg).kind, "stub");
  assert.equal(decide(req("POST", "/v1/subscriptions", "customer=cus_REAL&items[0][price]=p"), s, cfg).kind, "passthrough");
  assert.equal(decide(req("GET", "/v1/subscriptions/sub_lt_x"), s, cfg).kind, "stub");
  assert.equal(decide(req("GET", "/v1/subscriptions", "", "customer=cus_lt_x&limit=100"), s, cfg).kind, "stub");
  assert.equal(decide(req("GET", "/v1/invoices", "", "customer=cus_lt_x"), s, cfg).kind, "stub");
  assert.equal(decide(req("GET", "/v1/prices", "", "product=prod_1&active=true&expand[]=data.tiers"), s, cfg).kind, "passthrough");
  // A stub id somewhere unsupported is refused, never forwarded.
  const pm = decide(req("GET", "/v1/payment_methods", "", "customer=cus_lt_x"), s, cfg);
  assert.equal(pm.kind, "refuse");
});

test("live keys are refused before anything else", () => {
  assert.equal(isLiveKey({ authorization: "Bearer sk_live_abc" }), true);
  assert.equal(isLiveKey({ authorization: "Bearer rk_live_abc" }), true);
  assert.equal(isLiveKey({ authorization: "Basic " + Buffer.from("sk_live_abc:").toString("base64") }), true);
  assert.equal(isLiveKey({ authorization: "Bearer sk_test_abc" }), false);
  const d = decide(req("GET", "/v1/prices", "", "", { authorization: "Bearer sk_live_x" }), new Store(), cfg);
  assert.equal(d.kind, "refuse");
  if (d.kind === "refuse") assert.equal(d.status, 403);
});

test("create customer and subscription: active, future period on sub and items, real price, invoice", async () => {
  priceCalls = 0;
  const s = new Store();
  const h = new StubHandler(s, cfg, fakePrice);
  const c = await h.handle(req("POST", "/v1/customers", "email=lt-r1-ws1%40invalid.tide.test"));
  assert.equal(c.status, 200);
  const cus = c.body.id as string;
  assert.match(cus, /^cus_lt_/);
  assert.equal(c.body.email, "lt-r1-ws1@invalid.tide.test");

  const t = Math.floor(Date.now() / 1000);
  const anchorTs = addMonth(t) - 7 * 86400;
  const r = await h.handle(req("POST", "/v1/subscriptions",
    `customer=${cus}&items[0][price]=price_123&items[0][quantity]=5&billing_cycle_anchor=${anchorTs}&metadata[LicensingTier]=BusinessTier&metadata[VendorData]=x`));
  assert.equal(r.status, 200);
  const sub = r.body;
  assert.match(sub.id as string, /^sub_lt_/);
  assert.equal(sub.status, "active");
  assert.equal(sub.customer, cus);
  assert.equal(sub.currency, "usd");
  assert.deepEqual(sub.metadata, { LicensingTier: "BusinessTier", VendorData: "x" });
  assert.equal(sub.current_period_end, anchorTs);
  assert.ok((sub.current_period_end as number) > t + 20 * 86400);
  const item = ((sub.items as Obj).data as Obj[])[0];
  assert.match(item.id as string, /^si_lt_/);
  assert.equal(item.quantity, 5);
  assert.equal((item.price as Obj).id, "price_123");
  assert.equal(item.current_period_end, anchorTs);
  assert.equal(sub.cancel_at_period_end, false);
  assert.equal(sub.pause_collection, null);
  assert.equal(sub.default_payment_method, null);
  assert.match(sub.latest_invoice as string, /^in_lt_/);

  // Without an anchor the period is one month.
  const r2 = await h.handle(req("POST", "/v1/subscriptions", `customer=${cus}&items[0][price]=price_123`));
  assert.equal(r2.body.current_period_end, addMonth(r2.body.current_period_start as number));
  assert.equal(priceCalls, 1, "price is cached");

  // Expand latest_invoice.
  const g = await h.handle(req("GET", `/v1/subscriptions/${sub.id}`, "", "expand[]=latest_invoice.payment_intent"));
  const inv = g.body.latest_invoice as Obj;
  assert.equal(inv.status, "paid");
  assert.equal(inv.amount_paid, 0);
  assert.equal(inv.payment_intent, null);

  // Lists by customer, newest first.
  const l = await h.handle(req("GET", "/v1/subscriptions", "", `customer=${cus}&limit=100`));
  assert.equal(l.body.object, "list");
  assert.equal((l.body.data as Obj[]).length, 2);
  assert.equal(l.body.has_more, false);
  const li = await h.handle(req("GET", "/v1/invoices", "", `customer=${cus}`));
  assert.equal((li.body.data as Obj[]).length, 2);

  // Update metadata and quantity, then cancel.
  const u = await h.handle(req("POST", `/v1/subscriptions/${sub.id}`, `metadata[LicensingTier]=FreeTier&items[0][id]=${item.id}&items[0][quantity]=7`));
  assert.equal((u.body.metadata as Obj).LicensingTier, "FreeTier");
  assert.equal((((u.body.items as Obj).data as Obj[])[0]).quantity, 7);
  const d = await h.handle(req("DELETE", `/v1/subscriptions/${sub.id}`));
  assert.equal(d.body.status, "canceled");
  const l2 = await h.handle(req("GET", "/v1/subscriptions", "", `customer=${cus}`));
  assert.equal((l2.body.data as Obj[]).length, 1, "canceled ones drop out of the default list");
});

test("unknown stub ids give Stripe's 404 shape; unknown price is passed back", async () => {
  const s = new Store();
  const h = new StubHandler(s, cfg, fakePrice);
  const r = await h.handle(req("GET", "/v1/subscriptions/sub_lt_nope"));
  assert.equal(r.status, 404);
  const err = r.body.error as Obj;
  assert.equal(err.type, "invalid_request_error");
  assert.equal(err.code, "resource_missing");
  assert.match(err.message as string, /No such subscription: 'sub_lt_nope'/);
  const c = await h.handle(req("POST", "/v1/customers", "email=a%40invalid.tide.test"));
  const bad = await h.handle(req("POST", "/v1/subscriptions", `customer=${c.body.id}&items[0][price]=price_missing`));
  assert.equal(bad.status, 404);
});

test("state survives a restart through the state file", async () => {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const file = join(mkdtempSync(join(tmpdir(), "stub-")), "state.json");
  const s1 = new Store(file);
  const h = new StubHandler(s1, cfg, fakePrice);
  const c = await h.handle(req("POST", "/v1/customers", "email=b%40invalid.tide.test"));
  s1.flush();
  const s2 = new Store(file);
  assert.ok(s2.state.customers[c.body.id as string]);
});
