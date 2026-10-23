// Integration: the official Stripe Node SDK pointed at a running stub. Stub calls never leave the
// process; the passthrough calls go to api.stripe.com with the TEST key from ~/.env (STRIPE_SK,
// sk_test_ only, never printed). Skipped when no test key is available.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import Stripe from "stripe";
import { startServer } from "../src/server.js";

function envFile(name: string): string | undefined {
  if (process.env[name]) return process.env[name];
  const p = join(homedir(), ".env");
  if (!existsSync(p)) return undefined;
  const line = readFileSync(p, "utf8").split("\n").find((l) => l.startsWith(`${name}=`));
  return line ? line.slice(name.length + 1).trim().replace(/^["']|["']$/g, "") : undefined;
}

const KEY = envFile("STRIPE_SK");
const PRODUCT = envFile("STRIPE_PRODUCT_ID");
const usable = !!KEY && KEY.startsWith("sk_test_") && !!PRODUCT;

test("Stripe SDK against the stub: stubbed objects + one passthrough read", { skip: usable ? false : "no sk_test_ STRIPE_SK / STRIPE_PRODUCT_ID in ~/.env" }, async () => {
  const port = 18000 + Math.floor(Math.random() * 1000);
  const s = startServer({ port, upstream: "https://api.stripe.com", emailSuffix: "@invalid.tide.test", logFile: "/dev/null" });
  try {
    const stripe = new Stripe(KEY!, { host: "127.0.0.1", port, protocol: "http", maxNetworkRetries: 0 });

    // Passthrough, read-only: the v2 product's active prices, exactly as the payer's catalogue asks.
    const prices = await stripe.prices.list({ product: PRODUCT!, active: true, expand: ["data.tiers"], limit: 10 });
    assert.equal(prices.object, "list");
    assert.ok(prices.data.length > 0, "product has active prices");
    const price = prices.data[0];

    // Stubbed: create customer + subscription the way CreateFreeTierLicense does.
    const customer = await stripe.customers.create({ email: `lt-itest-${Date.now()}@invalid.tide.test` });
    assert.match(customer.id, /^cus_lt_/);
    const anchor = Math.floor(Date.now() / 1000) + 23 * 86400;
    const sub = await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: price.id, quantity: 5 }],
      billing_cycle_anchor: anchor,
      metadata: { VendorData: "{}", RedirectUri: "http://localhost", LicensingTier: "BusinessTier" },
    });
    assert.match(sub.id, /^sub_lt_/);
    assert.equal(sub.status, "active");
    assert.equal(sub.items.data[0].price.id, price.id, "real price object copied in");
    assert.equal(sub.items.data[0].price.currency, price.currency);
    assert.equal(sub.items.data[0].quantity, 5);
    assert.ok(sub.current_period_end > Date.now() / 1000);
    assert.ok((sub.items.data[0] as unknown as { current_period_end: number }).current_period_end > Date.now() / 1000);

    // Read back, as GetSubscriptionStatus/Info do.
    const got = await stripe.subscriptions.retrieve(sub.id, { expand: ["latest_invoice"] });
    assert.equal(got.customer, customer.id);
    assert.equal((got.latest_invoice as Stripe.Invoice).status, "paid");
    const inv = await stripe.invoices.retrieve((got.latest_invoice as Stripe.Invoice).id!);
    assert.equal(inv.amount_paid, 0);

    // Lists filtered by a stub customer.
    const subs = await stripe.subscriptions.list({ customer: customer.id, limit: 100 });
    assert.equal(subs.data.length, 1);
    const invoices = await stripe.invoices.list({ customer: customer.id });
    assert.equal(invoices.data.length, 1);
    const cust = await stripe.customers.retrieve(customer.id);
    assert.equal((cust as Stripe.Customer).email, customer.email);

    // Unknown stub id: SDK raises Stripe's resource_missing.
    await assert.rejects(stripe.subscriptions.retrieve("sub_lt_doesnotexist"), (e: Stripe.errors.StripeError) => e.code === "resource_missing" && e.statusCode === 404);

    // Stats prove what reached Stripe.
    const stats = await (await fetch(`http://127.0.0.1:${port}/__stub/stats`)).json() as { decisions: Record<string, number> };
    // Only prices.list went to Stripe from the client side; the price lookup inside the
    // subscription create is internal and not a client request.
    assert.equal(stats.decisions.passthrough, 1);
    assert.equal(stats.decisions.stubbed, 8);
  } finally {
    await s.close();
  }
});
