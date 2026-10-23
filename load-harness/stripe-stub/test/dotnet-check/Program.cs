// Drives the stub with Stripe.net 47.3.0 the way the ORK payer does in CreateFreeTierLicense and
// GetSubscriptionStatus/Info, and checks the fields the payer reads deserialize.
// Usage: STUB=http://127.0.0.1:8090 PRICE=price_... STRIPE_SK=sk_test_... dotnet run
using Stripe;

var stub = Environment.GetEnvironmentVariable("STUB") ?? "http://127.0.0.1:8090";
var key = Environment.GetEnvironmentVariable("STRIPE_SK");
var priceId = Environment.GetEnvironmentVariable("PRICE");
if (string.IsNullOrEmpty(key) || !key.StartsWith("sk_test_") || string.IsNullOrEmpty(priceId)) { Console.Error.WriteLine("need STRIPE_SK (sk_test_) and PRICE"); return 2; }
StripeConfiguration.StripeClient = new StripeClient(key, apiBase: stub);

int fails = 0;
void Check(bool ok, string what) { Console.WriteLine($"{(ok ? "ok  " : "FAIL")} {what}"); if (!ok) fails++; }

var customer = new CustomerService().Create(new CustomerCreateOptions { Email = $"lt-dotnet-{DateTime.UtcNow.Ticks}@invalid.tide.test" });
Check(customer.Id.StartsWith("cus_lt_"), "customer created by stub");

var anchor = DateTime.UtcNow.AddMonths(1).AddDays(-7);
var sub = new SubscriptionService().Create(new SubscriptionCreateOptions
{
    Customer = customer.Id,
    Items = new List<SubscriptionItemOptions> { new SubscriptionItemOptions { Price = priceId, Quantity = 5 } },
    BillingCycleAnchor = anchor,
    Metadata = new Dictionary<string, string> { { "VendorData", "{}" }, { "RedirectUri", "http://x" }, { "LicensingTier", "BusinessTier" } },
});
Check(sub.Id.StartsWith("sub_lt_"), "subscription created by stub");
Check(sub.Status == "active", "Status active");
Check(sub.CustomerId == customer.Id, "CustomerId echoes");
Check(sub.CurrentPeriodEnd > DateTime.UtcNow.AddDays(20), $"CurrentPeriodEnd in the future ({sub.CurrentPeriodEnd:o})");
var graced = new DateTimeOffset(DateTime.SpecifyKind(sub.CurrentPeriodEnd, DateTimeKind.Utc)).ToUnixTimeSeconds();
Check(graced > DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "ComputeGracedExpiry input is future");
Check(sub.Items.Data.Count == 1 && sub.Items.Data[0].Price?.Id == priceId, "Items.Data[0].Price.Id");
Check(sub.Items.Data[0].Quantity == 5, "Items.Data[0].Quantity");
Check(sub.Items.Data[0].Id.StartsWith("si_lt_"), "Items.Data[0].Id");
Check(sub.Metadata.TryGetValue("LicensingTier", out var t) && t == "BusinessTier", "Metadata LicensingTier");
Check(!sub.CancelAtPeriodEnd, "CancelAtPeriodEnd false");
Check(sub.LatestInvoiceId?.StartsWith("in_lt_") == true, "LatestInvoiceId");

var got = new SubscriptionService().Get(sub.Id);
Check(got.Status == "active" && got.CustomerId == customer.Id, "Get: Status + CustomerId (GetSubscriptionStatus)");
var inv = new InvoiceService().Get(got.LatestInvoiceId);
Check(inv.Status == "paid" && inv.AmountPaid == 0, "Invoice Get (latest invoice)");
var withInv = new SubscriptionService().Get(sub.Id, new SubscriptionGetOptions { Expand = new List<string> { "latest_invoice.payment_intent" } });
Check(withInv.LatestInvoice?.Status == "paid", "expand latest_invoice.payment_intent");
var list = new SubscriptionService().List(new SubscriptionListOptions { Customer = customer.Id, Limit = 100 });
Check(list.Data.Count == 1 && list.Data[0].Created <= DateTime.UtcNow, "List by customer + Created");
var c2 = new CustomerService().Get(customer.Id, new CustomerGetOptions { Expand = new List<string> { "invoice_settings.default_payment_method" } });
Check(c2.Email == customer.Email && c2.InvoiceSettings != null, "Customer Get with expand");
var upd = new SubscriptionService().Update(sub.Id, new SubscriptionUpdateOptions { Metadata = new Dictionary<string, string> { { "LicensingTier", "FreeTier" } } });
Check(upd.Metadata["LicensingTier"] == "FreeTier", "Update metadata");
try { new SubscriptionService().Get("sub_lt_missing"); Check(false, "404 raises"); }
catch (StripeException e) { Check(e.HttpStatusCode == System.Net.HttpStatusCode.NotFound && e.StripeError?.Code == "resource_missing", "404 resource_missing as StripeException"); }

Console.WriteLine(fails == 0 ? "ALL OK" : $"{fails} FAILED");
return fails == 0 ? 0 : 1;
