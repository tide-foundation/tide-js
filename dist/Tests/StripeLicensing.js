"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StripeLicensing = StripeLicensing;
exports.CheckLicenseAddedToPayer = CheckLicenseAddedToPayer;
const NodeClient_ts_1 = __importDefault(require("../Clients/NodeClient.ts"));
async function StripeLicensing() {
    const proceed = window.prompt("Run this command in your terminal, this will forward the webhook event to the correct endpoint for license issuance.\nUpdate --api-key to the test secret key from stripe", "docker run --rm -it stripe/stripe-cli listen --forward-to host.docker.internal:1001/payer/license/StripeWebhook --api-key sk_test_51PoIUiP0B8PCGiS8nGBZ1TOcfQzVXLD2WjnzUzcYRNGfpOFDkde3WPZX4Wj5jLpyPoB9vMTCipcfdqFDomCPChlt00yBOd48WO");
    if (proceed) {
        var client = new NodeClient_ts_1.default("http://localhost:1004");
        const redirectUrl = window.location.href.endsWith('/') ? window.location.href.slice(0, -1) : window.location.href;
        const vendorData = {
            GVRK: "010000000500000056524B3A3137000000010000002300000020000017ffad8068dc0de9935d36636f3ad1b5de6de3413b12388e453b05f2a4c1d3db08000000F7ED6F67000000000B000000526F7461746556524B3A311900000054696465636C6F616B55706461746553657474696E67733A31",
            VendorId: "54f2c12e7c0c713e6107a5f8b76cc0ead5be1309069e2bca0df033b20f0f2fc2"
        };
        const response = await client.CreateCheckoutSession(vendorData, redirectUrl, "FreeTier");
        if (response.status === 303) {
            var body = await response.json();
            window.location.href = body.redirectUrl;
        }
        else {
            client._handleError(response, "Create Checkout Session");
        }
    }
    else {
        console.log("You cancelled the stripe test, try adding license manually");
    }
}
async function CheckLicenseAddedToPayer() {
    var client = new NodeClient_ts_1.default("http://localhost:1004");
    const response = await client.IsLicenseActive("54f2c12e7c0c713e6107a5f8b76cc0ead5be1309069e2bca0df033b20f0f2fc2");
    if (response) {
        console.log("License has been activated!");
    }
    else {
        console.log("License FAILED to activate!");
    }
}
