// Entry point. Config from env: PORT, STRIPE_UPSTREAM, STUB_EMAIL_SUFFIX, STUB_STATE_FILE, STUB_LOG_FILE.

import { startServer, ALLOWED_UPSTREAM } from "./server.js";

const port = parseInt(process.env.PORT ?? "8090", 10);
const s = startServer({
  port,
  upstream: process.env.STRIPE_UPSTREAM ?? ALLOWED_UPSTREAM,
  emailSuffix: process.env.STUB_EMAIL_SUFFIX ?? "@invalid.tide.test",
  stateFile: process.env.STUB_STATE_FILE || undefined,
  logFile: process.env.STUB_LOG_FILE || undefined,
});
console.error(`stripe-stub listening on :${port}, upstream ${ALLOWED_UPSTREAM}, stub suffix ${process.env.STUB_EMAIL_SUFFIX ?? "@invalid.tide.test"}`);

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => { void s.close().then(() => process.exit(0)); });
}
