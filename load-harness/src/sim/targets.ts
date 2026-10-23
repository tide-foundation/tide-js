// Target allowlist. Staging and a local stack only; production hosts are refused outright.

export type TargetName = "staging" | "local";

export interface Target {
  name: TargetName;
  tcBase: string;
  // Azure names, used only by the optional read-only watchers.
  resourceGroup: string;
  orkApps: string[];
  promJob: string;
}

const STAGING_TC = "https://staging.dauth.me";
const LOCAL_TC = "http://localhost:8080";

// Hosts that must never receive traffic from this tool.
const DENY: RegExp[] = [
  /^login\.dauth\.me$/i,
  /^ork\d+\.tideprotocol\.com$/i,
];

const ALLOW_STAGING: RegExp[] = [
  /^staging\.dauth\.me$/i,
  /^sork\d+\.tideprotocol\.com$/i,
];

// hostgateway is how the local ORKs advertise each other to the browser.
const ALLOW_LOCAL: RegExp[] = [/^localhost$/i, /^127\.0\.0\.1$/, /^host\.docker\.internal$/i, /^hostgateway$/i];

export function isDeniedHost(host: string): boolean {
  return DENY.some((r) => r.test(host));
}

export function isAllowedHost(target: TargetName, host: string): boolean {
  if (isDeniedHost(host)) return false;
  const list = target === "staging" ? ALLOW_STAGING : ALLOW_LOCAL;
  return list.some((r) => r.test(host));
}

// Throws unless the URL is allowed for this target.
export function assertAllowedUrl(target: TargetName, url: string): void {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    throw new Error(`refusing malformed URL: ${url}`);
  }
  if (isDeniedHost(host)) throw new Error(`REFUSED: ${host} is a production host. This tool never targets production.`);
  if (!isAllowedHost(target, host)) throw new Error(`REFUSED: ${host} is not on the ${target} allowlist.`);
}

export function resolveTarget(name: string, tcOverride?: string, orkApps?: string[]): Target {
  if (name !== "staging" && name !== "local") {
    throw new Error(`--target must be "staging" or "local" (got "${name}"). Production is not supported.`);
  }
  const tcBase = (tcOverride ?? (name === "staging" ? STAGING_TC : LOCAL_TC)).replace(/\/+$/, "");
  assertAllowedUrl(name, tcBase);
  return {
    name,
    tcBase,
    resourceGroup: "Tide-Staging",
    orkApps: orkApps && orkApps.length ? orkApps : ["sork1", "sork2", "sork3", "sork4", "sork5"],
    promJob: "sork-env/ork",
  };
}

// The redirect URI the harness OIDC client is registered with. The browser never
// reaches it; the simulator intercepts the navigation and reads the code.
export const CALLBACK_URL = "http://localhost:3000/callback";
export const OIDC_CLIENT_ID = "tide-loadtest-harness";
