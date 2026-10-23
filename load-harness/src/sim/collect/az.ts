// Thin read-only Azure CLI wrapper. Every call is a GET-style command; output is parsed as JSON and
// anything that looks like a secret is redacted before it is kept or printed.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/(Password|Pwd)\s*=\s*[^;"'\s]+/gi, "$1=[REDACTED]"],
  [/\b(sk|rk)_(live|test)_[A-Za-z0-9]+/g, "$1_$2_[REDACTED]"],
  [/\bwhsec_[A-Za-z0-9]+/g, "whsec_[REDACTED]"],
  [/(AccountKey|SharedAccessKey|AccessKey)\s*=\s*[^;"'\s]+/gi, "$1=[REDACTED]"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[JWT]"],
  [/("?(access_?token|refresh_?token|client_?secret|password)"?\s*[:=]\s*")[^"]+/gi, "$1[REDACTED]"],
];

export function redact(s: string): string {
  let out = s;
  for (const [re, rep] of SECRET_PATTERNS) out = out.replace(re, rep);
  return out;
}

// Redact every string inside a parsed JSON value.
export function redactDeep<T>(v: T): T {
  if (typeof v === "string") return redact(v) as unknown as T;
  if (Array.isArray(v)) return v.map(redactDeep) as unknown as T;
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = redactDeep(x);
    return out as T;
  }
  return v;
}

export async function az<T = unknown>(args: string[], timeoutMs = 120_000): Promise<T> {
  try {
    const { stdout } = await run("az", [...args, "-o", "json"], { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
    return redactDeep(JSON.parse(stdout || "null")) as T;
  } catch (e) {
    const err = e as { stderr?: string; message?: string };
    throw new Error(redact((err.stderr || err.message || String(e)).split("\n").filter(Boolean).slice(0, 2).join(" ")).slice(0, 300));
  }
}

export async function azLoggedIn(): Promise<boolean> {
  try {
    await az(["account", "show", "--query", "id"], 30_000);
    return true;
  } catch {
    return false;
  }
}

export async function azToken(resource: string): Promise<string> {
  const { stdout } = await run("az", ["account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv"], { timeout: 60_000 });
  return stdout.trim();
}
