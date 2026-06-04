//
// Per-VU cookie jar wrapper.
//
// The cmkOnly flow only functionally requires ONE cookie
// (`KC_AUTH_SESSION_HASH`, set by TideCloak on the /broker/tide/login
// hop, Path=/realms/<realm>/, Max-Age=60s). R2 preflight confirmed the
// other three HttpOnly cookies (AUTH_SESSION_ID*, KEYCLOAK_*) are NOT
// required — curl's default jar dropped them and TideCloak still
// accepted the terminal Fetch 2. But we use a full RFC 6265 jar anyway
// because:
//
//   1. tough-cookie is well-tested vs. a hand-rolled regex parser.
//   2. We want path/domain/Max-Age handling to be correct in case
//      TideCloak introduces a new cookie in a later version — the jar
//      should adapt without code changes.
//   3. Per-VU isolation requires per-jar storage; tough-cookie's
//      `CookieJar` is exactly that.
//
// We picked `tough-cookie` over undici's `Cookie` interceptor because
// the interceptor is per-Dispatcher (one for the whole pool), while we
// want per-VU isolation. tough-cookie's API is also closer to "browser
// cookie jar" semantics, which is what the SWE assumes.
//
// SECURITY: cookies are per-VU and live in memory only. No persistence.
// `KC_AUTH_SESSION_HASH` is session-bound and short-lived (60s); the
// other cookies are HttpOnly equivalents we forward unmodified. Never
// log raw cookie values.
//
import { CookieJar } from "tough-cookie";

/** Lightweight wrapper so the rest of the protocol code can ignore
 *  tough-cookie's async API surface and just pass an object around. */
export interface PerVUJar {
  /** Underlying tough-cookie jar instance. One per VU. */
  jar: CookieJar;
  /**
   * Serialize all cookies that match the request URL into a single
   * `Cookie:` header value. Returns "" if none apply.
   */
  cookieHeader(url: string): Promise<string>;
  /**
   * Ingest one or more `Set-Cookie` header lines from a response.
   * Passing `undici`'s `headers.getSetCookie()` output is the expected
   * call site; we accept `string[]` so the call site stays explicit.
   */
  ingestSetCookie(url: string, setCookies: string[]): Promise<void>;
  /**
   * Look up a single cookie by name for a given URL. Returns the value
   * (not the full Cookie object) or undefined. Used by tests + the
   * Fetch 1 assertion that KC_AUTH_SESSION_HASH was captured.
   */
  getValue(url: string, name: string): Promise<string | undefined>;
}

export function createCookieJar(): PerVUJar {
  // looseMode=true: tolerate cookies like `=value` (no name) — some
  // Keycloak builds historically emit these for legacy reasons; we
  // never read them but we don't want the jar to throw on a recv.
  const jar = new CookieJar(undefined, { looseMode: true, allowSpecialUseDomain: true });

  return {
    jar,
    async cookieHeader(url: string): Promise<string> {
      // getCookieString returns ""; no header → we just don't attach it.
      return jar.getCookieString(url);
    },
    async ingestSetCookie(url: string, setCookies: string[]): Promise<void> {
      for (const raw of setCookies) {
        try {
          await jar.setCookie(raw, url);
        } catch {
          // Defensive: a malformed Set-Cookie should NOT abort the flow.
          // The required cookie (KC_AUTH_SESSION_HASH) is well-formed in
          // every observed response, so dropping a junk line is safe.
          // We swallow to avoid leaking the cookie value via err message.
        }
      }
    },
    async getValue(url: string, name: string): Promise<string | undefined> {
      const cookies = await jar.getCookies(url);
      const hit = cookies.find((c) => c.key === name);
      return hit?.value;
    },
  };
}
