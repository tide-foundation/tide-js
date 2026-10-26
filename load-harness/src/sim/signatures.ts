// Known failure signatures from the 2026-10-22 incident, matched against error text.
// "expected" ones (like the seat cap) are reported but do not count as staging breaking.

export interface Signature {
  id: string;
  re: RegExp;
  expected?: boolean;
  note: string;
}

export const SIGNATURES: Signature[] = [
  { id: "SEAT_CAP", re: /exceeded its total user count/i, expected: true, note: "realm seat limit reached (expected, pool sizing)" },
  { id: "NOT_TIDE_SIGNED", re: /NOT_TIDE_SIGNED|should be Tide-signed/i, note: "token minted locally (RS256) on a realm that must be Tide-signed" },
  { id: "SQLITE_LOCKED", re: /database is locked|SQLITE_BUSY|SqliteException/i, note: "ORK SQLite lock on Create/Commit" },
  { id: "VENDOR_ALREADY_CREATED", re: /VENDOR_ALREADY_CREATED/i, note: "payer refused vendor after partial VVK setup" },
  { id: "UID_NOT_FOUND", re: /could not find uid/i, note: "master SubmitUser lag" },
  { id: "UID_DUPLICATE", re: /IX_UIDs_Id/, note: "master SubmitUser concurrent UID insert (master-libs PR #30)" },
  { id: "PG_UNIQUE_VIOLATION", re: /\b23505:|duplicate key value violates unique constraint/i, note: "Postgres unique constraint violation" },
  { id: "STATEMENT_TIMEOUT", re: /statement timeout|canceling statement due to statement timeout/i, note: "Postgres statement_timeout" },
  { id: "VENDOR_KEYGEN_FAILED", re: /VENDOR_KEYGEN_FAILED/i, note: "VVK setup failed after wallet commit" },
  { id: "VENDOR_SETUP_FAILED", re: /VENDOR_REALM_SETUP_FAILED|VENDOR_STRIPE_CHECKOUT_FAILED/i, note: "setUpTideRealm failed" },
  { id: "RESERVATION_CONFLICT", re: /GetReservers|already reserved|ReserveUserId.*409/i, note: "stale user-id reservation" },
  { id: "NOT_ENOUGH_ORKS", re: /Could not reach enough|NET_THRESHOLD_FAILURE|not enough ORKs/i, note: "ORK fan-out below threshold" },
  { id: "UID_THROTTLED", re: /throttl|too many requests|\b429\b/i, note: "per-user throttle (spread users wider)" },
  { id: "LICENCE_ACTIVE_CAP", re: /exceeded its total concurrent active users/i, expected: true, note: "realm licence active-user cap reached (expected, raise MaxConcurrentAccountsPerMonth)" },
  { id: "HEADER_TOO_LARGE", re: /Request Header Fields Too Large|\b(?:HTTP|status)[ :]+431\b| 431 Request/i, note: "request headers over the server limit (oversized token)" },
  { id: "GATEWAY", re: /HTTP 50[234]\b|Bad Gateway|Service Unavailable|Gateway Timeout/i, note: "ingress or upstream unavailable" },
];

export function matchSignatures(text: string): Signature[] {
  if (!text) return [];
  return SIGNATURES.filter((s) => s.re.test(text));
}

// Signatures that count toward "break" (server-side failure, not client or pool sizing).
export function isBreakSignature(id: string): boolean {
  const s = SIGNATURES.find((x) => x.id === id);
  return !!s && !s.expected && id !== "UID_THROTTLED";
}

export function isExpectedSignature(id: string): boolean {
  return !!SIGNATURES.find((x) => x.id === id && x.expected);
}
