// HTTP front: stub endpoints, passthrough to the real Stripe API, request log and stats.

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { Readable } from "node:stream";
import { createWriteStream, type WriteStream } from "node:fs";
import { Store, type Obj } from "./store.js";
import { StubHandler, decide, type StubRequest, type PriceFetcher } from "./handler.js";

export interface ServerConfig {
  port: number;
  upstream: string;        // must be https://api.stripe.com
  emailSuffix: string;
  stateFile?: string;
  logFile?: string;        // JSONL; stdout when unset
}

export const ALLOWED_UPSTREAM = "https://api.stripe.com";

// Headers that describe the hop, not the request; never forwarded either way.
const HOP = new Set(["host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "content-length", "accept-encoding", "te", "trailer"]);
const HOP_RESPONSE = new Set(["connection", "keep-alive", "transfer-encoding", "content-encoding", "content-length"]);

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function lowerHeaders(req: IncomingMessage): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(req.headers)) out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
  return out;
}

function forwardHeaders(h: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) if (v !== undefined && !HOP.has(k) && !k.startsWith("x-forwarded-")) out[k] = v;
  out["accept-encoding"] = "identity";
  return out;
}

export interface Stats {
  startedAt: string;
  decisions: Record<string, number>;
  byRoute: Record<string, number>;
  upstreamErrors: number;
}

export function startServer(cfg: ServerConfig): { server: Server; store: Store; stats: Stats; close: () => Promise<void> } {
  if (cfg.upstream.replace(/\/+$/, "") !== ALLOWED_UPSTREAM) {
    throw new Error(`STRIPE_UPSTREAM must be ${ALLOWED_UPSTREAM}`);
  }
  const upstream = ALLOWED_UPSTREAM;
  const store = new Store(cfg.stateFile);
  const stats: Stats = { startedAt: new Date().toISOString(), decisions: {}, byRoute: {}, upstreamErrors: 0 };
  const log: WriteStream | null = cfg.logFile ? createWriteStream(cfg.logFile, { flags: "a" }) : null;
  const writeLog = (row: Obj) => {
    const line = JSON.stringify(row) + "\n";
    if (log) log.write(line); else process.stdout.write(line);
  };

  const fetchPrice: PriceFetcher = async (priceId, headers) => {
    const h = forwardHeaders({ authorization: headers["authorization"], "stripe-version": headers["stripe-version"] });
    const r = await fetch(`${upstream}/v1/prices/${encodeURIComponent(priceId)}?expand[]=tiers`, { headers: h });
    return { status: r.status, body: (await r.json()) as Obj };
  };
  const handler = new StubHandler(store, { emailSuffix: cfg.emailSuffix }, fetchPrice);

  const send = (res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) => {
    const data = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(data), ...extra });
    res.end(data);
  };

  const server = createServer(async (req, res) => {
    const t0 = Date.now();
    const url = new URL(req.url ?? "/", "http://stub.local");
    const method = (req.method ?? "GET").toUpperCase();

    if (url.pathname === "/__stub/health") return send(res, 200, { ok: true });
    if (url.pathname === "/__stub/stats") return send(res, 200, { ...stats, objects: store.counts() });

    let decision = "error";
    let status = 500;
    let ids: string[] | undefined;
    let reason: string | undefined;
    try {
      const body = await readBody(req);
      const headers = lowerHeaders(req);
      const sreq: StubRequest = { method, path: url.pathname, query: url.search.replace(/^\?/, ""), body, headers };
      const d = decide(sreq, store, { emailSuffix: cfg.emailSuffix });
      decision = d.kind === "stub" ? "stubbed" : d.kind === "passthrough" ? "passthrough" : "refused";
      reason = d.kind === "passthrough" ? undefined : d.reason;

      if (d.kind === "refuse") {
        status = d.status;
        return send(res, d.status, d.body);
      }
      if (d.kind === "stub") {
        const out = await handler.handle(sreq);
        status = out.status;
        ids = out.ids;
        return send(res, out.status, out.body, { "request-id": `req_lt_${Date.now().toString(36)}`, "stripe-version": headers["stripe-version"] ?? "" });
      }

      // Passthrough: same method, path, query, body and headers, to api.stripe.com only.
      const target = `${upstream}${url.pathname}${url.search}`;
      let up: Response;
      try {
        up = await fetch(target, {
          method,
          headers: forwardHeaders(headers),
          body: method === "GET" || method === "HEAD" ? undefined : body,
          redirect: "manual",
        });
      } catch (e) {
        stats.upstreamErrors++;
        status = 502;
        return send(res, 502, { error: { type: "api_error", message: `stub could not reach Stripe: ${(e as Error).message}` } });
      }
      status = up.status;
      const outHeaders: Record<string, string> = {};
      up.headers.forEach((v, k) => { if (!HOP_RESPONSE.has(k.toLowerCase())) outHeaders[k] = v; });
      res.writeHead(up.status, outHeaders);
      if (up.body) Readable.fromWeb(up.body as import("node:stream/web").ReadableStream).pipe(res);
      else res.end();
    } catch (e) {
      status = 500;
      if (!res.headersSent) send(res, 500, { error: { type: "api_error", message: `stub error: ${(e as Error).message}` } });
      else res.end();
    } finally {
      stats.decisions[decision] = (stats.decisions[decision] ?? 0) + 1;
      const route = `${method} ${url.pathname.replace(/\/(cus|sub|si|in|price|prod|pi|seti|pm|cs)_[A-Za-z0-9_]+/g, "/{id}")}`;
      stats.byRoute[`${decision} ${route}`] = (stats.byRoute[`${decision} ${route}`] ?? 0) + 1;
      // Path and ids only: never headers, keys or bodies.
      writeLog({ ts: new Date().toISOString(), method, path: url.pathname, decision, ...(reason ? { reason } : {}), status, ms: Date.now() - t0, ...(ids ? { ids } : {}) });
    }
  });

  server.listen(cfg.port);
  return {
    server, store, stats,
    close: () => new Promise((r) => { store.flush(); log?.end(); server.close(() => r()); }),
  };
}
