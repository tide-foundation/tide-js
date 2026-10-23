// Small shared helpers for the simulator.

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

// "2/min", "0.5/s", "120/h", or a bare number (per minute). Returns ops per minute.
export function parseRate(s: string): number {
  const m = /^\s*([0-9]*\.?[0-9]+)\s*(?:\/\s*(s|sec|m|min|h|hr|hour))?\s*$/i.exec(s);
  if (!m) throw new Error(`bad rate "${s}" (use e.g. 2/min, 0.5/s, 120/h)`);
  const v = parseFloat(m[1]);
  const unit = (m[2] ?? "min").toLowerCase();
  if (unit.startsWith("s")) return v * 60;
  if (unit.startsWith("h")) return v / 60;
  return v;
}

// "5m", "90s", "1h", or bare seconds. Returns milliseconds.
export function parseDuration(s: string): number {
  const m = /^\s*([0-9]*\.?[0-9]+)\s*(ms|s|m|h)?\s*$/i.exec(s);
  if (!m) throw new Error(`bad duration "${s}" (use e.g. 5m, 90s)`);
  const v = parseFloat(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  const mult = unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : 3_600_000;
  return Math.round(v * mult);
}

export function fmtRate(perMin: number): string {
  if (perMin >= 60) return `${(perMin / 60).toFixed(2)}/s`;
  return `${perMin.toFixed(2)}/min`;
}

export function fmtDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h > 0 ? `${h}h${m}m` : m > 0 ? `${m}m${r ? r + "s" : ""}` : `${r}s`;
}

export function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const k = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[k];
}

export function utcStamp(d = new Date()): string {
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export function newRunId(prefix = "r"): string {
  const t = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*$/, "").replace("T", "t").toLowerCase();
  const rand = Math.random().toString(36).slice(2, 6);
  return `${prefix}${t}${rand}`;
}

export function truncate(s: string, max = 400): string {
  return s.length <= max ? s : s.slice(0, max) + `...[+${s.length - max}b]`;
}

// Strip anything that looks like a token or password before it hits disk or the console.
export function scrub(s: string, secrets: string[] = []): string {
  let out = s;
  for (const sec of secrets) {
    if (sec && sec.length >= 3) {
      out = out.split(sec).join("[REDACTED]").split(encodeURIComponent(sec)).join("[REDACTED]");
    }
  }
  out = out.replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[JWT]");
  out = out.replace(/(password|code|code_verifier|refresh_token|access_token|client_secret)=([^&\s"]+)/gi, "$1=[REDACTED]");
  return out;
}
