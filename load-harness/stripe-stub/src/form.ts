// Stripe-style form decoding: a[b][c]=1, items[0][price]=x, expand[]=y.

export type FormValue = string | FormValue[] | { [k: string]: FormValue };
export type FormObject = { [k: string]: FormValue };

function splitKey(key: string): string[] {
  const parts: string[] = [];
  const head = key.indexOf("[");
  if (head < 0) return [key];
  parts.push(key.slice(0, head));
  const re = /\[([^\]]*)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(key.slice(head)))) parts.push(m[1]);
  return parts;
}

// Turns objects whose keys are all 0..n-1 into arrays, recursively.
function arrayify(v: FormValue): FormValue {
  if (typeof v === "string" || Array.isArray(v)) return Array.isArray(v) ? v.map(arrayify) : v;
  const keys = Object.keys(v);
  for (const k of keys) v[k] = arrayify(v[k]);
  if (keys.length && keys.every((k, i) => k === String(i))) return keys.map((k) => v[k]);
  return v;
}

export function parseForm(body: string): FormObject {
  const out: FormObject = {};
  if (!body) return out;
  for (const [rawKey, value] of new URLSearchParams(body)) {
    const path = splitKey(rawKey);
    let cur: FormObject = out;
    for (let i = 0; i < path.length; i++) {
      const k = path[i];
      const last = i === path.length - 1;
      if (last) {
        if (k === "") {
          // a[]=x appends; the parent was created as an object keyed by index
          const n = String(Object.keys(cur).length);
          cur[n] = value;
        } else {
          cur[k] = value;
        }
      } else {
        if (k === "") {
          const n = String(Object.keys(cur).length);
          cur[n] = {};
          cur = cur[n] as FormObject;
        } else {
          if (typeof cur[k] !== "object" || cur[k] === null || Array.isArray(cur[k])) cur[k] = {};
          cur = cur[k] as FormObject;
        }
      }
    }
  }
  return arrayify(out) as FormObject;
}

export function str(v: FormValue | undefined): string | undefined {
  return typeof v === "string" ? v : undefined;
}

export function strList(v: FormValue | undefined): string[] {
  if (v === undefined) return [];
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  return Object.values(v).filter((x): x is string => typeof x === "string");
}

export function strMap(v: FormValue | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!v || typeof v === "string" || Array.isArray(v)) return out;
  for (const [k, x] of Object.entries(v)) if (typeof x === "string") out[k] = x;
  return out;
}
