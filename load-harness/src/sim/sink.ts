// Run directory writers: JSONL event and step logs, the cleanup manifest, and the users secret file.

import { mkdirSync, openSync, writeSync, closeSync, writeFileSync, renameSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";

export class Jsonl {
  private fd: number;
  count = 0;
  constructor(readonly path: string) {
    this.fd = openSync(path, "a");
  }
  write(row: unknown): void {
    writeSync(this.fd, JSON.stringify(row) + "\n");
    this.count++;
  }
  close(): void {
    try { closeSync(this.fd); } catch { /* already closed */ }
  }
}

export function runDir(base: string, runId: string): string {
  const dir = resolve(base, runId);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function atomicWriteJson(path: string, data: unknown, mode?: number): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2), mode ? { mode } : undefined);
  renameSync(tmp, path);
  if (mode) chmodSync(path, mode);
}

export function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export interface RealmEntry {
  realm: string;
  email: string;
  status: "created" | "setup-ok" | "setup-failed" | "ready" | "not-ready";
  purpose: "pool" | "s3-setup";
  createdAt: string;
  licence?: string;
  customerId?: string;
  subscriptionId?: string;
  error?: string;
}

export interface UserEntry {
  userId: string;
  realm: string;
  email: string;
  status: "attempted" | "created" | "failed" | "seat-cap";
  at: string;
}

export interface Manifest {
  runId: string;
  createdAt: string;
  target: string;
  tcBase: string;
  command: string;
  args: Record<string, unknown>;
  emailPattern: string;
  realms: RealmEntry[];
  users: UserEntry[];
  notes: string[];
}

// Keeps manifest.json current on disk. Every change rewrites the file so a crash still leaves a usable list.
export class ManifestWriter {
  readonly path: string;
  readonly data: Manifest;
  constructor(dir: string, init: Omit<Manifest, "realms" | "users" | "notes">) {
    this.path = join(dir, "manifest.json");
    if (existsSync(this.path)) {
      const prev = readJson<Manifest>(this.path);
      this.data = { ...prev, ...init, realms: prev.realms ?? [], users: prev.users ?? [], notes: prev.notes ?? [] };
    } else {
      this.data = { ...init, realms: [], users: [], notes: [] };
    }
    this.flush();
  }
  upsertRealm(e: RealmEntry): void {
    const i = this.data.realms.findIndex((r) => r.realm === e.realm);
    if (i >= 0) this.data.realms[i] = { ...this.data.realms[i], ...e };
    else this.data.realms.push(e);
    this.flush();
  }
  upsertUser(e: UserEntry): void {
    const i = this.data.users.findIndex((u) => u.userId === e.userId && u.realm === e.realm);
    if (i >= 0) this.data.users[i] = { ...this.data.users[i], ...e };
    else this.data.users.push(e);
    this.flush();
  }
  note(s: string): void {
    this.data.notes.push(s);
    this.flush();
  }
  flush(): void {
    atomicWriteJson(this.path, this.data);
  }
}

export interface SecretUser {
  userId: string;
  realm: string;
  password: string;
}

// Passwords for users the simulator created. Mode 0600, gitignored, never printed.
export class UsersSecret {
  readonly path: string;
  users: SecretUser[] = [];
  constructor(dir: string) {
    this.path = join(dir, "users.secret.json");
    if (existsSync(this.path)) this.users = readJson<{ users: SecretUser[] }>(this.path).users ?? [];
  }
  add(u: SecretUser): void {
    this.users.push(u);
    atomicWriteJson(this.path, { users: this.users }, 0o600);
  }
}
