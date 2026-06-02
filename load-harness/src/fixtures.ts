//
// Fixture loader.
//
// fixtures.json is produced by the Playwright warm-up pass (see
// src/warmup/index.ts) and consumed by both the harness server (which
// holds them in memory for /run/sign) and the Locust task (which picks
// one per iteration on the Python side).
//
// On-disk shape (schemaVersion "1"):
//   {
//     schemaVersion: "1",
//     capturedAt:    "2026-06-02T02:55:00Z",
//     realm:         RealmFixture,
//     users:         UserFixture[]
//   }
//
// We return both halves from a single loadFixtures() call rather than
// splitting into two loaders — the file is one JSON blob and the realm
// + users are always consumed together by server.ts.
//
import { readFileSync } from "node:fs";
import type { RealmFixture, UserFixture } from "./runSign.js";

interface FixturesFile {
  schemaVersion: "1";
  capturedAt:    string;
  realm:         RealmFixture;
  users:         UserFixture[];
}

export interface LoadedFixtures {
  realm:      RealmFixture;
  users:      UserFixture[];
  capturedAt: string;
}

export async function loadFixtures(path: string): Promise<LoadedFixtures> {
  const raw = JSON.parse(readFileSync(path, "utf8")) as FixturesFile;
  if (raw.schemaVersion !== "1") {
    throw new Error(`unknown fixture schemaVersion: ${raw.schemaVersion}`);
  }
  if (!raw.realm || typeof raw.realm !== "object") {
    throw new Error("fixtures missing realm block");
  }
  if (!Array.isArray(raw.users) || raw.users.length === 0) {
    throw new Error("no users in fixtures");
  }
  return {
    realm:      raw.realm,
    users:      raw.users,
    capturedAt: raw.capturedAt,
  };
}
