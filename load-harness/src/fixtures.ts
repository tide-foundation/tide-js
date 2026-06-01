//
// Fixture loader.
//
// fixtures.json is produced by the Playwright warm-up pass (see
// src/warmup/index.ts) and consumed by both the harness server (which
// holds them in memory for /run/sign) and the Locust task (which picks
// one per iteration on the Python side).
//
import { readFileSync } from "node:fs";
import type { UserFixture } from "./runSign.js";

interface FixturesFile {
  schemaVersion: "1";
  realm: string;
  createdAt: string;
  users: UserFixture[];
}

export async function loadFixtures(path: string): Promise<UserFixture[]> {
  const raw = JSON.parse(readFileSync(path, "utf8")) as FixturesFile;
  if (raw.schemaVersion !== "1") {
    throw new Error(`unknown fixture schemaVersion: ${raw.schemaVersion}`);
  }
  if (!Array.isArray(raw.users) || raw.users.length === 0) {
    throw new Error("no users in fixtures");
  }
  return raw.users;
}
