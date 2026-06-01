//
// tide-load-harness Express server.
//
// Locust posts a randomly-chosen UserFixture to /run/sign; we drive one
// Tide Sign iteration via @tideorg/js and return the per-iteration
// status + latency. Locust collects HTTP-level metrics on top.
//
import "./shims.js";
import express, { type Request, type Response } from "express";
import { runSign } from "./runSign.js";
import { loadFixtures } from "./fixtures.js";

const port = Number(process.env.PORT ?? 3000);
const fixturesPath = process.env.FIXTURES_PATH ?? "./fixtures.json";

const fixtures = await loadFixtures(fixturesPath);

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true, fixturesLoaded: fixtures.length });
});

app.post("/run/sign", async (req: Request, res: Response) => {
  const fixture = req.body?.fixture;
  if (!fixture) {
    res.status(400).json({
      ok: false,
      code: "BAD_REQUEST",
      message: "missing fixture",
    });
    return;
  }
  const result = await runSign(fixture);
  res.status(result.ok ? 200 : 500).json(result);
});

app.listen(port, () => {
  console.log(
    `tide-load-harness listening on :${port}, ${fixtures.length} fixtures loaded`,
  );
});
