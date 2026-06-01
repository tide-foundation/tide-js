"""
Locust task for the Tide load test v1.

Each VU does one Sign iteration per task by POSTing a randomly-chosen
fixture to the local tide-harness Express server. The harness drives
the real Tide protocol via @tideorg/js; Locust just measures HTTP
latency to localhost + the harness's reported per-iteration status.

Expected setup:
  - Harness server running on localhost:3000 (started by Azure Load
    Testing engine init script before Locust spawns).
  - fixtures.json present in the harness CWD.
"""
import json
import os
import random
from locust import HttpUser, task, between, events


HARNESS_URL = os.environ.get("HARNESS_URL", "http://localhost:3000")
FIXTURES_PATH = os.environ.get("FIXTURES_PATH", "./fixtures.json")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Load fixtures once at test start so every VU picks from the same pool."""
    with open(FIXTURES_PATH) as f:
        environment.fixtures = json.load(f)["users"]
    print(f"Loaded {len(environment.fixtures)} fixtures")


class TideSignUser(HttpUser):
    host = HARNESS_URL
    wait_time = between(0.1, 0.5)

    @task(1)
    def run_sign(self):
        fixture = random.choice(self.environment.fixtures)
        with self.client.post(
            "/run/sign",
            json={"fixture": fixture},
            catch_response=True,
            name="/run/sign",
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"http_{resp.status_code}")
                return
            body = resp.json()
            if not body.get("ok"):
                resp.failure(body.get("code", "harness-error"))
                return
            resp.success()
