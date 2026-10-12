// The print receiver against the sender's own signing vectors.
// Run: npm test
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { mock } from "node:test";
import printReceiver from "../print-receiver.js";

const vectors = JSON.parse(readFileSync(new URL("./fixtures/signature-vectors.json", import.meta.url), "utf8"));
const { delivery, signing } = vectors;
const ID = signing.subscriptionId as string;
const URL_BASE = "https://print.example.com";

type Env = { HOOK_PATH?: string; SIGNING_SECRETS?: string };
const post = (body: string, headers: Record<string, string> = {}, path = "/") =>
  new Request(URL_BASE + path, { method: "POST", headers, body });
const run = (request: Request, env: Env = {}) => printReceiver.fetch(request, env);

/** Capture what the receiver prints and pin its clock to the vector's timestamp. */
function harness(t: { after: (fn: () => void) => void }, nowSeconds = delivery.timestamp as number) {
  const lines: string[] = [];
  const log = mock.method(console, "log", (line: string) => { lines.push(line); });
  const now = mock.method(Date, "now", () => nowSeconds * 1000);
  t.after(() => { log.mock.restore(); now.mock.restore(); });
  return lines;
}

test("answers a challenge with the challenge as the whole body, before any secret is installed", async (t) => {
  const lines = harness(t);
  const response = await run(post(JSON.stringify({ type: "boros.webhook.verification", version: 1, subscription_id: ID, challenge: "c0ffee" })));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "c0ffee");
  assert.match(lines[0]!, /challenge for sub_abcdefghijklmnopqrst \(signature not checked\)/);
});

test("prints an event in full and acknowledges it", async (t) => {
  const lines = harness(t);
  const event = { id: "e1", type: "boros.wallet_event", version: 1, subscription_id: ID, event: { role: "taker-fill" } };
  const response = await run(post(JSON.stringify(event), { "x-boros-attempt": "2" }));
  assert.equal(response.status, 200);
  assert.match(lines[0]!, /^boros\.wallet_event for sub_abcdefghijklmnopqrst, attempt 2 \(signature not checked\)\n/);
  assert.deepEqual(JSON.parse(lines[0]!.slice(lines[0]!.indexOf("\n") + 1)), event);
});

test("with a secret installed, the sender's own vectors verify and anything else is refused unprinted", async (t) => {
  const lines = harness(t);
  const env = { SIGNING_SECRETS: JSON.stringify({ [ID]: signing.secret }) };
  const headers = (signature: string) => ({ "x-boros-subscription-id": ID, "x-boros-signature": signature });

  assert.equal((await run(post(delivery.rawBody, headers(delivery.header)), env)).status, 200);
  assert.match(lines[0]!, /\(signature ok\)/);
  // During a rotation the header carries two signatures; either installed secret passes.
  for (const secret of [signing.secret, signing.rotatedSecret, [signing.rotatedSecret, signing.secret]]) {
    assert.equal((await run(post(delivery.rawBody, headers(delivery.rotatedHeader)), { SIGNING_SECRETS: JSON.stringify({ [ID]: secret }) })).status, 200);
  }

  const printed = lines.length;
  for (const request of [
    post(delivery.rawBody + " ", headers(delivery.header)),
    post(delivery.rawBody, headers(delivery.header.replace(/v1=./, "v1=0"))),
    post(delivery.rawBody, { "x-boros-subscription-id": ID }),
  ]) {
    assert.equal((await run(request, env)).status, 401);
  }
  assert.equal((await run(post(delivery.rawBody, headers(delivery.header)), { SIGNING_SECRETS: JSON.stringify({ [ID]: signing.rotatedSecret }) })).status, 401);
  assert.deepEqual(lines.slice(printed), Array(4).fill(`REJECTED ${ID}: bad or stale signature`));
});

test("a signature older than five minutes is refused", async (t) => {
  harness(t, (delivery.timestamp as number) + 301);
  const response = await run(post(delivery.rawBody, { "x-boros-subscription-id": ID, "x-boros-signature": delivery.header }), { SIGNING_SECRETS: JSON.stringify({ [ID]: signing.secret }) });
  assert.equal(response.status, 401);
});

test("HOOK_PATH limits the receiver to one path, and only POST is accepted", async (t) => {
  harness(t);
  const challenge = JSON.stringify({ type: "boros.webhook.verification", subscription_id: ID, challenge: "x" });
  assert.equal((await run(post(challenge, {}, "/"), { HOOK_PATH: "secret-path" })).status, 404);
  assert.equal((await run(post(challenge, {}, "/secret-path/extra"), { HOOK_PATH: "secret-path" })).status, 404);
  assert.equal((await run(post(challenge, {}, "/secret-path"), { HOOK_PATH: "secret-path" })).status, 200);
  assert.equal((await run(new Request(URL_BASE + "/secret-path"), { HOOK_PATH: "secret-path" })).status, 405);
  assert.equal((await run(post("not json"))).status, 400);
});
