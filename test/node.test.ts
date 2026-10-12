import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { createNodeReceiver, readNodeConfig, SqliteReceiverKv } from "../src/node";

const { walletEvent: envelopeExample, testEvent: testExample } = JSON.parse(readFileSync(new URL("./fixtures/events.json", import.meta.url), "utf8"));

const id = "sub_aaaaaaaaaaaaaaaaaaaa", secret = `whsec_${"x".repeat(43)}`;
const hook = "private-example-hook-0123456789";
const signed = (body: unknown, t = Math.floor(Date.now() / 1000)) => {
  const raw = JSON.stringify(body);
  return { raw, signature: `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${raw}`).digest("hex")}` };
};

test("Node SQLite adapter persists, pages and expires receiver records without leaking file permissions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "boros-node-receiver-"));
  const filename = join(directory, "receiver.sqlite");
  let now = 10_000;
  let kv = new SqliteReceiverKv(filename, () => now);
  try {
    await kv.put("sub:a", "", { metadata: { verifiedAt: now } });
    await kv.put("sub:b", "", { metadata: { verifiedAt: now + 1 } });
    await kv.put("pending:c", "", { expirationTtl: 1 });
    await kv.put("event:id", "1", { expirationTtl: 2 });
    assert.equal((await stat(filename)).mode & 0o777, 0o600);
    kv.close(); kv = new SqliteReceiverKv(filename, () => now);
    assert.equal(await kv.get("event:id"), "1");
    const first = await kv.list({ prefix: "sub:", limit: 1 });
    assert.deepEqual(first, { keys: [{ name: "sub:a", metadata: { verifiedAt: 10_000 } }], list_complete: false, cursor: "sub:a" });
    assert.deepEqual(await kv.list({ prefix: "sub:", limit: 1, cursor: first.cursor }), {
      keys: [{ name: "sub:b", metadata: { verifiedAt: 10_001 } }], list_complete: true,
    });
    now = 11_000;
    assert.equal(await kv.get("pending:c"), null);
    assert.deepEqual((await kv.list({ prefix: "pending:" })).keys, []);
    assert.equal(await kv.get("event:id"), "1");
    now = 12_000;
    assert.equal(await kv.get("event:id"), null);
    assert.equal(await kv.get("sub:a"), ""); // verified IDs do not expire
    await kv.put("event:new", "1"); // bounded cleanup must not delete unexpired rows
    assert.equal(await kv.get("event:new"), "1");
    await assert.rejects(kv.list({ prefix: "", limit: 0 }));
  } finally { kv.close(); await rm(directory, { recursive: true, force: true }); }
});

test("Node HTTP adapter preserves raw signatures, installs secrets, retains IDs and dedupes across restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "boros-node-http-"));
  const filename = join(directory, "receiver.sqlite"), configFile = join(directory, "config.json");
  const config = { HOOK_PATH: hook, SIGNING_SECRETS: "{}", ADMIN_TOKEN: "a".repeat(32), REFUSED_SUBSCRIPTION_IDS: "" };
  const save = () => writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
  await save();
  let kv = new SqliteReceiverKv(filename);
  const server = createNodeReceiver(async () => ({ ...await readNodeConfig(configFile), RECEIVER_KV: kv }));
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (body: unknown, { suffix = "", stale = false, tamper = false, eventId }: { suffix?: string; stale?: boolean; tamper?: boolean; eventId?: string } = {}) => {
    const { raw, signature } = signed(body, Math.floor(Date.now() / 1000) - (stale ? 301 : 0));
    return fetch(`${origin}/hook/${hook}${suffix}`, { method: "POST", body: raw + (tamper ? " " : ""), headers: {
      "content-type": "application/json", "x-boros-signature": signature, "x-boros-subscription-id": id,
      "x-boros-event-id": eventId ?? envelopeExample.id, "x-boros-attempt": "1",
    } });
  };
  try {
    const challenge = { type: "boros.webhook.verification", version: 1, subscription_id: id, challenge: "private-challenge-value" };
    const pending = await post(challenge);
    assert.equal(pending.status, 503); assert.doesNotMatch(await pending.text(), /private-challenge-value/);
    assert.equal(await kv.get(`sub:${id}`), null);
    config.SIGNING_SECRETS = JSON.stringify({ [id]: secret }); await save();
    assert.equal((await post(challenge, { tamper: true })).status, 401);
    const verified = await post(challenge);
    assert.equal(verified.status, 200); assert.equal(await verified.text(), challenge.challenge);
    assert.equal(await kv.get(`sub:${id}`), "");
    assert.equal((await post(envelopeExample, { stale: true })).status, 401);
    assert.equal((await post(envelopeExample, { tamper: true })).status, 401);
    assert.equal((await post(envelopeExample, { eventId: "wrong" })).status, 400);
    assert.equal((await post(envelopeExample)).status, 200);
    kv.close(); kv = new SqliteReceiverKv(filename);
    const duplicate = await post(envelopeExample);
    assert.equal(duplicate.status, 200); assert.equal((await duplicate.json()).duplicate, true);
    assert.equal((await post(testExample, { eventId: testExample.id })).status, 200);
    const admin = await fetch(`${origin}/hook/${hook}/admin?list=events`, { headers: { authorization: `Bearer ${config.ADMIN_TOKEN}` } });
    const events = await admin.json();
    assert.equal(events.items.length, 2);
    assert.equal(events.items.find((event: { event_id: string }) => event.event_id === envelopeExample.id).transactionHash, envelopeExample.event.transactionHash);
    assert.doesNotMatch(JSON.stringify(events), new RegExp(`${secret}|private-challenge-value|${hook}`));
    config.REFUSED_SUBSCRIPTION_IDS = id; await save();
    assert.equal((await post(envelopeExample)).status, 410);
    assert.equal((await post(challenge)).status, 410);
    assert.equal((await post(challenge, { suffix: "-wrong" })).status, 404);
    await writeFile(configFile, "broken-private-config");
    const broken = await post(envelopeExample);
    assert.equal(broken.status, 503); assert.equal(await broken.text(), "");
    await save();
    const bytes = await readFile(filename);
    assert.equal(bytes.includes(Buffer.from(secret)), false);
    assert.equal(bytes.includes(Buffer.from(challenge.challenge)), false);
  } finally {
    await new Promise<void>((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); });
    kv.close(); await rm(directory, { recursive: true, force: true });
  }
});
