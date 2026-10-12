// Run: npm test
// Signatures here are computed independently with node:crypto and checked
// against the alerts Worker's own fixed vectors.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { handleRequest, type ReceiverEnv, type ReceiverKv } from "../src/receiver";
import { parseSignatureHeader, verifySignature } from "../src/verify";

const vectors = JSON.parse(readFileSync(new URL("./fixtures/signature-vectors.json", import.meta.url), "utf8"));
const envelope = JSON.parse(readFileSync(new URL("./fixtures/events.json", import.meta.url), "utf8")).senderEnvelope;
const encoder = new TextEncoder();

const HOOK = "abcdefghijklmnopqrstuvwxyz_0123";
const ID = vectors.signing.subscriptionId as string; // sub_abcdefghijklmnopqrst
const SECRET = vectors.signing.secret as string;
const OTHER = "sub_bbbbbbbbbbbbbbbbbbbb";
const NOW = 1_790_812_800_000;

/** In-memory KV with the platform behaviours that matter here: metadata limit, cursors, op counting. */
class MemoryKv implements ReceiverKv {
  readonly values = new Map<string, { value: string; metadata?: unknown; ttl?: number }>();
  readonly puts: string[] = [];
  ops = 0;
  failPut: (key: string) => boolean = () => false;
  emptyFirstPage = false;
  async get(key: string) { this.ops++; return this.values.get(key)?.value ?? null; }
  async put(key: string, value: string, options?: { expirationTtl?: number; metadata?: unknown }) {
    this.ops++;
    if (this.failPut(key)) throw new Error("kv unavailable");
    if (options?.metadata !== undefined && JSON.stringify(options.metadata).length > 1024) throw new Error("metadata exceeds 1024 bytes");
    this.puts.push(key); this.values.set(key, { value, metadata: options?.metadata, ttl: options?.expirationTtl });
  }
  async list({ prefix, limit = 1000, cursor }: { prefix: string; limit?: number; cursor?: string }) {
    this.ops++;
    if (this.emptyFirstPage && cursor === undefined) return { keys: [], list_complete: false, cursor: "0" };
    const names = [...this.values.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0, end = start + limit;
    return { keys: names.slice(start, end).map((name) => ({ name, metadata: this.values.get(name)!.metadata })),
      list_complete: end >= names.length, ...(end < names.length ? { cursor: String(end) } : {}) };
  }
}
type TestEnv = ReceiverEnv & { RECEIVER_KV: MemoryKv };
function env(overrides: Partial<ReceiverEnv> = {}): TestEnv {
  return { HOOK_PATH: HOOK, SIGNING_SECRETS: JSON.stringify({ [ID]: SECRET }), RECEIVER_KV: new MemoryKv(), ...overrides } as TestEnv;
}
const sign = (secret: string, t: number, raw: string) => createHmac("sha256", secret).update(`${t}.${raw}`).digest("hex");
function post(raw: string, headers: Record<string, string> = {}, path = `/hook/${HOOK}`) {
  return new Request(`https://receiver.example.com${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: raw });
}
function signedEvent(body: Record<string, unknown>, id = ID, secret = SECRET, t = NOW / 1000) {
  const raw = JSON.stringify(body);
  return post(raw, { "x-boros-subscription-id": id, "x-boros-event-id": String(body.id), "x-boros-attempt": "1", "x-boros-signature": `t=${t},v1=${sign(secret, t, raw)}` });
}
const delivery = (id = ID, eventId = envelope.id as string, secret = SECRET, t = NOW / 1000) =>
  signedEvent({ ...envelope, id: eventId, subscription_id: id, event: { ...envelope.event, alertId: eventId } }, id, secret, t);
function challenge(id = ID, value = "chal_9f2c4e", secret: string | null = SECRET) {
  const raw = JSON.stringify({ type: "boros.webhook.verification", version: 1, subscription_id: id, challenge: value });
  return post(raw, { "x-boros-subscription-id": id, ...(secret ? { "x-boros-signature": `t=${NOW / 1000},v1=${sign(secret, NOW / 1000, raw)}` } : {}) });
}
const admin = (token: string, query = "") => new Request(`https://r.example.com/hook/${HOOK}/admin${query}`, { headers: { authorization: `Bearer ${token}` } });

test("verifies the alerts Worker's own signature vectors, including the rotation header", async () => {
  const { delivery: d, signing } = vectors;
  const raw = encoder.encode(d.rawBody);
  assert.equal(sign(signing.secret, d.timestamp, d.rawBody), d.signature);
  assert.equal(await verifySignature({ header: d.header, rawBody: raw, secrets: [signing.secret], nowSeconds: d.timestamp }), true);
  for (const secret of [signing.secret, signing.rotatedSecret]) {
    assert.equal(await verifySignature({ header: d.rotatedHeader, rawBody: raw, secrets: [secret], nowSeconds: d.timestamp }), true);
  }
  assert.equal(await verifySignature({ header: d.header, rawBody: raw, secrets: [signing.rotatedSecret], nowSeconds: d.timestamp }), false);
  assert.equal(await verifySignature({ header: d.header, rawBody: encoder.encode(d.rawBody + " "), secrets: [signing.secret], nowSeconds: d.timestamp }), false);
  assert.equal(await verifySignature({ header: d.header, rawBody: raw, secrets: [signing.secret], nowSeconds: d.timestamp + 300 }), true);
  assert.equal(await verifySignature({ header: d.header, rawBody: raw, secrets: [signing.secret], nowSeconds: d.timestamp + 301 }), false);
  assert.equal(await verifySignature({ header: d.header, rawBody: raw, secrets: [signing.secret], nowSeconds: d.timestamp - 301 }), false);
  const sig = "a".repeat(64);
  for (const bad of [null, "", "t=1", `v1=${sig}`, `t=1,v1=${sig.slice(1)}`, `t=1,t=2,v1=${sig}`, `t=01,v1=${sig}`, `t=1,v1=${sig},v1=${sig},v1=${sig}`, `t=1,v1=${sig},x=1`]) {
    assert.equal(parseSignatureHeader(bad), null, String(bad));
  }
});

test("F1: a first registration is never activated before its secret is installed", async () => {
  const e = env({ SIGNING_SECRETS: "{}" });
  // Registration-time challenge: the secret is not installed, so no echo.
  const first = await handleRequest(challenge(ID, "chal_first"), e, NOW);
  assert.equal(first.status, 503); assert.equal(first.headers.get("retry-after"), "60");
  assert.doesNotMatch(await first.text(), /chal_first/);
  assert.deepEqual(e.RECEIVER_KV.puts, [`pending:${ID}`]);
  assert.equal(e.RECEIVER_KV.values.get(`pending:${ID}`)!.ttl, 2 * 24 * 60 * 60);
  assert.equal(await e.RECEIVER_KV.get(`sub:${ID}`), null);
  // The owner installs the secret and calls /verify: the new challenge is signed and verifiable.
  e.SIGNING_SECRETS = JSON.stringify({ [ID]: SECRET });
  const verified = await handleRequest(challenge(ID, "chal_second"), e, NOW + 60_000);
  assert.equal(verified.status, 200); assert.equal(await verified.text(), "chal_second");
  assert.deepEqual(e.RECEIVER_KV.values.get(`sub:${ID}`)!.metadata, { verifiedAt: NOW + 60_000 });
});

test("F1: a stranger who knows the path cannot activate a subscription", async () => {
  const e = env();
  // Unknown ID with no installed secret: refused retryably, never echoed.
  const unknown = await handleRequest(challenge(OTHER, "chal_stranger", null), e, NOW);
  assert.equal(unknown.status, 503); assert.doesNotMatch(await unknown.text(), /chal_stranger/);
  // Known ID but unsigned or wrongly signed: rejected.
  assert.equal((await handleRequest(challenge(ID, "c", null), e, NOW)).status, 401);
  assert.equal((await handleRequest(challenge(ID, "c", "whsec_wrong"), e, NOW)).status, 401);
  assert.equal(await e.RECEIVER_KV.get(`sub:${OTHER}`), null);
});

test("challenge: not answered when the ID cannot be recorded or is refused", async () => {
  const failing = env(); failing.RECEIVER_KV.failPut = () => true;
  const unrecorded = await handleRequest(challenge(), failing, NOW);
  assert.equal(unrecorded.status, 503); assert.doesNotMatch(await unrecorded.text(), /chal_/);
  const refused = await handleRequest(challenge(), env({ REFUSED_SUBSCRIPTION_IDS: ` ${OTHER}, ${ID} ` }), NOW);
  assert.equal(refused.status, 410); assert.doesNotMatch(await refused.text(), /chal_/);
});

test("delivery: verified events are accepted once and deduplicated on retries", async () => {
  const e = env();
  const first = await handleRequest(delivery(), e, NOW);
  assert.equal(first.status, 200); assert.deepEqual(await first.json(), { ok: true });
  const retry = await handleRequest(delivery(), e, NOW + 10_000);
  assert.equal(retry.status, 200); assert.deepEqual(await retry.json(), { ok: true, duplicate: true });
  assert.equal(e.RECEIVER_KV.puts.filter((k) => k.startsWith("event:")).length, 1);
  const logged = [...e.RECEIVER_KV.values].filter(([k]) => k.startsWith("log:"));
  assert.equal(logged.length, 1);
  assert.deepEqual(logged[0]![1].metadata, {
    subscription_id: ID, event_id: envelope.id, type: "boros.wallet_event", receivedAt: NOW, attempt: 1, role: "taker-fill",
    walletRoot: envelope.event.walletRoot, marketId: 197, blockNumber: envelope.event.blockNumber, logIndex: 17, transactionHash: null,
  }, "fixture tx hash 0xtx is not a real hash, so it is dropped rather than stored unbounded");
});

test("F2: the completion marker is written last, so a failed write is retried, not skipped", async () => {
  for (const failing of ["log:", "event:"]) {
    const e = env(); let fail = true;
    e.RECEIVER_KV.failPut = (key) => fail && key.startsWith(failing);
    // A rejection (storage error escaping) must also fail here, at an assertion.
    const first = await handleRequest(delivery(), e, NOW).catch(() => new Response(null, { status: 599 }));
    assert.equal(first.status, 503, failing);
    assert.equal(await e.RECEIVER_KV.get(`event:${ID}:${envelope.id}`), null, `${failing}: no marker after a failure`);
    fail = false;
    const retry = await handleRequest(delivery(), e, NOW + 10_000);
    assert.equal(retry.status, 200); assert.deepEqual(await retry.json(), { ok: true }, `${failing}: retry is processed, not a duplicate`);
    assert.ok(await e.RECEIVER_KV.get(`event:${ID}:${envelope.id}`));
    assert.ok([...e.RECEIVER_KV.values.keys()].some((k) => k.startsWith("log:")));
  }
});

test("delivery: boros.webhook.test sends are verified and recorded", async () => {
  const e = env();
  const id = "test_8c1f6c86-8a1c-4c55-9b54-1d3c2f4b9e10";
  assert.equal((await handleRequest(signedEvent({ id, type: "boros.webhook.test", version: 1, subscription_id: ID }), e, NOW)).status, 200);
});

test("delivery: signed but unsupported envelopes are rejected, and stored fields stay bounded", async () => {
  const e = env();
  const base = { ...envelope, subscription_id: ID };
  for (const body of [
    { ...base, version: 999 },
    { ...base, event: null },
    { ...base, event: { ...envelope.event, alertId: "different" } },
    { id: "test_x", type: "boros.webhook.test", version: 1, subscription_id: ID, event: {} },
  ]) assert.equal((await handleRequest(signedEvent(body), e, NOW)).status, 400, JSON.stringify(body).slice(0, 60));
  const huge = "x".repeat(5_000);
  const bounded = await handleRequest(signedEvent({ ...base, event: { ...envelope.event, role: huge, walletRoot: huge, transactionHash: huge, marketId: huge } }), e, NOW);
  assert.equal(bounded.status, 200);
  const [, stored] = [...e.RECEIVER_KV.values].find(([k]) => k.startsWith("log:"))!;
  assert.ok(JSON.stringify(stored.metadata).length <= 1024);
  assert.equal((stored.metadata as { role: unknown }).role, null);
});

test("delivery: refusal is per ID and needs no secret; the other subscription is unaffected", async () => {
  const e = env({ REFUSED_SUBSCRIPTION_IDS: OTHER });
  assert.equal((await handleRequest(delivery(OTHER, "orphan-event", "whsec_lost"), e, NOW)).status, 410);
  assert.equal((await handleRequest(delivery(ID), e, NOW)).status, 200);
});

test("delivery: rejected without a known secret, with a bad or stale signature, or mismatched identity", async () => {
  assert.equal((await handleRequest(delivery(), env({ SIGNING_SECRETS: "{}" }), NOW)).status, 401);
  assert.equal((await handleRequest(delivery(ID, envelope.id, "whsec_wrong"), env(), NOW)).status, 401);
  assert.equal((await handleRequest(delivery(ID, envelope.id, SECRET, NOW / 1000 - 600), env(), NOW)).status, 401);
  const raw = JSON.stringify({ ...envelope, subscription_id: ID });
  const signature = `t=${NOW / 1000},v1=${sign(SECRET, NOW / 1000, raw)}`;
  assert.equal((await handleRequest(post(raw, { "x-boros-subscription-id": OTHER, "x-boros-event-id": envelope.id, "x-boros-signature": signature }), env(), NOW)).status, 400);
  assert.equal((await handleRequest(post(raw, { "x-boros-subscription-id": ID, "x-boros-event-id": "different", "x-boros-signature": signature }), env(), NOW)).status, 400);
});

test("delivery: forced failures are not recorded, so the retry is processed afterwards", async () => {
  const e = env({ FORCE_DELIVERY_STATUS: "500" });
  assert.equal((await handleRequest(delivery(), e, NOW)).status, 500);
  assert.equal(e.RECEIVER_KV.puts.length, 0);
  e.FORCE_DELIVERY_STATUS = "";
  assert.equal((await handleRequest(delivery(), e, NOW + 10_000)).status, 200);
  for (const ignored of ["404", "410", "200", "abc"]) {
    assert.equal((await handleRequest(delivery(), env({ FORCE_DELIVERY_STATUS: ignored }), NOW)).status, 200, ignored);
  }
});

test("only the secret path answers; other paths and methods reveal nothing", async () => {
  assert.equal((await handleRequest(challenge(), env({ HOOK_PATH: undefined }), NOW)).status, 404);
  assert.equal((await handleRequest(challenge(), env({ HOOK_PATH: "short" }), NOW)).status, 404);
  for (const path of ["/", "/hook", "/hook/wrong-path-wrong-path-wrong", `/hook/${HOOK}/`, `/hook/${HOOK}x`]) {
    const response = await handleRequest(post(JSON.stringify({ type: "boros.webhook.verification", version: 1, subscription_id: ID, challenge: "c" }), {}, path), env(), NOW);
    assert.equal(response.status, 404, path);
  }
  assert.equal((await handleRequest(new Request(`https://r.example.com/hook/${HOOK}`), env(), NOW)).status, 405);
  assert.equal((await handleRequest(post("not json"), env(), NOW)).status, 400);
  assert.equal((await handleRequest(post(JSON.stringify({ type: "other" })), env(), NOW)).status, 400);
  assert.equal((await handleRequest(post("x".repeat(1024 * 1024 + 1)), env(), NOW)).status, 413);
});

test("F5: admin pages with cursors, reports completeness, and costs one KV operation", async () => {
  const token = "admin-token-for-tests-only-0001";
  const e = env({ ADMIN_TOKEN: token });
  await handleRequest(challenge(ID, "chal_secret_value"), e, NOW);
  await handleRequest(challenge(OTHER, "chal_other", null), e, NOW);
  await handleRequest(delivery(), e, NOW + 1);
  e.REFUSED_SUBSCRIPTION_IDS = OTHER;
  assert.equal((await handleRequest(admin(token), env({ ADMIN_TOKEN: undefined }), NOW)).status, 404);
  assert.equal((await handleRequest(new Request(`https://r.example.com/hook/${HOOK}/admin`), e, NOW)).status, 401);
  assert.equal((await handleRequest(admin("wrong-token-wrong-token-xx"), e, NOW)).status, 401);
  e.RECEIVER_KV.ops = 0;
  const subs = await handleRequest(admin(token), e, NOW);
  assert.equal(e.RECEIVER_KV.ops, 1, "one list, no per-ID reads");
  assert.equal(subs.headers.get("cache-control"), "no-store");
  const text = await subs.text(), body = JSON.parse(text);
  assert.deepEqual(body.items, [{ id: ID, verifiedAt: NOW, refused: false, hasSigningSecret: true }]);
  assert.equal(body.complete, true); assert.deepEqual(body.refused, [OTHER]);
  const pending = await (await handleRequest(admin(token, "?list=pending"), e, NOW)).json();
  assert.deepEqual(pending.items, [{ id: OTHER, challengedAt: NOW, refused: true, hasSigningSecret: false }]);
  const events = await (await handleRequest(admin(token, "?list=events"), e, NOW)).json();
  assert.equal(events.items.length, 1); assert.equal(events.items[0].event_id, envelope.id);
  for (const hidden of [SECRET, "chal_secret_value", token, HOOK]) assert.ok(!text.includes(hidden), hidden);
  // An empty page that is not the last must not read as "nothing here".
  e.RECEIVER_KV.emptyFirstPage = true;
  const first = await (await handleRequest(admin(token), e, NOW)).json();
  assert.deepEqual([first.items, first.complete, first.cursor], [[], false, "0"]);
  e.RECEIVER_KV.emptyFirstPage = false;
  const next = await (await handleRequest(admin(token, `?cursor=${first.cursor}`), e, NOW)).json();
  assert.equal(next.items[0].id, ID);
  assert.equal((await handleRequest(admin(token, "?list=secrets"), e, NOW)).status, 400);
});

test("F5: large listings page instead of exceeding a request's KV budget", async () => {
  const token = "admin-token-for-tests-only-0001";
  const e = env({ ADMIN_TOKEN: token });
  const letter = (n: number) => String.fromCharCode(97 + (n % 26));
  const subId = (n: number) => `sub_${"a".repeat(18)}${letter(Math.floor(n / 26))}${letter(n)}`;
  for (let n = 0; n < 250; n++) await e.RECEIVER_KV.put(`sub:${subId(n)}`, "", { metadata: { verifiedAt: n } });
  let cursor: string | null = null, seen = 0, pages = 0;
  do {
    e.RECEIVER_KV.ops = 0;
    const page = await (await handleRequest(admin(token, cursor ? `?cursor=${cursor}` : ""), e, NOW)).json();
    assert.equal(e.RECEIVER_KV.ops, 1); assert.ok(page.items.length <= 100);
    seen += page.items.length; cursor = page.cursor; pages++;
    assert.ok(pages <= 5, "pagination must advance and terminate");
  } while (cursor);
  assert.equal(seen, 250); assert.equal(pages, 3);
});

test("logs carry identifiers and outcomes only", async () => {
  const lines: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => { lines.push(args.map(String).join(" ")); };
  try {
    const e = env();
    await handleRequest(challenge(ID, "chal_never_logged"), e, NOW);
    await handleRequest(challenge(OTHER, "chal_pending_never_logged", null), e, NOW);
    await handleRequest(delivery(), e, NOW);
    await handleRequest(delivery(ID, envelope.id, "whsec_wrong"), env(), NOW);
  } finally { console.log = original; }
  assert.ok(lines.length >= 4);
  for (const line of lines) for (const hidden of [SECRET, "chal_never_logged", "chal_pending_never_logged", "whsec_", HOOK, "marketSymbol", "quantity"]) assert.ok(!line.includes(hidden), line);
});
