// A Boros webhook receiver: signed verification, signature checks, dedup and
// per-subscription refusal. See ../README.md for setup, registration and limits.
//
// Activation rule: this receiver answers a verification challenge ONLY when
// it holds that subscription's signing secret and the challenge's signature
// verifies. A first registration therefore stays pending until the secret is
// installed and /verify is called, so no delivery can arrive before the
// receiver is able to check it.

import { verifySignature } from "./verify";

/** The subset of a Workers KV namespace this receiver uses. */
export interface ReceiverKv {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number; metadata?: unknown }): Promise<void>;
  list(options: { prefix: string; limit?: number; cursor?: string }): Promise<{
    keys: Array<{ name: string; metadata?: unknown }>;
    list_complete: boolean;
    cursor?: string;
  }>;
}

export interface ReceiverEnv {
  /** Secret path segment: the callback is https://<host>/hook/<HOOK_PATH>. At least 24 characters. */
  HOOK_PATH?: string;
  /** JSON object: { "sub_…": "whsec_…" } or { "sub_…": ["whsec_current", "whsec_previous"] }. */
  SIGNING_SECRETS?: string;
  /** Comma-separated subscription IDs to stop with HTTP 410. */
  REFUSED_SUBSCRIPTION_IDS?: string;
  /** Testing only: answer verified events with this status (429 or 500-599) to watch retries. */
  FORCE_DELIVERY_STATUS?: string;
  /** Enables GET /hook/<HOOK_PATH>/admin with `Authorization: Bearer <ADMIN_TOKEN>`. */
  ADMIN_TOKEN?: string;
  RECEIVER_KV?: ReceiverKv;
}

const SUBSCRIPTION_ID = /^sub_[a-z2-7]{20}$/;
const MAX_BODY_BYTES = 1024 * 1024;
const EVENT_RETENTION_SECONDS = 7 * 24 * 60 * 60;
/** Unverified challenge IDs are kept briefly for visibility; the Worker's cleanup removes pending rows after 24 hours. */
const PENDING_RETENTION_SECONDS = 2 * 24 * 60 * 60;
const ADMIN_PAGE_SIZE = { subscriptions: 100, pending: 100, events: 50 } as const;
const encoder = new TextEncoder();

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
const notFound = () => json(404, { ok: false });
/** Retryable: the sender tries again later; nothing was recorded as done. */
const unavailable = () => json(503, { ok: false }, { "retry-after": "60" });

/** Logs identifiers and outcomes only: never challenges, secrets, tokens, paths or payloads. */
function log(fields: Record<string, unknown>) {
  console.log(JSON.stringify({ receiver: "boros-webhooks", ...fields }));
}

function refusedIds(env: ReceiverEnv): Set<string> {
  return new Set((env.REFUSED_SUBSCRIPTION_IDS ?? "").split(",").map((id) => id.trim()).filter((id) => SUBSCRIPTION_ID.test(id)));
}

function secretsFor(env: ReceiverEnv, id: string): string[] {
  try {
    const value = (JSON.parse(env.SIGNING_SECRETS ?? "{}") as Record<string, unknown>)[id];
    const list = Array.isArray(value) ? value : [value];
    return list.filter((secret): secret is string => typeof secret === "string" && secret.startsWith("whsec_"));
  } catch {
    return [];
  }
}

async function readBody(request: Request): Promise<Uint8Array | null> {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > MAX_BODY_BYTES) return null;
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const parts: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_BODY_BYTES) { await reader.cancel(); return null; }
    parts.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  return bytes;
}

async function sameSecret(a: string, b: string): Promise<boolean> {
  const digest = async (value: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  const x = await digest(a), y = await digest(b);
  let difference = 0;
  for (let i = 0; i < x.length; i++) difference |= x[i]! ^ y[i]!;
  return difference === 0;
}

/** One page per request, one KV operation: everything shown lives in key metadata. */
async function admin(request: Request, env: ReceiverEnv): Promise<Response> {
  if (!env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 24) return notFound();
  if (request.method !== "GET") return json(405, { ok: false }, { allow: "GET" });
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ") || !(await sameSecret(auth.slice(7), env.ADMIN_TOKEN))) return json(401, { ok: false });
  if (!env.RECEIVER_KV) return unavailable();
  const params = new URL(request.url).searchParams;
  const kind = params.get("list") ?? "subscriptions";
  if (kind !== "subscriptions" && kind !== "pending" && kind !== "events") return json(400, { ok: false });
  const cursor = params.get("cursor") ?? undefined;
  const prefix = kind === "subscriptions" ? "sub:" : kind === "pending" ? "pending:" : "log:";
  const page = await env.RECEIVER_KV.list({ prefix, limit: ADMIN_PAGE_SIZE[kind], cursor });
  const refused = refusedIds(env);
  const items = page.keys.map(({ name, metadata }) => {
    if (kind === "events") return metadata ?? null;
    const id = name.slice(prefix.length);
    return { id, ...(metadata && typeof metadata === "object" ? metadata : {}), refused: refused.has(id), hasSigningSecret: secretsFor(env, id).length > 0 };
  });
  // KV can return an empty page that is not the last: always pass the cursor on.
  return json(200, { ok: true, list: kind, items, complete: page.list_complete, cursor: page.list_complete ? null : page.cursor ?? null, refused: [...refused] });
}

async function verification(env: ReceiverEnv, body: Record<string, unknown>, raw: Uint8Array, signature: string | null, nowMs: number): Promise<Response> {
  const id = body.subscription_id, challenge = body.challenge;
  if (body.version !== 1 || typeof id !== "string" || !SUBSCRIPTION_ID.test(id) || typeof challenge !== "string" || !challenge || challenge.length > 512) {
    return json(400, { ok: false });
  }
  // A refused challenge only blocks activation; the Worker keeps the row pending.
  if (refusedIds(env).has(id)) { log({ kind: "challenge-refused", subscription_id: id }); return json(410, { ok: false }); }
  const secrets = secretsFor(env, id);
  if (!secrets.length) {
    // A first registration: its secret only arrives in the registration
    // response. Do not activate yet. Keep the ID briefly so it is visible,
    // and fail retryably; install the secret, then call /verify.
    try {
      await env.RECEIVER_KV?.put(`pending:${id}`, "", { expirationTtl: PENDING_RETENTION_SECONDS, metadata: { challengedAt: nowMs } });
    } catch { /* visibility only; the challenge is refused either way */ }
    log({ kind: "challenge-awaiting-secret", subscription_id: id });
    return unavailable();
  }
  if (!(await verifySignature({ header: signature, rawBody: raw, secrets, nowSeconds: Math.floor(nowMs / 1000) }))) {
    log({ kind: "challenge-bad-signature", subscription_id: id });
    return json(401, { ok: false });
  }
  // Record the ID BEFORE answering, so every active subscription is listed here.
  if (!env.RECEIVER_KV) return unavailable();
  try {
    await env.RECEIVER_KV.put(`sub:${id}`, "", { metadata: { verifiedAt: nowMs } });
  } catch {
    log({ kind: "challenge-not-recorded", subscription_id: id });
    return unavailable();
  }
  log({ kind: "challenge", subscription_id: id });
  return new Response(challenge, { status: 200, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

const pick = (value: unknown, pattern: RegExp) => (typeof value === "string" && pattern.test(value) ? value : null);
const integer = (value: unknown) => (Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : null);

async function delivery(request: Request, env: ReceiverEnv, body: Record<string, unknown>, raw: Uint8Array, nowMs: number): Promise<Response> {
  const id = request.headers.get("x-boros-subscription-id");
  const eventId = request.headers.get("x-boros-event-id");
  if (!id || !SUBSCRIPTION_ID.test(id) || body.subscription_id !== id || !eventId || eventId.length > 300 || body.id !== eventId) {
    return json(400, { ok: false });
  }
  // Refusal needs no secret: the secret may be the thing that was lost.
  if (refusedIds(env).has(id)) { log({ kind: "refused", subscription_id: id, event_id: eventId }); return json(410, { ok: false }); }
  const secrets = secretsFor(env, id);
  if (!secrets.length) {
    // Should not happen: this receiver only activates subscriptions whose
    // secret is installed. A removed secret makes deliveries fail (and, after
    // 25 failures, pauses the subscription).
    log({ kind: "no-signing-secret", subscription_id: id, event_id: eventId });
    return json(401, { ok: false });
  }
  if (!(await verifySignature({ header: request.headers.get("x-boros-signature"), rawBody: raw, secrets, nowSeconds: Math.floor(nowMs / 1000) }))) {
    log({ kind: "bad-signature", subscription_id: id, event_id: eventId });
    return json(401, { ok: false });
  }
  // Signed is not the same as understood: accept only the v1 shapes.
  const event = body.event;
  const walletEvent = body.type === "boros.wallet_event" && event !== null && typeof event === "object" && !Array.isArray(event)
    && (event as Record<string, unknown>).alertId === eventId;
  if (body.version !== 1 || !(walletEvent || (body.type === "boros.webhook.test" && event === undefined))) {
    log({ kind: "unsupported-envelope", subscription_id: id, event_id: eventId });
    return json(400, { ok: false });
  }
  const forced = Number(env.FORCE_DELIVERY_STATUS);
  if (forced === 429 || (Number.isInteger(forced) && forced >= 500 && forced <= 599)) {
    log({ kind: "forced-failure", subscription_id: id, event_id: eventId, status: forced });
    return json(forced, { ok: false });
  }
  if (!env.RECEIVER_KV) return unavailable();
  const marker = `event:${id}:${eventId}`;
  try {
    // At least once: the same id arrives on every retry, so dedupe on (subscription, id).
    if (await env.RECEIVER_KV.get(marker)) {
      log({ kind: "duplicate", subscription_id: id, event_id: eventId });
      return json(200, { ok: true, duplicate: true });
    }
    const e = (walletEvent ? event : {}) as Record<string, unknown>;
    // Bounded scalars only, so the summary always fits KV's 1,024-byte metadata.
    const summary = {
      subscription_id: id, event_id: eventId, type: body.type, receivedAt: nowMs,
      attempt: integer(Number(request.headers.get("x-boros-attempt"))),
      role: pick(e.role, /^[a-z-]{1,40}$/), walletRoot: pick(e.walletRoot, /^0x[0-9a-f]{40}$/),
      marketId: integer(e.marketId), blockNumber: integer(e.blockNumber), logIndex: integer(e.logIndex),
      transactionHash: pick(e.transactionHash, /^0x[0-9a-f]{64}$/),
    };
    // Your own processing goes here, BEFORE the completion marker below, and
    // must be idempotent: a failure anywhere leaves no marker, so the retry
    // runs it again. Keep it well under the 5-second response limit.
    const order = String(9_999_999_999_999 - nowMs).padStart(13, "0"); // newest first in KV listings
    await env.RECEIVER_KV.put(`log:${order}:${id}:${eventId}`, "", { expirationTtl: EVENT_RETENTION_SECONDS, metadata: summary });
    // The marker is written last: it means "fully processed".
    await env.RECEIVER_KV.put(marker, "1", { expirationTtl: EVENT_RETENTION_SECONDS });
    log({ kind: "delivered", subscription_id: id, event_id: eventId, attempt: summary.attempt });
    return json(200, { ok: true });
  } catch {
    log({ kind: "storage-failure", subscription_id: id, event_id: eventId });
    return unavailable();
  }
}

export async function handleRequest(request: Request, env: ReceiverEnv, nowMs = Date.now()): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (!env.HOOK_PATH || env.HOOK_PATH.length < 24 || !/^[A-Za-z0-9_-]+$/.test(env.HOOK_PATH)) return notFound();
  const hook = `/hook/${env.HOOK_PATH}`;
  if (path === `${hook}/admin`) return admin(request, env);
  // Anything but the secret path is unknown. The path is defence in depth:
  // activation already requires a secret installed by the owner.
  if (path !== hook) return notFound();
  if (request.method !== "POST") return json(405, { ok: false }, { allow: "POST" });
  const raw = await readBody(request);
  if (!raw) return json(413, { ok: false });
  let body: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return json(400, { ok: false });
    body = parsed as Record<string, unknown>;
  } catch {
    return json(400, { ok: false });
  }
  if (body.type === "boros.webhook.verification") return verification(env, body, raw, request.headers.get("x-boros-signature"), nowMs);
  if (body.type === "boros.wallet_event" || body.type === "boros.webhook.test") return delivery(request, env, body, raw, nowMs);
  return json(400, { ok: false });
}
