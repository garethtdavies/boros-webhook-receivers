// The smallest receiver that works: it answers the verification challenge and
// prints every event. One file, no storage, for trying webhooks out. Deploy it
// as a Cloudflare Worker (see README.md) and watch `wrangler tail`.
//
// A receiver you rely on should do more: keep the IDs it verified, deduplicate
// retries and refuse unsigned requests. That is src/receiver.ts.
//
// Settings, both optional:
//   HOOK_PATH        answer only on https://<host>/<HOOK_PATH>, so strangers cannot use this URL
//   SIGNING_SECRETS  {"sub_…":"whsec_…"}; a subscription listed here must be signed correctly,
//                    one that is not listed is printed without checking its signature

const encoder = new TextEncoder();
const hexBytes = (hex) => Uint8Array.from(hex.match(/../g), (byte) => Number.parseInt(byte, 16));

/** x-boros-signature is `t=<unix seconds>,v1=<hex>[,v1=<hex>]`; each v1 is HMAC-SHA256 of `<t>.<raw body>`. */
async function signatureVerifies(header, rawBody, secrets) {
  const t = /(?:^|,)t=(\d+)(?:,|$)/.exec(header ?? "")?.[1];
  const signatures = [...(header ?? "").matchAll(/(?:^|,)v1=([0-9a-f]{64})(?=,|$)/g)].map((match) => match[1]);
  if (!t || signatures.length === 0 || Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
  const message = encoder.encode(`${t}.${rawBody}`);
  for (const secret of secrets) {
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    for (const signature of signatures) {
      if (await crypto.subtle.verify("HMAC", key, hexBytes(signature), message)) return true;
    }
  }
  return false;
}

const receiver = {
  async fetch(request, env) {
    if (env.HOOK_PATH && new URL(request.url).pathname !== `/${env.HOOK_PATH}`) return new Response("Not found", { status: 404 });
    if (request.method !== "POST") return new Response("POST only", { status: 405 });

    const rawBody = await request.text(); // the signature covers these exact characters, so read before parsing
    let body;
    try {
      body = JSON.parse(rawBody);
    } catch {
      return new Response("Not JSON", { status: 400 });
    }

    const id = body.subscription_id ?? request.headers.get("x-boros-subscription-id");
    const installed = JSON.parse(env.SIGNING_SECRETS || "{}")[id];
    let signature = "signature not checked";
    if (installed) {
      if (!(await signatureVerifies(request.headers.get("x-boros-signature"), rawBody, [installed].flat()))) {
        console.log(`REJECTED ${id}: bad or stale signature`);
        return new Response("Bad signature", { status: 401 });
      }
      signature = "signature ok";
    }

    if (body.type === "boros.webhook.verification") {
      console.log(`challenge for ${id} (${signature})`);
      return new Response(body.challenge, { headers: { "content-type": "text/plain" } }); // the whole body, nothing else
    }

    console.log(`${body.type} for ${id}, attempt ${request.headers.get("x-boros-attempt") ?? "?"} (${signature})\n${JSON.stringify(body, null, 2)}`);
    return new Response("ok");
  },
};

export default receiver;
