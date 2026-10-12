# Boros webhook receivers (examples)

Receivers for Boros Explorer wallet webhooks, which are in a private beta. The
webhook contract (registration, signatures, the envelope, delivery rules and
limits) is on the [developer page](https://borosexplorer.com/docs/developers/webhooks).

- **To see events arrive**, start with the print receiver below: one file, no
  storage.
- **To build on**, use the full receiver, which comes as a Cloudflare Worker and
  as a Node 22 process. The rest of this page is about it.

## Quick start: print the events

`print-receiver.js` answers the verification challenge and prints every event it
receives. In your own Cloudflare account:

```bash
npm install
HOOK_PATH=$(openssl rand -hex 16)
WORKER_URL=$(npx wrangler deploy --config print.wrangler.jsonc | tee /dev/stderr | grep -o 'https://[^ ]*\.workers\.dev' | head -1)
printf '%s' "$HOOK_PATH" | npx wrangler secret put HOOK_PATH --config print.wrangler.jsonc
echo "Callback URL: $WORKER_URL/$HOOK_PATH"
npx wrangler tail --config print.wrangler.jsonc
```

The `echo` line prints your callback URL: the Worker's address followed by a
random path, so that only someone with the whole URL can use it. Keep it; if
you lose it, run the `HOOK_PATH` lines again for a new one.

During the beta the hostname has to be approved first: [get in touch](https://borosexplorer.com/docs/contact).
Then, on My Desk,
press **Webhook** beside an alert and paste the URL. The webhook
is active straight away, because this receiver answers the first challenge, and
Send test prints a test event in the `wrangler tail` window within seconds.

It is for trying things out. It keeps nothing, does not deduplicate retries,
and prints without checking signatures unless you install the secret (the
`SIGNING_SECRETS` map described below, set the same way as `HOOK_PATH`).
`wrangler tail` also shows each request's URL, which contains the path, so
don't share its output.

## The full receiver

Two builds share one request handler (`src/receiver.ts`) and signature verifier
(`src/verify.ts`):

- **Cloudflare Worker** (`src/index.ts`), storing state in Workers KV.
- **Node 22** (`src/node.ts`), storing state in a local SQLite file. It runs as
  one process, and `node:sqlite` is still experimental in Node 22.

To host one for the first time, start with [SETUP.md](SETUP.md). What it does:

- **Activates a subscription only once it can check that subscription's
  signatures.** It answers a challenge only when the subscription's signing
  secret is installed and the challenge's signature verifies.
- **Verifies every delivery's signature**, with a five-minute replay window and
  both secrets accepted during a rotation.
- **Deduplicates retries** on `(subscription_id, id)`.
- **Stops chosen subscriptions** with HTTP 410, by ID, with no credentials needed.
- **Only answers on a secret path.** Activation already needs a secret that only
  you install; the path is a second barrier.

## Requests it handles

Everything lives under `https://<receiver-host>/hook/<HOOK_PATH>`. Any other path answers 404.

| Request | Response |
| --- | --- |
| Challenge, secret not installed yet | `503`, with no echo. The ID is kept for 48 hours under `pending`, so the subscription stays pending. |
| Challenge, secret installed | Signature checked (`401` if it fails), the ID recorded under `subscriptions`, then `200` with the challenge as the body. `503` if the ID could not be recorded. |
| Challenge for an ID in `REFUSED_SUBSCRIPTION_IDS` | `410`, never echoed. The registration stays `pending_verification` until it is deleted or cleaned up. |
| Delivery for an ID in `REFUSED_SUBSCRIPTION_IDS` | `410`. The sender marks that subscription `gone`. |
| Event (`boros.wallet_event`) or test (`boros.webhook.test`) | `200` when verified, a supported v1 shape, and new. `200 {duplicate:true}` when already processed. `401` for an unknown secret or a bad or stale signature. `400` for mismatched headers or an unsupported shape. `503` (retried) if storage fails. |
| `GET …/admin?list=subscriptions\|pending\|events[&cursor=…]` with `Authorization: Bearer <ADMIN_TOKEN>` | One page: `items`, `complete` and `cursor`. Never includes secrets, challenges or payloads. `404` unless `ADMIN_TOKEN` is set. |

## Register a subscription

Keep credentials in a private directory outside the checkout (mode 0700, files
0600), backed up somewhere like a password manager. Don't paste them into chat,
issues, command arguments or logs. The paths and IDs below are placeholders.

**1. Register.** The simpler way is from the explorer: on My Desk, write an
alert for the wallets and events you want (a wallet page's Account section
opens one filled in with that wallet), press **Webhook** beside
it and enter your callback URL. Download `registration.json` when the
credentials appear, then continue at step 2. My Desk keeps the management token
and shows the webhook's status beside the alert.

To register from a script instead, put your callback URL and wallet in
`request.json`:

```json
{
  "callbackUrl": "https://receiver.example.com/hook/your-private-path",
  "wallet": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "events": ["fills"]
}
```

Send it once, writing the response to a new file so a failure can't overwrite
saved credentials:

```bash
(umask 077; curl --silent --show-error --fail-with-body --max-time 20 \
  --request POST --header 'content-type: application/json' \
  --data-binary @/private/path/request.json \
  --output /private/path/registration.json \
  https://borosexplorer.com/api/webhooks/subscriptions)
```

Don't add `--retry`. If the command fails or times out, the subscription may
still exist: see [Lost credentials](https://borosexplorer.com/docs/developers/webhooks#recovery)
before trying again.

The registration's challenge reaches the receiver before you have the secret, so
the receiver declines it and the response shows `pending_verification`. The
response also holds the subscription `id`, the **management token** and the
**signing secret**, each shown only once.

**2. Save the credentials.** This writes the token to a header file and the
secret to a signing-secret map without printing either. It refuses to overwrite
existing files, so use it for your first subscription:

```bash
node --input-type=module - /private/path/registration.json /private/path <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const [source, directory] = process.argv.slice(2);
const r = JSON.parse(readFileSync(source, 'utf8'));
if (!/^sub_[a-z2-7]{20}$/.test(r.id ?? '') ||
    !/^bwm_[A-Za-z0-9_-]{43}$/.test(r.managementToken ?? '') ||
    !/^whsec_[A-Za-z0-9_-]{43}$/.test(r.signingSecret ?? '')) {
  throw new Error('No valid registration credentials; use the recovery procedure.');
}
const save = (name, text) => writeFileSync(join(directory, name), text, { mode: 0o600, flag: 'wx' });
save('management.headers', `Authorization: Bearer ${r.managementToken}\n`);
save('signing-secrets.json', JSON.stringify({ [r.id]: r.signingSecret }));
console.log(JSON.stringify({ id: r.id, status: r.status, expiresAt: r.expiresAt }));
JS
```

For later subscriptions, keep one header file per ID and add each new secret to
the existing map. The receiver reads the whole map, so replacing it with only the
new entry breaks the others.

**3. Install the secret.** On Cloudflare, from this directory:

```bash
npx wrangler secret put SIGNING_SECRETS < /private/path/signing-secrets.json
```

On Node, copy the map into the config file's `SIGNING_SECRETS` (a JSON string).
The receiver rereads the config on every request, so no restart is needed. This
replaces the file in one rename, so a request never reads half of it:

```bash
node --input-type=module - /private/path/receiver-state/config.json /private/path/signing-secrets.json <<'JS'
import { readFileSync, writeFileSync, renameSync } from 'node:fs';
const [file, mapFile] = process.argv.slice(2);
const config = JSON.parse(readFileSync(file, 'utf8'));
const map = JSON.parse(readFileSync(mapFile, 'utf8'));
config.SIGNING_SECRETS = JSON.stringify(map); // complete map, including existing IDs
const next = `${file}.next`;
writeFileSync(next, JSON.stringify(config), { mode: 0o600, flag: 'wx' });
renameSync(next, file);
JS
```

**4. Verify.** Press Verify beside the alert on My Desk, or with the API:

```bash
curl --silent --show-error --fail-with-body --max-time 20 \
  --request POST --header @/private/path/management.headers \
  --header 'content-type: application/json' --data '{}' \
  https://borosexplorer.com/api/webhooks/subscriptions/sub_aaaaaaaaaaaaaaaaaaaa/verify
```

The response should show `status: active`. The registration's own challenge used
the first of five attempts, so four remain; after the fifth, `/verify` answers
409. If a challenge fails, fix the receiver before trying again.

**Rotating a secret.** Rotate on the management page (Manage, beside the
alert), or call `POST /:id/rotate-secret` once, and save the new secret. For the 24-hour overlap, install both, new first:
`{"sub_…":["whsec_new","whsec_old"]}`. Remove the old one afterwards; the
receiver does not expire it on its own.

## Check it's working

The management page (Manage, beside the alert on My Desk) shows today's usage
and the latest 50 delivery receipts. With the API, `GET
/api/webhooks/subscriptions/:id` and the same header file return the same; the
response includes your callback URL, so save it privately rather than printing it.

An active subscription with no receipts has passed its challenge and is waiting
for a matching event. An order cancellation won't show up on a fills-only
subscription. You don't need to trade to test it: Send test on My Desk, or
`POST /:id/test` with `{}`, sends a `boros.webhook.test` event through the real queue, retries and daily
budget. Check the receipts before sending another, as the first may still be
queued. Only a real event exercises matching and the full wallet payload.

The receiver's own admin view lists what it has seen. Keep the URL and admin
token out of shell history with a private curl config file:

```text
url = "https://<receiver-host>/hook/<HOOK_PATH>/admin?list=events"
header = "Authorization: Bearer <ADMIN_TOKEN>"
```

```bash
curl --silent --show-error --config /private/path/receiver-admin.curl
```

- `subscriptions` lists verified IDs. Keep them: they are how you stop a
  subscription whose token is lost.
- `pending` lists challenged IDs for 48 hours. An ID can stay here after it is
  verified, so this is not a status.
- `events` lists event summaries, newest first, 50 a page.
- Follow `cursor` until `complete` is true; an empty page can still have a cursor.
- KV is eventually consistent, so on Cloudflare a new entry can take a minute or
  longer to appear. SQLite has no lag but only sees that one process's traffic.

## Stopping a subscription by ID

Add only its ID to `REFUSED_SUBSCRIPTION_IDS`, a comma-separated list: in the
Node config file, or in `wrangler.jsonc` (then redeploy) or the dashboard on
Cloudflare.

- **Active subscription:** its next delivery answers `410`, and the sender marks
  it `gone`. Nothing happens until that delivery arrives.
- **Pending registration:** its challenges answer `410`, which only stops it
  activating. It stays pending until it is deleted or cleaned up.

Other subscriptions on the receiver are unaffected. Never answer 410 to every
request on a shared callback.

If you still have the management token, `DELETE` is simpler. Boros Explorer can
also disable a subscription whose ID you know: [get in touch](https://borosexplorer.com/docs/contact). Never send
credentials to anyone.

## Your own processing

Put your work where the comment in `src/receiver.ts` says.

- **It runs before the completion marker,** so any failure is retried rather than
  skipped. It must be idempotent: a retry can run it again, and so can two
  near-simultaneous deliveries, because neither store makes your work and the
  marker one transaction.
- **It must finish well inside five seconds,** including storage writes. Send
  slow work to a queue rather than doing it after the response.
- **For effects that must happen exactly once,** use a unique key in a
  transactional store, or an idempotent downstream call.

## Testing retries

Set `FORCE_DELIVERY_STATUS` to `500` (or `429`, `502`, `503`). Verified events
then fail without being recorded. Watch `x-boros-attempt` climb, then clear the
setting, and the next retry is accepted once.

- **404, 410 and 2xx are ignored here on purpose:** a 404 or 410 would mark the
  subscription gone.
- **Stay under 25 failures in a row:** 25 consecutive failures pause the
  subscription. Forced failures also spend the daily attempt budget.

## Logs and the secret path

- **Console lines** carry subscription IDs, event IDs and outcomes only, never
  events, challenges, credentials or the path.
- **Invocation logs are disabled** in `wrangler.jsonc`, because they record the
  request URL.
- **`wrangler tail` still shows the URL,** so treat its output as containing the
  secret path, and don't share or export it. Configure the HTTPS proxy in front
  of the Node receiver to leave URLs, headers and bodies out of its logs too.

## Storage

- **Retention:** event summaries and dedup markers expire after seven days,
  pending IDs after 48 hours. Verified IDs stay until you remove them. SQLite
  prunes up to 1,000 expired rows on each write and hides expired rows from reads.
- **KV writes:** two per new event, one per challenge. Check your plan's KV
  limits before a busy test (Workers Free allows 1,000 writes a day).
- **Ordering:** events arrive in any order. Sort by `blockNumber`, then
  `logIndex`.

## Tests

On Node 22:

```bash
npm install
npm test
```

The tests check the signature code against the sender's fixed vectors,
including the rotation header. They also cover:

- refusing to activate before the secret is installed;
- marker-last retries after storage failures;
- payload validation and bounded stored fields;
- per-ID refusal, the secret path and forced failures;
- paginated admin reads;
- what is logged;
- for Node, over real local HTTP: raw-byte verification, config reloads, and
  deduplication and stored IDs surviving a restart.
- for the print receiver: the challenge echo, printing, and signatures against
  the same vectors once a secret is installed.
