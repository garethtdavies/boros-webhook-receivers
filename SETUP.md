# Hosting an example receiver

One-time setup for your own receiver. Once it is running, register subscriptions
with the [README](README.md). If you already run an HTTPS service, you can
instead reuse `src/verify.ts` and implement the
[callback contract](https://borosexplorer.com/docs/developers/webhooks) yourself.

## Secret path and admin token

Both receivers need a random `HOOK_PATH` and an admin token. Generate them into
a private directory without printing them:

```bash
(umask 077
 mkdir -m 700 /private/path/receiver-state
 openssl rand -hex 32 > /private/path/receiver-state/hook-path
 openssl rand -hex 32 > /private/path/receiver-state/admin-token)
```

Back both up privately. Your callback URL is
`https://<your-approved-host>/hook/<HOOK_PATH>`.

**Treat `HOOK_PATH` as permanent.** Changing it makes every subscription using the
old URL answer 404, which marks it `gone` on its next delivery.

## Cloudflare Worker

From this directory, after `npm install`, in your own Cloudflare account:

1. Create the KV namespace and put the returned ID in the `RECEIVER_KV` binding
   in `wrangler.jsonc`:

   ```bash
   npx wrangler kv namespace create RECEIVER_KV
   ```

2. Store both values as Worker secrets:

   ```bash
   npx wrangler secret put HOOK_PATH < /private/path/receiver-state/hook-path
   npx wrangler secret put ADMIN_TOKEN < /private/path/receiver-state/admin-token
   ```

3. Deploy:

   ```bash
   npx wrangler deploy
   ```

4. [Get in touch](https://borosexplorer.com/docs/contact) to have the Worker's hostname approved for the beta.

`SIGNING_SECRETS` stays unset until you register. Leave `REFUSED_SUBSCRIPTION_IDS`
and `FORCE_DELIVERY_STATUS` empty for normal use. Keep invocation logs disabled
in `wrangler.jsonc`: they record the URL, which contains the secret path.

## Node 22

The Node receiver uses the built-in `node:sqlite`, so it needs no database server
or extra package. Run one process with the database on persistent local disk,
not a network share or ephemeral storage.

Write the config file from the generated values:

```bash
node --input-type=module - /private/path/receiver-state <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const directory = process.argv[2];
const value = name => readFileSync(join(directory, name), 'utf8').trim();
writeFileSync(join(directory, 'config.json'), JSON.stringify({
  HOOK_PATH: value('hook-path'), ADMIN_TOKEN: value('admin-token'),
  SIGNING_SECRETS: '{}', REFUSED_SUBSCRIPTION_IDS: '', FORCE_DELIVERY_STATUS: ''
}), { mode: 0o600, flag: 'wx' });
JS
```

Then, after `npm install` in this directory:

```bash
npx tsx src/node.ts \
  /private/path/receiver-state/config.json \
  /private/path/receiver-state/receiver.sqlite 8788
```

It listens on 127.0.0.1 only (port 8788 by default; 3000 is refused). Put an
HTTPS reverse proxy on port 443 in front of it that passes the method, path,
body bytes and `x-boros-*` headers through unchanged and keeps URLs, headers and
bodies out of its logs. TLS, process supervision and backups are up to you.
[Get in touch](https://borosexplorer.com/docs/contact) to have the proxy's hostname approved for the beta.

Keep the database between restarts. It holds verified IDs, dedup markers and
event summaries, never secrets or full payloads.
