// Node 22 example adapter for the same receiver used by the Cloudflare Worker.
// Run with tsx; see ../SETUP.md. Localhost only: put HTTPS termination in front.
import { createServer } from "node:http";
import { chmodSync, closeSync, openSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Readable } from "node:stream";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { handleRequest, type ReceiverEnv, type ReceiverKv } from "./receiver";

// node:sqlite ships with Node 22 but older @types/node do not describe it, so
// the few calls this file makes are typed here.
type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;
interface ReceiverDatabase {
  exec(sql: string): void;
  close(): void;
  prepare(sql: string): {
    get(...parameters: SqlValue[]): SqlRow | undefined;
    all(...parameters: SqlValue[]): SqlRow[];
    run(...parameters: SqlValue[]): unknown;
  };
}
const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
  DatabaseSync: new (filename: string) => ReceiverDatabase;
};

/** A single-process, local-disk store. It is not an exactly-once effect adapter. */
export class SqliteReceiverKv implements ReceiverKv {
  private readonly db: ReceiverDatabase;
  constructor(filename: string, private readonly now = Date.now) {
    closeSync(openSync(filename, "a", 0o600));
    chmodSync(filename, 0o600);
    this.db = new DatabaseSync(filename);
    this.db.exec(`CREATE TABLE IF NOT EXISTS receiver (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, metadata TEXT, expires INTEGER
    ); CREATE INDEX IF NOT EXISTS receiver_expiry ON receiver(expires);`);
  }
  close() { this.db.close(); }
  async get(key: string): Promise<string | null> {
    const row = this.db.prepare("SELECT value FROM receiver WHERE key = ? AND (expires IS NULL OR expires > ?)").get(key, this.now());
    return row ? String(row.value) : null;
  }
  async put(key: string, value: string, options?: { expirationTtl?: number; metadata?: unknown }): Promise<void> {
    const now = this.now();
    this.db.prepare("DELETE FROM receiver WHERE key IN (SELECT key FROM receiver WHERE expires <= ? LIMIT 1000)").run(now);
    this.db.prepare(`INSERT INTO receiver(key, value, metadata, expires) VALUES (?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value, metadata=excluded.metadata, expires=excluded.expires`).run(
      key, value, options?.metadata === undefined ? null : JSON.stringify(options.metadata),
      options?.expirationTtl === undefined ? null : now + options.expirationTtl * 1000,
    );
  }
  async list({ prefix, limit = 1000, cursor = "" }: { prefix: string; limit?: number; cursor?: string }) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new Error("Invalid page size");
    const rows = this.db.prepare(`SELECT key, metadata FROM receiver
      WHERE key >= ? AND key < ? AND key > ? AND (expires IS NULL OR expires > ?)
      ORDER BY key LIMIT ?`).all(prefix, `${prefix}\uffff`, cursor, this.now(), limit + 1);
    const keys = rows.slice(0, limit).map(row => ({
      name: String(row.key), ...(row.metadata === null ? {} : { metadata: JSON.parse(String(row.metadata)) as unknown }),
    }));
    return { keys, list_complete: rows.length <= limit, ...(rows.length > limit ? { cursor: keys.at(-1)!.name } : {}) };
  }
}

/** Read afresh so installing/rotating a secret needs no process restart. */
export async function readNodeConfig(filename: string): Promise<Omit<ReceiverEnv, "RECEIVER_KV">> {
  const raw: unknown = JSON.parse(await readFile(filename, "utf8"));
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Invalid receiver config");
  const data = raw as Record<string, unknown>;
  const env: Omit<ReceiverEnv, "RECEIVER_KV"> = {};
  for (const key of ["HOOK_PATH", "SIGNING_SECRETS", "ADMIN_TOKEN", "REFUSED_SUBSCRIPTION_IDS", "FORCE_DELIVERY_STATUS"] as const) {
    if (data[key] !== undefined && typeof data[key] !== "string") throw new Error("Receiver config values must be strings");
    env[key] = data[key] as string | undefined;
  }
  if (!env.HOOK_PATH || !/^[A-Za-z0-9_-]{24,}$/.test(env.HOOK_PATH)) throw new Error("Invalid hook path");
  const secrets: unknown = JSON.parse(env.SIGNING_SECRETS ?? "{}");
  if (!secrets || typeof secrets !== "object" || Array.isArray(secrets)) throw new Error("Invalid signing secret map");
  for (const [id, value] of Object.entries(secrets)) {
    const values = Array.isArray(value) ? value : [value];
    if (!/^sub_[a-z2-7]{20}$/.test(id) || values.length < 1 || values.length > 2 ||
      !values.every(secret => typeof secret === "string" && /^whsec_[A-Za-z0-9_-]{43}$/.test(secret))) {
      throw new Error("Invalid signing secret entry");
    }
  }
  return env;
}

export function createNodeReceiver(loadEnv: () => Promise<ReceiverEnv>) {
  return createServer({ requestTimeout: 5000, headersTimeout: 5000 }, async (incoming, outgoing) => {
    try {
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(",") : value);
      }
      const init: RequestInit & { duplex: "half" } = {
        method: incoming.method, headers, duplex: "half",
        ...(incoming.method !== "GET" && incoming.method !== "HEAD" ? { body: Readable.toWeb(incoming) as unknown as ReadableStream<Uint8Array> } : {}),
      };
      const request = new Request(new URL(incoming.url ?? "/", "http://127.0.0.1"), init);
      const response = await handleRequest(request, await loadEnv());
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      // Never print an exception: request URLs/config errors may contain secrets.
      outgoing.writeHead(503, { "cache-control": "no-store", "retry-after": "60" });
      outgoing.end();
    }
  });
}

async function main() {
  const [configFile, databaseFile, portText = "8788"] = process.argv.slice(2);
  const port = Number(portText);
  if (!configFile || !databaseFile || !Number.isInteger(port) || port < 1024 || port > 65535 || port === 3000) {
    throw new Error("Usage: tsx node.ts <private-config.json> <private-receiver.sqlite> [port, default 8788]");
  }
  process.umask(0o077);
  await readNodeConfig(configFile);
  const storage = new SqliteReceiverKv(databaseFile);
  const server = createNodeReceiver(async () => ({ ...await readNodeConfig(configFile), RECEIVER_KV: storage }));
  server.on("error", () => { console.error("Receiver could not listen"); storage.close(); process.exitCode = 1; });
  server.listen(port, "127.0.0.1", () => console.log(`Boros example receiver listening on loopback port ${port}`));
  const close = () => { server.close(() => storage.close()); server.closeIdleConnections(); };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void main().catch(() => { console.error("Receiver startup failed; check private configuration, storage and port"); process.exitCode = 1; });
}
