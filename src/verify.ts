// Boros webhook signature verification. Web Crypto only, so it runs unchanged
// in a Cloudflare Worker, Node 18+ or a browser.
//
//   x-boros-signature: t=<unix seconds>,v1=<hex>[,v1=<hex>]
//
// Each v1 is HMAC-SHA256 over `<t>.<raw body>`, keyed with the UTF-8 bytes of
// the whsec_ string (do not base64-decode it). During a secret rotation the
// header carries two v1 values, current first; either one verifying is enough.

const encoder = new TextEncoder();

/** Reject signatures older or newer than this, so a captured request cannot be replayed later. */
export const SIGNATURE_TOLERANCE_SECONDS = 300;

export type ParsedSignature = { t: number; signatures: string[] };

export function parseSignatureHeader(header: string | null): ParsedSignature | null {
  if (!header || header.length > 512) return null;
  let t: number | null = null;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [key, value, extra] = part.trim().split("=");
    if (extra !== undefined || value === undefined) return null;
    if (key === "t" && /^(?:0|[1-9]\d{0,11})$/.test(value) && t === null) t = Number(value);
    else if (key === "v1" && /^[0-9a-f]{64}$/.test(value)) signatures.push(value);
    else return null;
  }
  return t === null || signatures.length === 0 || signatures.length > 2 ? null : { t, signatures };
}

function hexBytes(hex: string) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/**
 * True when any v1 signature verifies with any of the subscription's secrets
 * and the timestamp is within tolerance. `crypto.subtle.verify` compares in
 * constant time.
 */
export async function verifySignature(options: {
  header: string | null;
  rawBody: Uint8Array;
  secrets: readonly string[];
  nowSeconds: number;
}): Promise<boolean> {
  const parsed = parseSignatureHeader(options.header);
  if (!parsed || Math.abs(options.nowSeconds - parsed.t) > SIGNATURE_TOLERANCE_SECONDS) return false;
  const prefix = encoder.encode(`${parsed.t}.`);
  const message = new Uint8Array(prefix.length + options.rawBody.length);
  message.set(prefix);
  message.set(options.rawBody, prefix.length);
  for (const secret of options.secrets) {
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    for (const signature of parsed.signatures) {
      if (await crypto.subtle.verify("HMAC", key, hexBytes(signature), message)) return true;
    }
  }
  return false;
}
