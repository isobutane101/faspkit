import crypto from "node:crypto";

/**
 * RFC 9530 Content-Digest (SHA-256) and RFC 9421 HTTP Message Signatures
 * using "EdDSA Using Curve edwards25519", as required by the FASP
 * general specification (general/v0.1/protocol_basics.md).
 */

export function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    // FASP exchanges *raw* 32-byte keys, base64 encoded — not PEM/SPKI.
    publicKey: rawPublicKey(publicKey).toString("base64"),
    privateKey: rawPrivateKey(privateKey).toString("base64"),
  };
}

// Strip the 12-byte SPKI header to get the raw 32-byte Ed25519 public key.
function rawPublicKey(key: crypto.KeyObject): Buffer {
  return key.export({ type: "spki", format: "der" }).subarray(12);
}

// Strip the 16-byte PKCS8 header to get the raw 32-byte seed.
function rawPrivateKey(key: crypto.KeyObject): Buffer {
  return key.export({ type: "pkcs8", format: "der" }).subarray(16);
}

export function importPublicKey(b64: string): crypto.KeyObject {
  const der = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(b64, "base64"),
  ]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

export function importPrivateKey(b64: string): crypto.KeyObject {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(b64, "base64"),
  ]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function contentDigest(body: string | Buffer): string {
  const hash = crypto.createHash("sha256").update(body).digest("base64");
  return `sha-256=:${hash}:`;
}

export function keyFingerprint(publicKeyB64: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(publicKeyB64, "base64"))
    .digest("base64");
}

/**
 * Build the RFC 9421 signature base. Requests cover @method, @target-uri and
 * content-digest; responses cover @status and content-digest.
 */
function signatureBase(
  components: Record<string, string>,
  order: string[],
  params: string,
): string {
  const lines = order.map((c) => `"${c}": ${components[c]}`);
  lines.push(`"@signature-params": ${params}`);
  return lines.join("\n");
}

function paramsString(order: string[], created: number, keyid: string): string {
  const inner = order.map((c) => `"${c}"`).join(" ");
  return `(${inner});created=${created};keyid="${keyid}"`;
}

export interface SignedHeaders {
  "content-digest": string;
  "signature-input": string;
  signature: string;
}

export function signRequest(opts: {
  method: string;
  targetUri: string;
  body: string;
  keyid: string;
  privateKey: string;
  created?: number;
}): SignedHeaders {
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const digest = contentDigest(opts.body);
  const order = ["@method", "@target-uri", "content-digest"];
  const params = paramsString(order, created, opts.keyid);
  const base = signatureBase(
    {
      "@method": opts.method.toUpperCase(),
      "@target-uri": opts.targetUri,
      "content-digest": digest,
    },
    order,
    params,
  );
  const sig = crypto.sign(null, Buffer.from(base), importPrivateKey(opts.privateKey));
  return {
    "content-digest": digest,
    "signature-input": `sig1=${params}`,
    signature: `sig1=:${sig.toString("base64")}:`,
  };
}

export function signResponse(opts: {
  status: number;
  body: string;
  keyid: string;
  privateKey: string;
  created?: number;
}): SignedHeaders {
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const digest = contentDigest(opts.body);
  const order = ["@status", "content-digest"];
  const params = paramsString(order, created, opts.keyid);
  const base = signatureBase(
    { "@status": String(opts.status), "content-digest": digest },
    order,
    params,
  );
  const sig = crypto.sign(null, Buffer.from(base), importPrivateKey(opts.privateKey));
  return {
    "content-digest": digest,
    "signature-input": `sig1=${params}`,
    signature: `sig1=:${sig.toString("base64")}:`,
  };
}

export interface VerifyResult {
  ok: boolean;
  keyid?: string;
  reason?: string;
}

const MAX_SKEW_SECONDS = 300;

/**
 * Verify an inbound signed request. `lookupKey` maps a keyid to a base64
 * public key, so the caller controls key storage.
 */
export function verifyRequest(opts: {
  method: string;
  targetUri: string;
  rawBody: string | Buffer;
  headers: Record<string, string | string[] | undefined>;
  lookupKey: (keyid: string) => string | undefined;
  maxSkewSeconds?: number;
}): VerifyResult {
  const h = (name: string): string | undefined => {
    const v = opts.headers[name] ?? opts.headers[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  };

  const sigInput = h("signature-input");
  const sigHeader = h("signature");
  const digestHeader = h("content-digest");
  if (!sigInput || !sigHeader) return { ok: false, reason: "missing signature headers" };
  if (!digestHeader) return { ok: false, reason: "missing content-digest" };

  if (contentDigest(opts.rawBody) !== digestHeader) {
    return { ok: false, reason: "content-digest mismatch" };
  }

  const label = sigInput.split("=")[0];
  const params = sigInput.slice(label.length + 1);
  const createdMatch = /created=(\d+)/.exec(params);
  const keyidMatch = /keyid="([^"]+)"/.exec(params);
  if (!createdMatch || !keyidMatch) return { ok: false, reason: "malformed signature-input" };

  const created = Number(createdMatch[1]);
  const skew = Math.abs(Math.floor(Date.now() / 1000) - created);
  if (skew > (opts.maxSkewSeconds ?? MAX_SKEW_SECONDS)) {
    return { ok: false, reason: "created timestamp outside acceptable range" };
  }

  const keyid = keyidMatch[1];
  const publicKey = opts.lookupKey(keyid);
  if (!publicKey) return { ok: false, reason: "unknown keyid" };

  const covered = [...params.matchAll(/"([^"]+)"/g)]
    .map((m) => m[1])
    .filter((c) => c !== keyid);
  const values: Record<string, string> = {
    "@method": opts.method.toUpperCase(),
    "@target-uri": opts.targetUri,
    "content-digest": digestHeader,
  };
  for (const c of covered) {
    if (!(c in values)) return { ok: false, reason: `uncovered component ${c}` };
  }

  const base = signatureBase(values, covered, params);
  const sigB64 = /:([^:]+):/.exec(sigHeader)?.[1];
  if (!sigB64) return { ok: false, reason: "malformed signature" };

  const ok = crypto.verify(
    null,
    Buffer.from(base),
    importPublicKey(publicKey),
    Buffer.from(sigB64, "base64"),
  );
  return ok ? { ok: true, keyid } : { ok: false, reason: "signature verification failed" };
}
