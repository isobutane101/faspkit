import crypto from "node:crypto";

/**
 * RFC 9530 Content-Digest (SHA-256) and RFC 9421 HTTP Message Signatures
 * using "EdDSA Using Curve edwards25519", as required by the FASP
 * general specification (general/v0.1/protocol_basics.md).
 *
 * This module is deliberately free of Express and filesystem imports so it
 * stays unit-testable and reusable on its own.
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

/** Components the FASP spec mandates for requests and for responses. */
export const REQUEST_COMPONENTS = ["@method", "@target-uri", "content-digest"] as const;
export const RESPONSE_COMPONENTS = ["@status", "content-digest"] as const;

/** RFC 9421 registry name for "EdDSA Using Curve edwards25519". */
const ALGORITHM = "ed25519";

/**
 * Build the RFC 9421 signature base. `paramsRaw` is the serialized
 * `@signature-params` value and MUST be used byte-for-byte as received when
 * verifying — the sender signed their own serialization, whitespace included.
 */
function signatureBase(
  components: Record<string, string>,
  order: readonly string[],
  paramsRaw: string,
): string {
  const lines = order.map((c) => `"${c}": ${components[c]}`);
  lines.push(`"@signature-params": ${paramsRaw}`);
  return lines.join("\n");
}

function paramsString(
  order: readonly string[],
  created: number,
  keyid: string,
  nonce?: string,
): string {
  const inner = order.map((c) => `"${c}"`).join(" ");
  const n = nonce === undefined ? "" : `;nonce="${nonce}"`;
  return `(${inner});created=${created};keyid="${keyid}"${n}`;
}

/** Exposed so tests can assert the exact base string a refactor would change. */
export function requestSignatureBase(opts: {
  method: string;
  targetUri: string;
  body: string | Buffer;
  keyid: string;
  created: number;
  nonce?: string;
}): string {
  const paramsRaw = paramsString(REQUEST_COMPONENTS, opts.created, opts.keyid, opts.nonce);
  return signatureBase(
    {
      "@method": opts.method.toUpperCase(),
      "@target-uri": opts.targetUri,
      "content-digest": contentDigest(opts.body),
    },
    REQUEST_COMPONENTS,
    paramsRaw,
  );
}

export function responseSignatureBase(opts: {
  status: number;
  body: string | Buffer;
  keyid: string;
  created: number;
  nonce?: string;
}): string {
  const paramsRaw = paramsString(RESPONSE_COMPONENTS, opts.created, opts.keyid, opts.nonce);
  return signatureBase(
    { "@status": String(opts.status), "content-digest": contentDigest(opts.body) },
    RESPONSE_COMPONENTS,
    paramsRaw,
  );
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
  label?: string;
  /**
   * Optional RFC 9421 nonce. Ed25519 is deterministic and `created` has
   * second granularity, so two identical requests sent within the same second
   * produce byte-identical signatures and a replay-protecting verifier cannot
   * tell them apart. Set a nonce when repeating a request is legitimate.
   */
  nonce?: string;
}): SignedHeaders {
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const label = opts.label ?? "sig1";
  const base = requestSignatureBase({ ...opts, created });
  const sig = crypto.sign(null, Buffer.from(base), importPrivateKey(opts.privateKey));
  return {
    "content-digest": contentDigest(opts.body),
    "signature-input": `${label}=${paramsString(REQUEST_COMPONENTS, created, opts.keyid, opts.nonce)}`,
    signature: `${label}=:${sig.toString("base64")}:`,
  };
}

export function signResponse(opts: {
  status: number;
  body: string;
  keyid: string;
  privateKey: string;
  created?: number;
  label?: string;
  nonce?: string;
}): SignedHeaders {
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const label = opts.label ?? "sig1";
  const base = responseSignatureBase({ ...opts, created });
  const sig = crypto.sign(null, Buffer.from(base), importPrivateKey(opts.privateKey));
  return {
    "content-digest": contentDigest(opts.body),
    "signature-input": `${label}=${paramsString(RESPONSE_COMPONENTS, created, opts.keyid, opts.nonce)}`,
    signature: `${label}=:${sig.toString("base64")}:`,
  };
}

// ---------------------------------------------------------------------------
// Structured-field parsing
//
// `Signature-Input` and `Signature` are RFC 8941 dictionaries. A sender may use
// any label, may send several signatures in one header, and may order the
// parameters however it likes. Naive regex parsing works against our own
// signer and fails against everyone else's, so parse properly.
// ---------------------------------------------------------------------------

/** Split a dictionary on top-level commas, ignoring those inside quotes or parens. */
function splitDictionary(input: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let inQuotes = false;
  let start = 0;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (inQuotes) {
      if (ch === "\\") i++;
      else if (ch === '"') inQuotes = false;
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) {
      out.push(input.slice(start, i));
      start = i + 1;
    }
  }
  out.push(input.slice(start));
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Split a member's parameters on top-level semicolons. */
function splitParams(input: string): string[] {
  const out: string[] = [];
  let inQuotes = false;
  let start = 0;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (inQuotes) {
      if (ch === "\\") i++;
      else if (ch === '"') inQuotes = false;
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === ";") {
      out.push(input.slice(start, i));
      start = i + 1;
    }
  }
  out.push(input.slice(start));
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Split "label=value" on the first top-level '='. */
function splitMember(member: string): { label: string; value: string } | undefined {
  const eq = member.indexOf("=");
  if (eq <= 0) return undefined;
  return { label: member.slice(0, eq).trim(), value: member.slice(eq + 1).trim() };
}

interface ParsedInput {
  label: string;
  /** Verbatim `@signature-params` value — used byte-for-byte in the base. */
  paramsRaw: string;
  covered: string[];
  params: Record<string, string>;
}

function parseSignatureInput(header: string): ParsedInput[] {
  const out: ParsedInput[] = [];
  for (const member of splitDictionary(header)) {
    const split = splitMember(member);
    if (!split) continue;
    const close = split.value.indexOf(")");
    if (!split.value.startsWith("(") || close === -1) continue;

    const inner = split.value.slice(1, close);
    const covered = [...inner.matchAll(/"([^"]*)"/g)].map((m) => m[1]);

    const params: Record<string, string> = {};
    for (const p of splitParams(split.value.slice(close + 1))) {
      const kv = splitMember(p);
      if (!kv) continue;
      params[kv.label.toLowerCase()] = kv.value.replace(/^"|"$/g, "");
    }
    out.push({ label: split.label, paramsRaw: split.value, covered, params });
  }
  return out;
}

/** Parse the `Signature` dictionary into label -> raw signature bytes. */
function parseSignatures(header: string): Record<string, Buffer> {
  const out: Record<string, Buffer> = {};
  for (const member of splitDictionary(header)) {
    const split = splitMember(member);
    if (!split) continue;
    const m = /^:([A-Za-z0-9+/=]*):$/.exec(split.value);
    if (!m) continue;
    out[split.label] = Buffer.from(m[1], "base64");
  }
  return out;
}

/**
 * The keyids a `Signature-Input` header claims, without verifying anything.
 *
 * Verification needs the public key up front, but a store that reaches a
 * database cannot be consulted from inside the synchronous verify path. So the
 * caller extracts the claimed keyids, resolves them however it likes, and hands
 * the result back as `lookupKey`. Nothing here is trusted: an attacker controls
 * these strings, and a wrong or unknown one simply fails to verify.
 */
export function signatureKeyids(signatureInput: string | undefined): string[] {
  if (!signatureInput) return [];
  const seen = new Set<string>();
  for (const cand of parseSignatureInput(signatureInput)) {
    if (cand.params.keyid) seen.add(cand.params.keyid);
  }
  return [...seen];
}

/** RFC 8941 field-value canonicalization: trim OWS, join repeats with ", ". */
function canonicalHeader(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined;
  return (Array.isArray(value) ? value : [value]).map((v) => v.trim()).join(", ");
}

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

/**
 * Timestamp skew alone does not prevent replay *within* the window: a captured
 * request can be resent freely for as long as its `created` stays fresh. Track
 * (keyid, signature) pairs for exactly that window and reject repeats.
 */
export interface ReplayGuard {
  /** Returns true if this pair has been seen before. Records it either way. */
  seen(keyid: string, signature: string): boolean;
  size(): number;
}

export function createReplayGuard(ttlSeconds = 300, maxEntries = 10_000): ReplayGuard {
  const entries = new Map<string, number>();

  function evict(nowMs: number) {
    for (const [k, expiry] of entries) {
      if (expiry > nowMs) break; // Map preserves insertion order; TTL is constant.
      entries.delete(k);
    }
    while (entries.size > maxEntries) {
      const oldest = entries.keys().next();
      if (oldest.done) break;
      entries.delete(oldest.value);
    }
  }

  return {
    seen(keyid, signature) {
      const now = Date.now();
      evict(now);
      const key = `${keyid} ${signature}`;
      if (entries.has(key)) return true;
      entries.set(key, now + ttlSeconds * 1000);
      return false;
    },
    size: () => entries.size,
  };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export interface VerifyResult {
  ok: boolean;
  keyid?: string;
  label?: string;
  reason?: string;
}

const MAX_SKEW_SECONDS = 300;

interface VerifyCommon {
  headers: Record<string, string | string[] | undefined>;
  rawBody: string | Buffer;
  /**
   * Resolve a keyid to the base64 public key(s) that may have produced it.
   * Returning several accepts any of them, which is what lets a key rotation
   * overlap: the previous key keeps verifying until it expires.
   */
  lookupKey: (keyid: string) => string | string[] | undefined;
  maxSkewSeconds?: number;
  replayGuard?: ReplayGuard;
}

function verify(
  opts: VerifyCommon,
  required: readonly string[],
  derived: Record<string, string>,
): VerifyResult {
  const h = (name: string): string | string[] | undefined =>
    opts.headers[name] ?? opts.headers[name.toLowerCase()];
  const one = (name: string): string | undefined => {
    const v = h(name);
    return Array.isArray(v) ? v[0] : v;
  };

  const sigInput = one("signature-input");
  const sigHeader = one("signature");
  const digestHeader = canonicalHeader(h("content-digest"));
  if (!sigInput || !sigHeader) return { ok: false, reason: "missing signature headers" };
  if (!digestHeader) return { ok: false, reason: "missing content-digest" };

  if (contentDigest(opts.rawBody) !== digestHeader) {
    return { ok: false, reason: "content-digest mismatch" };
  }

  const candidates = parseSignatureInput(sigInput);
  if (candidates.length === 0) return { ok: false, reason: "malformed signature-input" };
  const signatures = parseSignatures(sigHeader);

  // A sender may offer several signatures. Accept the message if any one of
  // them covers what we require and verifies; report the last failure otherwise.
  let reason = "no acceptable signature";
  for (const cand of candidates) {
    const outcome = verifyCandidate(opts, required, derived, cand, signatures, digestHeader);
    if (outcome.ok) return outcome;
    reason = outcome.reason ?? reason;
  }
  return { ok: false, reason };
}

function verifyCandidate(
  opts: VerifyCommon,
  required: readonly string[],
  derived: Record<string, string>,
  cand: ParsedInput,
  signatures: Record<string, Buffer>,
  digestHeader: string,
): VerifyResult {
  const fail = (reason: string): VerifyResult => ({ ok: false, label: cand.label, reason });

  const sig = signatures[cand.label];
  if (!sig) return fail(`no signature for label ${cand.label}`);

  if (cand.params.alg !== undefined && cand.params.alg.toLowerCase() !== ALGORITHM) {
    return fail(`unsupported alg ${cand.params.alg}`);
  }

  const createdRaw = cand.params.created;
  const keyid = cand.params.keyid;
  if (createdRaw === undefined || keyid === undefined) {
    return fail("signature-input missing required created/keyid params");
  }

  const created = Number(createdRaw);
  if (!Number.isFinite(created)) return fail("malformed created param");
  const skew = Math.abs(Math.floor(Date.now() / 1000) - created);
  if (skew > (opts.maxSkewSeconds ?? MAX_SKEW_SECONDS)) {
    return fail("created timestamp outside acceptable range");
  }

  const expires = cand.params.expires;
  if (expires !== undefined && Number(expires) < Math.floor(Date.now() / 1000)) {
    return fail("signature expired");
  }

  // Every component the spec mandates must actually be covered, or the
  // signature protects nothing that matters.
  for (const r of required) {
    if (!cand.covered.includes(r)) return fail(`signature does not cover ${r}`);
  }

  const values: Record<string, string> = { ...derived, "content-digest": digestHeader };
  for (const c of cand.covered) {
    if (c in values) continue;
    if (c.startsWith("@")) return fail(`unsupported derived component ${c}`);
    const v = canonicalHeader(opts.headers[c] ?? opts.headers[c.toLowerCase()]);
    if (v === undefined) return fail(`covered header ${c} not present`);
    values[c] = v;
  }

  const resolved = opts.lookupKey(keyid);
  const publicKeys = (Array.isArray(resolved) ? resolved : resolved === undefined ? [] : [resolved])
    .filter((k) => typeof k === "string" && k.length > 0);
  if (publicKeys.length === 0) return fail("unknown keyid");

  const base = signatureBase(values, cand.covered, cand.paramsRaw);
  const ok = publicKeys.some((key) => {
    try {
      return crypto.verify(null, Buffer.from(base), importPublicKey(key), sig);
    } catch {
      return false;
    }
  });
  if (!ok) return fail("signature verification failed");

  // Only consume replay budget once the signature is known good, so garbage
  // traffic cannot evict legitimate entries.
  if (opts.replayGuard?.seen(keyid, sig.toString("base64"))) {
    return fail("replayed signature");
  }

  return { ok: true, keyid, label: cand.label };
}

/**
 * Verify an inbound signed request. `lookupKey` maps a keyid to a base64
 * public key, so the caller controls key storage.
 */
export function verifyRequest(
  opts: VerifyCommon & { method: string; targetUri: string },
): VerifyResult {
  let url: URL;
  try {
    url = new URL(opts.targetUri);
  } catch {
    return { ok: false, reason: "malformed target-uri" };
  }
  return verify(opts, REQUEST_COMPONENTS, {
    "@method": opts.method.toUpperCase(),
    "@target-uri": opts.targetUri,
    "@authority": url.host,
    "@scheme": url.protocol.replace(/:$/, ""),
    "@path": url.pathname,
    "@query": url.search === "" ? "?" : url.search,
  });
}

/** Verify a signed response, which covers @status instead of @method/@target-uri. */
export function verifyResponse(opts: VerifyCommon & { status: number }): VerifyResult {
  return verify(opts, RESPONSE_COMPONENTS, { "@status": String(opts.status) });
}
