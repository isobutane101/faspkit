import crypto from "node:crypto";
import express from "express";

/**
 * Fetching objects from the wider fediverse.
 *
 * `data_sharing` only ever hands a FASP object *URIs*; it must retrieve the
 * content itself. Those requests have to be signed, and the spec requires
 * supporting both signature standards in circulation:
 *
 * - RFC 9421 HTTP Message Signatures (the modern one)
 * - draft-cavage-http-signatures-12 (what most deployed fediverse software
 *   still verifies)
 *
 * The prescribed strategy is "double-knocking": try RFC 9421, and on 401/403
 * retry with cavage, caching per host which one worked.
 *
 * The key used here is NOT one of the per-server FASP keys. The spec mandates a
 * separate keypair for acting as a server actor, and because cavage is defined
 * around RSA and deployed verifiers expect `publicKeyPem`, this one is RSA
 * rather than Ed25519.
 */

export const AS_PROFILE = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"';
const ACCEPT = `${AS_PROFILE}, application/activity+json`;

export interface ActorKeypair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function generateActorKeypair(modulusLength = 2048): ActorKeypair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength });
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export interface ActorIdentity {
  /** Base URL of this FASP, e.g. https://fasp.example.com */
  baseUrl: string;
  /** Username used for WebFinger lookups. */
  preferredUsername: string;
  keypair: ActorKeypair;
}

export const actorId = (id: ActorIdentity) => `${id.baseUrl.replace(/\/$/, "")}/actor`;
export const actorKeyId = (id: ActorIdentity) => `${actorId(id)}#main-key`;

/** The minimal actor document the spec requires, as an `Application` actor. */
export function actorDocument(id: ActorIdentity): Record<string, unknown> {
  const self = actorId(id);
  return {
    "@context": [
      "https://www.w3.org/ns/activitystreams",
      "https://w3id.org/security/v1",
    ],
    id: self,
    type: "Application",
    inbox: `${self}/inbox`,
    outbox: `${self}/outbox`,
    preferredUsername: id.preferredUsername,
    publicKey: {
      id: actorKeyId(id),
      owner: self,
      publicKeyPem: id.keypair.publicKeyPem,
    },
  };
}

export function webfingerDocument(id: ActorIdentity): Record<string, unknown> {
  const host = new URL(id.baseUrl).host;
  return {
    subject: `acct:${id.preferredUsername}@${host}`,
    aliases: [actorId(id)],
    links: [{ rel: "self", type: "application/activity+json", href: actorId(id) }],
  };
}

/**
 * Public, unsigned routes the wider fediverse needs in order to verify us.
 *
 * These sit outside the signature middleware on purpose: they are read by
 * arbitrary servers that have no FASP relationship with us. They also mount at
 * the origin rather than under a FASP base path, because the spec states the
 * actor URI's path MUST be `/actor`.
 */
export function actorRoutes(id: ActorIdentity): express.Router {
  const router = express.Router();

  router.get("/actor", (_req, res) => {
    res.type("application/activity+json").json(actorDocument(id));
  });

  router.get("/.well-known/webfinger", (req, res) => {
    const resource = String(req.query.resource ?? "");
    const expected = `acct:${id.preferredUsername}@${new URL(id.baseUrl).host}`;
    if (resource !== expected) return res.status(404).json({ error: "not found" });
    res.type("application/jrd+json").json(webfingerDocument(id));
  });

  // A minimal inbox may accept and discard; a minimal outbox may be empty.
  router.post("/actor/inbox", (_req, res) => res.status(202).end());
  router.get("/actor/outbox", (_req, res) => {
    res.type("application/activity+json").json({
      "@context": "https://www.w3.org/ns/activitystreams",
      id: `${actorId(id)}/outbox`,
      type: "OrderedCollection",
      totalItems: 0,
      orderedItems: [],
    });
  });

  return router;
}

// ---------------------------------------------------------------------------
// Request signing
// ---------------------------------------------------------------------------

export type SignatureStyle = "rfc9421" | "cavage";

function sha256Base64(body: string): string {
  return crypto.createHash("sha256").update(body).digest("base64");
}

/** draft-cavage-http-signatures-12, as deployed fediverse software expects. */
export function signCavage(opts: {
  method: string;
  url: string;
  identity: ActorIdentity;
  date: string;
  body?: string;
}): Record<string, string> {
  const url = new URL(opts.url);
  const requestTarget = `${opts.method.toLowerCase()} ${url.pathname}${url.search}`;

  const parts: [string, string][] = [
    ["(request-target)", requestTarget],
    ["host", url.host],
    ["date", opts.date],
  ];
  if (opts.body !== undefined) parts.push(["digest", `SHA-256=${sha256Base64(opts.body)}`]);

  const base = parts.map(([k, v]) => `${k}: ${v}`).join("\n");
  const signature = crypto
    .sign("sha256", Buffer.from(base), opts.identity.keypair.privateKeyPem)
    .toString("base64");

  const headers: Record<string, string> = {
    date: opts.date,
    host: url.host,
    signature:
      `keyId="${actorKeyId(opts.identity)}",` +
      `algorithm="rsa-sha256",` +
      `headers="${parts.map(([k]) => k).join(" ")}",` +
      `signature="${signature}"`,
  };
  if (opts.body !== undefined) headers.digest = `SHA-256=${sha256Base64(opts.body)}`;
  return headers;
}

/** RFC 9421 with an RSA key (`rsa-v1_5-sha256`), for servers that support it. */
export function signRfc9421(opts: {
  method: string;
  url: string;
  identity: ActorIdentity;
  created: number;
}): Record<string, string> {
  const components = ["@method", "@target-uri"];
  const params = `("${components.join('" "')}");created=${opts.created};keyid="${actorKeyId(opts.identity)}";alg="rsa-v1_5-sha256"`;
  const base = [
    `"@method": ${opts.method.toUpperCase()}`,
    `"@target-uri": ${opts.url}`,
    `"@signature-params": ${params}`,
  ].join("\n");
  const signature = crypto
    .sign("sha256", Buffer.from(base), opts.identity.keypair.privateKeyPem)
    .toString("base64");
  return {
    "signature-input": `sig1=${params}`,
    signature: `sig1=:${signature}:`,
  };
}

// ---------------------------------------------------------------------------
// Double-knocking
// ---------------------------------------------------------------------------

/**
 * Remembers which signature style each host accepted.
 *
 * The spec requires that a host recorded as cavage-only be retried with the
 * modern standard periodically, so entries expire rather than pinning a host to
 * the legacy path forever.
 */
export interface StyleCache {
  get(host: string): SignatureStyle | undefined;
  set(host: string, style: SignatureStyle): void;
}

export function createStyleCache(ttlMs = 7 * 24 * 60 * 60 * 1000): StyleCache {
  const entries = new Map<string, { style: SignatureStyle; expires: number }>();
  return {
    get(host) {
      const hit = entries.get(host);
      if (!hit) return undefined;
      if (hit.expires <= Date.now()) {
        entries.delete(host);
        return undefined;
      }
      return hit.style;
    },
    set(host, style) {
      // Only the legacy answer needs re-checking; RFC 9421 support is durable.
      const ttl = style === "cavage" ? ttlMs : ttlMs * 4;
      entries.set(host, { style, expires: Date.now() + ttl });
    },
  };
}

export interface FetchObjectOptions {
  identity: ActorIdentity;
  styleCache?: StyleCache;
  timeoutMs?: number;
  /** Injection point for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export interface FetchedObject {
  uri: string;
  ok: boolean;
  status?: number;
  style?: SignatureStyle;
  document?: Record<string, unknown>;
  error?: string;
}

async function attempt(
  uri: string,
  style: SignatureStyle,
  opts: FetchObjectOptions,
): Promise<globalThis.Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const headers: Record<string, string> = { accept: ACCEPT };
  if (style === "cavage") {
    Object.assign(headers, signCavage({ method: "GET", url: uri, identity: opts.identity, date: new Date().toUTCString() }));
  } else {
    Object.assign(headers, signRfc9421({ method: "GET", url: uri, identity: opts.identity, created: Math.floor(Date.now() / 1000) }));
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    return (await doFetch(uri, { headers, signal: controller.signal, redirect: "follow" })) as globalThis.Response;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Retrieve one object, double-knocking as the spec prescribes: RFC 9421 first,
 * then cavage if the server answers 401 or 403.
 */
export async function fetchObject(uri: string, opts: FetchObjectOptions): Promise<FetchedObject> {
  let host: string;
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return { uri, ok: false, error: `unsupported scheme ${parsed.protocol}` };
    }
    host = parsed.host;
  } catch {
    return { uri, ok: false, error: "malformed object URI" };
  }

  // Try the remembered style first, but keep the other one as a fallback: a
  // cached answer can go stale when a server upgrades, downgrades, or rotates
  // what it accepts, and giving up on a single 401 would strand us there.
  const cached = opts.styleCache?.get(host);
  const order: SignatureStyle[] = cached
    ? [cached, ...(["rfc9421", "cavage"] as SignatureStyle[]).filter((s) => s !== cached)]
    : ["rfc9421", "cavage"];

  let last: { status?: number; error?: string } = {};
  for (let i = 0; i < order.length; i++) {
    const style = order[i];
    const isLast = i === order.length - 1;

    let res: globalThis.Response;
    try {
      res = await attempt(uri, style, opts);
    } catch (err) {
      last = { error: String(err) };
      continue;
    }

    // Only an auth rejection justifies knocking again with the other style.
    if ((res.status === 401 || res.status === 403) && !isLast) {
      last = { status: res.status };
      continue;
    }

    if (!res.ok) return { uri, ok: false, status: res.status, style };

    opts.styleCache?.set(host, style);
    try {
      const document = (await res.json()) as Record<string, unknown>;
      return { uri, ok: true, status: res.status, style, document };
    } catch {
      return { uri, ok: false, status: res.status, style, error: "response was not valid JSON" };
    }
  }

  return { uri, ok: false, status: last.status, error: last.error ?? "all signature styles rejected" };
}
