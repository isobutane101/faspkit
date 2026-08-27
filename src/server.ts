import express, { Request, Response as ExpressResponse, NextFunction } from "express";
import {
  signRequest,
  signResponse,
  verifyRequest,
  keyFingerprint,
  createReplayGuard,
  signatureKeyids,
  ReplayGuard,
} from "./crypto.js";
import {
  FaspStore,
  defaultStore,
  acceptableTheirKeys,
  ServerRecord,
} from "./store.js";

export interface Capability {
  id: string;
  version: string;
  register?: (app: express.Router) => void;
}

export interface FaspOptions {
  name: string;
  /**
   * Public base URL of this FASP, exactly as fediverse servers will reach it.
   * If it contains path segments, all API paths are prefixed accordingly and
   * `@target-uri` is reconstructed to match — see general/v0.1/protocol_basics.
   */
  baseUrl: string;
  privacyPolicy?: { url: string; language: string }[];
  contactEmail?: string;
  fediverseAccount?: string;
  signInUrl?: string;
  capabilities: Capability[];
  /** Clock drift tolerated on inbound `created` params. Default 300s. */
  maxSkewSeconds?: number;
  /** Shared across middleware instances so replays are caught process-wide. */
  replayGuard?: ReplayGuard;
  /** Persistence. Defaults to the bundled JSON store. */
  store?: FaspStore;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      faspServer?: ServerRecord;
    }
  }
}

/**
 * Split a configured base URL into the origin we rebuild `@target-uri` from
 * and the path prefix every route mounts under.
 */
export function splitBaseUrl(baseUrl: string): { origin: string; basePath: string } {
  const url = new URL(baseUrl);
  const basePath = url.pathname.replace(/\/+$/, "");
  return { origin: url.origin, basePath };
}

// ---------------------------------------------------------------------------
// Outbound calls
// ---------------------------------------------------------------------------

export interface CallOptions {
  /** Per-attempt timeout. A FASP must never hang on a slow instance. */
  timeoutMs?: number;
  /** Retries after the first attempt. Default 3. */
  maxRetries?: number;
  /** Upper bound on any single backoff wait, including `Retry-After`. */
  maxDelayMs?: number;
}

const DEFAULT_CALL: Required<CallOptions> = {
  timeoutMs: 10_000,
  maxRetries: 3,
  maxDelayMs: 30_000,
};

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** RFC 9110 Retry-After: delta-seconds or an HTTP-date. */
function retryAfterMs(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header.trim());
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(header);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - Date.now());
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<globalThis.Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return (await fetch(url, { ...init, signal: controller.signal })) as globalThis.Response;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Make a signed request to a fediverse server, honouring `429` + `Retry-After`
 * with bounded exponential backoff. Each attempt is re-signed because the
 * `created` parameter — and therefore the signature — changes.
 */
export async function callServer(
  rec: ServerRecord,
  method: string,
  pathname: string,
  body?: unknown,
  options: CallOptions = {},
): Promise<globalThis.Response> {
  const cfg = { ...DEFAULT_CALL, ...options };
  const targetUri = `${rec.baseUrl}${pathname}`;
  const payload = body === undefined ? "" : JSON.stringify(body);

  let nextDelayMs: number | undefined;
  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    if (attempt > 0) {
      await delay(nextDelayMs ?? Math.min(cfg.maxDelayMs, 250 * 2 ** (attempt - 1)));
      nextDelayMs = undefined;
    }

    const headers = signRequest({
      method,
      targetUri,
      body: payload,
      keyid: rec.serverId,
      privateKey: rec.ourPrivateKey,
    });

    let res: globalThis.Response;
    try {
      res = await fetchWithTimeout(
        targetUri,
        {
          method,
          headers: {
            "content-type": "application/json",
            "content-digest": headers["content-digest"],
            "signature-input": headers["signature-input"],
            signature: headers.signature,
          },
          body: payload === "" ? undefined : payload,
        },
        cfg.timeoutMs,
      );
    } catch (err) {
      // Network failure or timeout: back off and retry.
      if (attempt === cfg.maxRetries) throw err;
      continue;
    }

    if (res.status === 429 && attempt < cfg.maxRetries) {
      // Respect the server-requested wait, capped so a hostile or broken
      // Retry-After cannot park this call for hours.
      const wait = retryAfterMs(res.headers.get("retry-after"));
      nextDelayMs = wait === undefined ? undefined : Math.min(wait, cfg.maxDelayMs);
      continue;
    }
    return res;
  }
  // Unreachable: the final attempt either returns or throws above.
  throw new Error("request failed after retries");
}

/** Discover a fediverse server's FASP base URL via .well-known/nodeinfo. */
export async function discoverFaspBaseUrl(
  serverUrl: string,
  options: CallOptions = {},
): Promise<string> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_CALL.timeoutMs;
  const wk = await fetchWithTimeout(
    `${serverUrl.replace(/\/$/, "")}/.well-known/nodeinfo`,
    {},
    timeoutMs,
  );
  if (!wk.ok) throw new Error(`nodeinfo discovery failed: ${wk.status}`);
  const links = (await wk.json()) as { links?: { rel: string; href: string }[] };
  // Prefer the newest advertised nodeinfo schema; fall back to the last link.
  const schemas = (links.links ?? []).filter((l) => l.rel?.includes("nodeinfo"));
  const href = (schemas.length ? schemas : (links.links ?? [])).at(-1)?.href;
  if (!href) throw new Error("no nodeinfo link found");
  const ni = await fetchWithTimeout(href, {}, timeoutMs);
  if (!ni.ok) throw new Error(`nodeinfo fetch failed: ${ni.status}`);
  const doc = (await ni.json()) as { metadata?: { faspBaseUrl?: string } };
  const base = doc.metadata?.faspBaseUrl;
  if (!base) throw new Error("server does not advertise faspBaseUrl — FASP not supported");
  return base.replace(/\/$/, "");
}

/** Start the registration handshake: POST /registration to the server. */
export async function registerWithServer(
  opts: FaspOptions,
  serverUrl: string,
): Promise<{ record: ServerRecord; fingerprint: string; completionUri: string }> {
  const store = opts.store ?? defaultStore;
  const baseUrl = await discoverFaspBaseUrl(serverUrl);
  const rec = await store.createServer(serverUrl, baseUrl);

  const res = await callServer(rec, "POST", "/registration", {
    name: opts.name,
    baseUrl: opts.baseUrl,
    serverId: rec.serverId,
    publicKey: rec.ourPublicKey,
  });

  if (res.status !== 201) {
    throw new Error(`registration rejected: HTTP ${res.status} ${await res.text()}`);
  }
  const data = (await res.json()) as {
    faspId: string;
    publicKey: string;
    registrationCompletionUri: string;
  };

  const updated = await store.updateServer(rec.serverId, {
    faspId: data.faspId,
    theirPublicKey: data.publicKey,
    status: "active",
  });

  return {
    record: updated,
    fingerprint: keyFingerprint(rec.ourPublicKey),
    completionUri: data.registrationCompletionUri,
  };
}

// ---------------------------------------------------------------------------
// Inbound middleware
// ---------------------------------------------------------------------------

/**
 * Express middleware enforcing RFC 9421 signatures on inbound requests.
 *
 * `@target-uri` is rebuilt from the configured origin plus `req.originalUrl`,
 * which already carries any mount prefix and the query string. Concatenating
 * the whole configured base URL instead would double-count its path segments
 * and drop the query, and the signature would never verify.
 */
export function requireSignature(opts: FaspOptions) {
  const { origin } = splitBaseUrl(opts.baseUrl);
  const replayGuard = opts.replayGuard ?? createReplayGuard(opts.maxSkewSeconds ?? 300);
  const store = opts.store ?? defaultStore;

  return async (req: Request, res: ExpressResponse, next: NextFunction) => {
    const raw = (req as Request & { rawBody?: string }).rawBody ?? "";
    const header = req.headers["signature-input"];

    // The store may be remote, so resolve the claimed keyids up front rather
    // than from inside the synchronous verify path. These strings are attacker
    // controlled and are trusted for nothing: an unknown one simply resolves to
    // no key and fails to verify.
    const records = new Map<string, ServerRecord>();
    for (const keyid of signatureKeyids(Array.isArray(header) ? header[0] : header)) {
      const rec = await store.serverByFaspId(keyid);
      if (rec) records.set(keyid, rec);
    }

    const result = verifyRequest({
      method: req.method,
      targetUri: `${origin}${req.originalUrl}`,
      rawBody: raw,
      headers: req.headers as Record<string, string | string[] | undefined>,
      // Both the current and an unexpired previous key are accepted, so a
      // rotation does not reject requests that were already in flight.
      lookupKey: (keyid) => {
        const rec = records.get(keyid);
        return rec ? acceptableTheirKeys(rec) : undefined;
      },
      maxSkewSeconds: opts.maxSkewSeconds,
      replayGuard,
    });
    if (!result.ok) {
      return res.status(401).json({ error: "unauthorized", reason: result.reason });
    }
    const rec = records.get(result.keyid!);
    if (!rec) {
      return res.status(401).json({ error: "unauthorized", reason: "unknown server" });
    }
    req.faspServer = rec;
    next();
  };
}

/**
 * Send a signed JSON response as the spec requires (@status + content-digest).
 *
 * Throws rather than falling back to an unsigned response: a silently unsigned
 * reply looks fine in testing and is rejected by every conforming instance.
 */
export function sendSigned(
  req: Request,
  res: ExpressResponse,
  status: number,
  body: unknown,
) {
  const rec = req.faspServer;
  if (!rec) {
    throw new Error(
      "sendSigned called without req.faspServer — the route must sit behind requireSignature()",
    );
  }
  const payload = body === undefined ? "" : JSON.stringify(body);
  const headers = signResponse({
    status,
    body: payload,
    keyid: rec.serverId,
    privateKey: rec.ourPrivateKey,
  });
  res.set({
    "content-digest": headers["content-digest"],
    "signature-input": headers["signature-input"],
    signature: headers.signature,
  });
  res.status(status).type("application/json").send(payload);
}

const GUARDED_METHODS = ["get", "post", "put", "patch", "delete", "all"] as const;

/**
 * A Router that attaches the signature guard to each route registered on it,
 * rather than to the router as a whole.
 *
 * `router.use(guard)` would look equivalent and is subtly wrong: router-level
 * middleware runs for every request that reaches the router, including ones
 * that match none of its routes. Because this router is mounted at the FASP
 * root, that made `/health` require a signature and caused any route added
 * after `createFasp` returned — an ActivityPub actor, say — to be answered with
 * 401 before it could ever be matched.
 *
 * Capabilities register routes with the usual verb methods, so guarding those
 * is enough. A capability that calls `.use()` directly is not guarded, which is
 * why capabilities should register concrete routes.
 */
function createGuardedRouter(guard: express.RequestHandler): express.Router {
  const router = express.Router();
  return new Proxy(router, {
    get(target, prop, receiver) {
      if (typeof prop === "string" && (GUARDED_METHODS as readonly string[]).includes(prop)) {
        return (path: string, ...handlers: express.RequestHandler[]) =>
          (target as unknown as Record<string, (...a: unknown[]) => unknown>)[prop](path, guard, ...handlers);
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

export function createFasp(opts: FaspOptions) {
  const { basePath } = splitBaseUrl(opts.baseUrl);
  const app = express();
  const routes = express.Router();

  // Capture the raw body — signature verification needs the exact bytes.
  app.use(
    express.json({
      verify: (req, _res, buf) => {
        (req as Request & { rawBody?: string }).rawBody = buf.toString("utf8");
      },
    }),
  );

  routes.get("/provider_info", (_req, res) => {
    res.json({
      name: opts.name,
      privacyPolicy: opts.privacyPolicy ?? [],
      capabilities: opts.capabilities.map((c) => ({ id: c.id, version: c.version })),
      ...(opts.signInUrl ? { signInUrl: opts.signInUrl } : {}),
      ...(opts.contactEmail ? { contactEmail: opts.contactEmail } : {}),
      ...(opts.fediverseAccount ? { fediverseAccount: opts.fediverseAccount } : {}),
    });
  });

  // Admin-facing registration form target: kicks off the handshake.
  routes.post("/register", async (req, res) => {
    try {
      const { serverUrl } = req.body ?? {};
      if (!serverUrl) return res.status(400).json({ error: "serverUrl required" });
      const result = await registerWithServer(opts, serverUrl);
      res.status(201).json({
        serverId: result.record.serverId,
        fingerprint: result.fingerprint,
        registrationCompletionUri: result.completionUri,
        message:
          "Compare this fingerprint in your server's admin UI, then accept the registration.",
      });
    } catch (err) {
      res.status(400).json({ error: String(err) });
    }
  });

  const guarded = createGuardedRouter(requireSignature(opts));
  for (const cap of opts.capabilities) cap.register?.(guarded);
  routes.use(guarded);

  routes.get("/health", async (_req, res) => {
    const servers = await (opts.store ?? defaultStore).allServers();
    res.json({ ok: true, servers: servers.length });
  });

  app.use(basePath === "" ? "/" : basePath, routes);
  return app;
}

/** The `debug` capability from debug/v0.1 — proves the handshake round-trips. */
export function debugCapability(): Capability {
  return {
    id: "callback",
    version: "0.1",
    register(router) {
      router.post("/debug/v0/callback/logs", async (req, res) => {
        const rec = req.faspServer!;
        const entry = {
          at: new Date().toISOString(),
          ip: req.ip,
          body: req.body ?? null,
          serverId: rec.serverId,
        };
        console.log("[debug/callback] inbound:", JSON.stringify(entry));

        // Spec: the provider must call back to the instance.
        try {
          const r = await callServer(
            rec,
            "POST",
            "/debug/v0/callback/responses",
            req.body ?? undefined,
          );
          console.log("[debug/callback] callback status:", r.status);
        } catch (err) {
          console.error("[debug/callback] callback failed:", err);
        }
        // Responses MUST be signed too (@status + content-digest).
        sendSigned(req, res, 201, undefined);
      });
    },
  };
}

export { defaultStore };
