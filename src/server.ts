import express, { Request, Response as ExpressResponse, NextFunction } from "express";
import {
  signRequest,
  signResponse,
  verifyRequest,
  keyFingerprint,
} from "./crypto.js";
import {
  createServer,
  updateServer,
  getServer,
  allServers,
  lookupKeyByFaspId,
  serverByFaspId,
  ServerRecord,
} from "./store.js";

export interface Capability {
  id: string;
  version: string;
  register?: (app: express.Router) => void;
}

export interface FaspOptions {
  name: string;
  baseUrl: string;
  privacyPolicy?: { url: string; language: string }[];
  contactEmail?: string;
  fediverseAccount?: string;
  signInUrl?: string;
  capabilities: Capability[];
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      faspServer?: ServerRecord;
    }
  }
}

/** Discover a fediverse server's FASP base URL via .well-known/nodeinfo. */
export async function discoverFaspBaseUrl(serverUrl: string): Promise<string> {
  const wk = await fetch(`${serverUrl.replace(/\/$/, "")}/.well-known/nodeinfo`);
  if (!wk.ok) throw new Error(`nodeinfo discovery failed: ${wk.status}`);
  const links = (await wk.json()) as { links: { rel: string; href: string }[] };
  const href = links.links?.[links.links.length - 1]?.href;
  if (!href) throw new Error("no nodeinfo link found");
  const ni = await fetch(href);
  if (!ni.ok) throw new Error(`nodeinfo fetch failed: ${ni.status}`);
  const doc = (await ni.json()) as { metadata?: { faspBaseUrl?: string } };
  const base = doc.metadata?.faspBaseUrl;
  if (!base) throw new Error("server does not advertise faspBaseUrl — FASP not supported");
  return base.replace(/\/$/, "");
}

/** Make a signed request to a fediverse server. */
export async function callServer(
  rec: ServerRecord,
  method: string,
  pathname: string,
  body?: unknown,
): Promise<globalThis.Response> {
  const targetUri = `${rec.baseUrl}${pathname}`;
  const payload = body === undefined ? "" : JSON.stringify(body);
  const headers = signRequest({
    method,
    targetUri,
    body: payload,
    keyid: rec.serverId,
    privateKey: rec.ourPrivateKey,
  });
  return (await fetch(targetUri, {
    method,
    headers: {
      "content-type": "application/json",
      "content-digest": headers["content-digest"],
      "signature-input": headers["signature-input"],
      signature: headers.signature,
    },
    body: payload === "" ? undefined : payload,
  })) as globalThis.Response;
}

/** Start the registration handshake: POST /registration to the server. */
export async function registerWithServer(
  opts: FaspOptions,
  serverUrl: string,
): Promise<{ record: ServerRecord; fingerprint: string; completionUri: string }> {
  const baseUrl = await discoverFaspBaseUrl(serverUrl);
  const rec = createServer(serverUrl, baseUrl);

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

  const updated = updateServer(rec.serverId, {
    faspId: data.faspId,
    theirPublicKey: data.publicKey,
  });

  return {
    record: updated,
    fingerprint: keyFingerprint(rec.ourPublicKey),
    completionUri: data.registrationCompletionUri,
  };
}

/** Express middleware enforcing RFC 9421 signatures on inbound requests. */
export function requireSignature(opts: FaspOptions) {
  return (req: Request, res: ExpressResponse, next: NextFunction) => {
    const raw = (req as Request & { rawBody?: string }).rawBody ?? "";
    const targetUri = `${opts.baseUrl}${req.originalUrl}`;
    const result = verifyRequest({
      method: req.method,
      targetUri,
      rawBody: raw,
      headers: req.headers as Record<string, string | undefined>,
      lookupKey: lookupKeyByFaspId,
    });
    if (!result.ok) {
      return res.status(401).json({ error: "unauthorized", reason: result.reason });
    }
    req.faspServer = serverByFaspId(result.keyid!);
    next();
  };
}

/** Send a signed JSON response as the spec requires (@status + content-digest). */
export function sendSigned(
  req: Request,
  res: ExpressResponse,
  status: number,
  body: unknown,
) {
  const rec = req.faspServer;
  const payload = body === undefined ? "" : JSON.stringify(body);
  if (rec) {
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
  }
  res.status(status).type("application/json").send(payload);
}

export function createFasp(opts: FaspOptions) {
  const app = express();

  // Capture the raw body — signature verification needs the exact bytes.
  app.use(
    express.json({
      verify: (req, _res, buf) => {
        (req as Request & { rawBody?: string }).rawBody = buf.toString("utf8");
      },
    }),
  );

  app.get("/provider_info", (_req, res) => {
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
  app.post("/register", async (req, res) => {
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

  const guarded = express.Router();
  guarded.use(requireSignature(opts));
  for (const cap of opts.capabilities) cap.register?.(guarded);
  app.use(guarded);

  app.get("/health", (_req, res) => res.json({ ok: true, servers: allServers().length }));

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
        res.status(201).end();
      });
    },
  };
}

export { getServer, allServers };
