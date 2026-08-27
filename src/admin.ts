import express, { Request, Response, NextFunction } from "express";
import { FaspStore, defaultStore, ServerRecord } from "./store.js";
import { FaspConfig, tokensMatch } from "./config.js";
import { keyFingerprint } from "./crypto.js";
import { registerWithServer, FaspOptions } from "./server.js";
import {
  subscribe,
  requestBackfill,
  Category,
  SubscriptionType,
  DataSharingError,
} from "./datasharing.js";
import { ReferenceIndex } from "./refindex.js";
import { adminPage, loginPage } from "./adminpage.js";

/**
 * The admin dashboard: the difference between a library and something an
 * instance operator will actually run.
 *
 * It answers the questions someone has in the first five minutes — is it up,
 * what is it connected to, is it collecting anything, does it work — and it
 * drives the registration handshake, which is otherwise a hand-written signed
 * HTTP request.
 *
 * Served as one self-contained HTML page with no framework, no build step and
 * no external assets, so `npx faspkit` really is the whole install.
 */

const COOKIE = "faspkit_admin";

export interface AdminOptions {
  config: FaspConfig;
  faspOptions: FaspOptions;
  store?: FaspStore;
  index?: ReferenceIndex;
}

/** Express gives a repeated query parameter as an array; take the first. */
function firstQueryValue(value: unknown): string {
  if (Array.isArray(value)) return typeof value[0] === "string" ? value[0] : "";
  return typeof value === "string" ? value : "";
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

/** Bearer header or session cookie; both compared in constant time. */
function isAuthorized(req: Request, token: string): boolean {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) return tokensMatch(auth.slice(7), token);
  const cookie = parseCookies(req.headers.cookie)[COOKIE];
  return cookie ? tokensMatch(cookie, token) : false;
}

function publicServer(rec: ServerRecord) {
  // Never expose private key material through the API, not even to an
  // authenticated admin — there is no reason for the browser to hold it.
  return {
    serverId: rec.serverId,
    faspId: rec.faspId,
    serverUrl: rec.serverUrl,
    baseUrl: rec.baseUrl,
    status: rec.status,
    createdAt: rec.createdAt,
    rotatedAt: rec.rotatedAt,
    fingerprint: keyFingerprint(rec.ourPublicKey),
    hasTheirKey: !!rec.theirPublicKey,
  };
}

export function adminRouter(opts: AdminOptions): express.Router {
  const store = opts.store ?? defaultStore;
  const { config, index } = opts;
  const router = express.Router();

  router.use(express.json());
  router.use(express.urlencoded({ extended: false }));

  // ---- Auth ---------------------------------------------------------------

  router.get("/admin/login", (_req, res) => {
    res.type("html").send(loginPage(config.name));
  });

  router.post("/admin/login", (req, res) => {
    const token = String(req.body?.token ?? "");
    if (!token || !tokensMatch(token, config.adminToken)) {
      return res.status(401).type("html").send(loginPage(config.name, "That token was not correct."));
    }
    res.cookie?.(COOKIE, token, { httpOnly: true, sameSite: "lax", path: "/" });
    if (!res.cookie) {
      res.setHeader("set-cookie", `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/`);
    }
    res.redirect("/admin");
  });

  router.post("/admin/logout", (_req, res) => {
    res.setHeader("set-cookie", `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    res.redirect("/admin/login");
  });

  const guard = (req: Request, res: Response, next: NextFunction) => {
    if (isAuthorized(req, config.adminToken)) return next();
    if (req.path.startsWith("/admin/api")) {
      return res.status(401).json({ error: "unauthorized" });
    }
    return res.redirect("/admin/login");
  };

  // ---- Dashboard ----------------------------------------------------------

  router.get("/admin", guard, (_req, res) => {
    res.type("html").send(adminPage(config));
  });

  // ---- JSON API -----------------------------------------------------------

  const api = express.Router();
  api.use(guard);

  const wrap = (fn: (req: Request, res: Response) => Promise<unknown>) =>
    async (req: Request, res: Response) => {
      try {
        const body = await fn(req, res);
        if (!res.headersSent) res.json(body);
      } catch (err) {
        const status = err instanceof DataSharingError ? err.status : 400;
        res.status(status).json({ error: err instanceof Error ? err.message : String(err) });
      }
    };

  api.get("/admin/api/status", wrap(async () => {
    const servers = await store.allServers();
    return {
      name: config.name,
      baseUrl: config.baseUrl,
      actor: `${config.baseUrl}/actor`,
      username: config.username,
      capabilities: opts.faspOptions.capabilities.map((c) => ({ id: c.id, version: c.version })),
      servers: servers.map(publicServer),
      counts: {
        servers: servers.length,
        active: servers.filter((s) => s.status === "active").length,
        seen: await store.seenCount(),
        indexed: await store.indexedCount(),
        ...(index ? index.stats() : {}),
      },
    };
  }));

  /**
   * Start the registration handshake with a fediverse server.
   *
   * The response carries the fingerprint the admin must compare in their own
   * server's UI. That comparison is the whole security model of registration —
   * it is how they confirm they are approving us and not an impostor — so the
   * UI shows it prominently rather than burying it.
   */
  api.post("/admin/api/connect", wrap(async (req) => {
    const serverUrl = String(req.body?.serverUrl ?? "").trim();
    if (!serverUrl) throw new Error("serverUrl is required");
    const normalized = /^https?:\/\//i.test(serverUrl) ? serverUrl : `https://${serverUrl}`;
    const result = await registerWithServer({ ...opts.faspOptions, store }, normalized);
    return {
      serverId: result.record.serverId,
      fingerprint: result.fingerprint,
      registrationCompletionUri: result.completionUri,
    };
  }));

  api.get("/admin/api/servers", wrap(async () => (await store.allServers()).map(publicServer)));

  api.post("/admin/api/servers/:id/subscribe", wrap(async (req) => {
    const rec = await store.getServer(firstQueryValue(req.params.id));
    if (!rec) throw new Error("unknown server");
    const category = (req.body?.category ?? "content") as Category;
    const subscriptionType = (req.body?.subscriptionType ?? "lifecycle") as SubscriptionType;
    return { subscriptionId: await subscribe(rec, { category, subscriptionType }) };
  }));

  api.post("/admin/api/servers/:id/backfill", wrap(async (req) => {
    const rec = await store.getServer(firstQueryValue(req.params.id));
    if (!rec) throw new Error("unknown server");
    const category = (req.body?.category ?? "content") as Category;
    const maxCount = Number(req.body?.maxCount ?? 100);
    return { backfillRequestId: await requestBackfill(rec, { category, maxCount }) };
  }));

  // Preview endpoints, so an operator can see what their FASP would answer
  // without having to craft a signed request by hand.
  api.get("/admin/api/preview/search", wrap(async (req) => {
    if (!index) throw new Error("no reference index is attached");
    const term = firstQueryValue(req.query.term);
    if (!term.trim()) return { uris: [] };
    return index.accountSearch({ term, limit: 20 });
  }));

  api.get("/admin/api/preview/trends", wrap(async (req) => {
    if (!index) throw new Error("no reference index is attached");
    const query = { withinLastHours: Number(firstQueryValue(req.query.withinLastHours) || 24), maxCount: 10 };
    return {
      hashtags: index.trendingHashtags(query),
      links: index.trendingLinks(query),
      content: index.trendingContent(query),
    };
  }));

  router.use(api);
  return router;
}
