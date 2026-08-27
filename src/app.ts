import express from "express";
import { createFasp, debugCapability, FaspOptions, Capability } from "./server.js";
import { FaspStore, defaultStore } from "./store.js";
import { FaspConfig, loadConfig, ConfigOverrides } from "./config.js";
import { actorRoutes } from "./activitypub.js";
import { dataSharingCapability, startRevalidation } from "./datasharing.js";
import {
  accountSearchCapability,
  trendsCapability,
  followRecommendationCapability,
} from "./discovery.js";
import { createReferenceIndex, ReferenceIndex } from "./refindex.js";
import { adminRouter } from "./admin.js";

/**
 * Assembles a complete, runnable FASP: transport, capabilities, the actor, the
 * admin dashboard and the revalidation loop.
 *
 * The library pieces stay usable on their own — this is the batteries-included
 * path for someone who wants to run a FASP rather than build one.
 */

export interface FaspAppOptions extends ConfigOverrides {
  /** Extra capabilities to offer alongside the built-in ones. */
  capabilities?: Capability[];
  /** Swap the reference index for your own providers. */
  index?: ReferenceIndex;
  /** Serve the admin dashboard. Default true. */
  admin?: boolean;
  /** Run the periodic consent revalidation pass. Default true. */
  revalidate?: boolean;
}

export interface FaspApp {
  app: express.Express;
  config: FaspConfig;
  store: FaspStore;
  index: ReferenceIndex;
  /** Stops the revalidation timer. */
  stop: () => void;
  listen: (port?: number) => Promise<{ port: number; close: () => Promise<void> }>;
}

export async function createFaspApp(options: FaspAppOptions = {}): Promise<FaspApp> {
  const store = options.store ?? defaultStore;
  const config = await loadConfig({ ...options, store });
  const index = options.index ?? createReferenceIndex();

  const capabilities: Capability[] = [
    debugCapability(),
    dataSharingCapability({
      identity: config.identity,
      store,
      handlers: {
        onAccepted: (obj, ctx) => index.add(obj, ctx.announcement.category),
        onRevalidated: (obj) => index.add(obj, "content"),
        onRevoked: (uri) => index.remove(uri),
      },
    }),
    accountSearchCapability((q) => index.accountSearch(q)),
    trendsCapability({
      content: (q) => index.trendingContent(q),
      hashtags: (q) => index.trendingHashtags(q),
      links: (q) => index.trendingLinks(q),
    }),
    followRecommendationCapability((q) => index.followRecommendations(q)),
    ...(options.capabilities ?? []),
  ];

  const faspOptions: FaspOptions = {
    name: config.name,
    baseUrl: config.baseUrl,
    privacyPolicy: [{ url: config.privacyPolicyUrl, language: "en" }],
    contactEmail: config.contactEmail,
    fediverseAccount: config.fediverseAccount,
    capabilities,
    store,
  };

  const app = createFasp(faspOptions);

  // The actor and WebFinger live at the origin, outside any FASP base path,
  // because the spec fixes the actor's path at /actor.
  app.use(actorRoutes(config.identity));

  if (options.admin !== false) {
    app.use(adminRouter({ config, faspOptions, store, index }));
    // A bare visit to the root should land somewhere useful rather than 404.
    app.get("/", (_req, res) => res.redirect("/admin"));
  }

  const stopRevalidation =
    options.revalidate === false
      ? () => {}
      : startRevalidation({
          identity: config.identity,
          store,
          handlers: { onRevoked: (uri) => index.remove(uri) },
        });

  return {
    app,
    config,
    store,
    index,
    stop: stopRevalidation,
    listen(port = config.port) {
      return new Promise((resolve) => {
        const server = app.listen(port, () => {
          const actual = (server.address() as { port: number }).port;
          resolve({
            port: actual,
            close: () =>
              new Promise((done) => {
                stopRevalidation();
                server.close(() => done());
              }),
          });
        });
      });
    },
  };
}
