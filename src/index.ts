import { createFasp, debugCapability, sendSigned, Capability } from "./server.js";
import { dataSharingCapability, startRevalidation } from "./datasharing.js";
import {
  accountSearchCapability,
  trendsCapability,
  followRecommendationCapability,
} from "./discovery.js";
import { createReferenceIndex } from "./refindex.js";
import { generateActorKeypair, actorRoutes, ActorIdentity } from "./activitypub.js";

export * from "./crypto.js";
export * from "./server.js";
export * from "./store.js";
export * from "./consent.js";
export * from "./activitypub.js";
export * from "./datasharing.js";
export * from "./discovery.js";
export * from "./refindex.js";
export * from "./secretbox.js";

/**
 * Sketch of a `link_preview` capability — one of the examples Mastodon names
 * as a good third-party FASP. No spec exists for this yet; the identifier and
 * shape below are a proposal, which is exactly the point: the spec repo invites
 * new capability specifications via PR.
 */
export function linkPreviewCapability(
  fetchPreview: (url: string) => Promise<Record<string, unknown>>,
): Capability {
  return {
    id: "link_preview",
    version: "0.1",
    register(router) {
      router.post("/link_preview/v0/previews", async (req, res) => {
        const urls: string[] = req.body?.urls ?? [];
        if (!Array.isArray(urls) || urls.length === 0) {
          return sendSigned(req, res, 422, { error: "urls array required" });
        }
        const previews = await Promise.all(
          urls.slice(0, 50).map(async (url) => {
            try {
              return { url, ...(await fetchPreview(url)) };
            } catch (err) {
              return { url, error: String(err) };
            }
          }),
        );
        sendSigned(req, res, 200, { previews });
      });
    },
  };
}

/**
 * A complete, runnable FASP.
 *
 * This is the whole layer wired together: registration and signed transport,
 * `data_sharing` pulling consented content in, the reference index holding it,
 * and the three discovery capabilities answering queries about it — plus the
 * revalidation pass that drops content whose author later withdraws consent.
 *
 * The reference index is in-memory and its ranking is deliberately simple. Swap
 * `createReferenceIndex()` for your own provider implementations to build a real
 * FASP; everything else here stays as it is.
 */
if (process.env.FASPKIT_RUN === "1") {
  const port = Number(process.env.PORT ?? 3000);
  const baseUrl = process.env.FASP_BASE_URL ?? `http://localhost:${port}`;

  // The actor keypair is separate from the per-server registration keys, and is
  // what signs our outbound fetches to the wider fediverse.
  const identity: ActorIdentity = {
    baseUrl,
    preferredUsername: process.env.FASP_USERNAME ?? "faspkit",
    keypair: generateActorKeypair(),
  };

  const index = createReferenceIndex();

  const app = createFasp({
    name: process.env.FASP_NAME ?? "faspkit",
    baseUrl,
    privacyPolicy: [{ url: `${baseUrl}/privacy`, language: "en" }],
    capabilities: [
      debugCapability(),
      dataSharingCapability({
        identity,
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
    ],
  });

  // The ActivityPub actor and WebFinger sit at the origin, outside the FASP
  // base path, because the spec fixes the actor's path at /actor.
  app.use(actorRoutes(identity));

  startRevalidation({ identity, handlers: { onRevoked: (uri) => index.remove(uri) } });

  app.listen(port, () => {
    console.log(`faspkit listening on ${baseUrl}`);
    console.log(`  provider_info  ${baseUrl}/provider_info`);
    console.log(`  actor          ${baseUrl}/actor`);
  });
}
