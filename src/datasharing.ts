import { Capability, callServer, sendSigned, CallOptions } from "./server.js";
import { ServerRecord, markSeen, forgetSeen } from "./store.js";
import {
  evaluateContent,
  evaluateAccount,
  attributedTo,
  ConsentResult,
  JsonObject,
} from "./consent.js";
import { fetchObject, FetchObjectOptions, createStyleCache } from "./activitypub.js";

/**
 * The `data_sharing` capability from discovery/data_sharing/v0.1.
 *
 * This is the gateway capability: `trends`, `account_search` and
 * `follow_recommendation` all depend on a FASP having content to work with, and
 * this is how it gets it. Fediverse servers announce object *URIs*; the FASP
 * fetches each one itself and must independently verify consent before storing
 * anything.
 */

export type Category = "content" | "account";
export type SubscriptionType = "lifecycle" | "trends";
export type EventType = "new" | "update" | "delete" | "trending";

export interface Threshold {
  /** Minutes in which interactions should fire an event. Server default 15. */
  timeframe?: number;
  /** Shares in the timeframe. Server default 3. */
  shares?: number;
  /** Likes in the timeframe. Server default 3. */
  likes?: number;
  /** Replies in the timeframe. Server default 3. */
  replies?: number;
}

export interface SubscriptionRequest {
  category: Category;
  subscriptionType: SubscriptionType;
  maxBatchSize?: number;
  /** Only meaningful when subscriptionType is "trends". */
  threshold?: Threshold;
}

export interface Announcement {
  source: { subscription?: { id: string }; backfillRequest?: { id: string } };
  category: Category;
  /** Present for events, absent for backfill fulfilment. */
  eventType?: EventType;
  objectUris: string[];
  /** Present on backfill responses: whether to ask for a continuation. */
  moreObjectsAvailable?: boolean;
}

// ---------------------------------------------------------------------------
// Client: subscriptions and backfill (FASP => fediverse server)
// ---------------------------------------------------------------------------

export class DataSharingError extends Error {
  constructor(message: string, readonly status: number, readonly body?: string) {
    super(message);
    this.name = "DataSharingError";
  }
}

/** `trends` subscriptions only apply to content; catch that before the round trip. */
function validateSubscription(req: SubscriptionRequest): void {
  if (req.category !== "content" && req.category !== "account") {
    throw new DataSharingError(`invalid category ${req.category}`, 422);
  }
  if (req.subscriptionType !== "lifecycle" && req.subscriptionType !== "trends") {
    throw new DataSharingError(`invalid subscriptionType ${req.subscriptionType}`, 422);
  }
  if (req.subscriptionType === "trends" && req.category !== "content") {
    throw new DataSharingError("trends subscriptions are only valid for the content category", 422);
  }
}

/** POST /data_sharing/v0/event_subscriptions — returns the new subscription id. */
export async function subscribe(
  rec: ServerRecord,
  req: SubscriptionRequest,
  options?: CallOptions,
): Promise<string> {
  validateSubscription(req);
  const res = await callServer(rec, "POST", "/data_sharing/v0/event_subscriptions", req, options);
  if (res.status === 422) {
    throw new DataSharingError("server rejected the subscription as invalid", 422, await res.text());
  }
  if (res.status !== 201) {
    throw new DataSharingError(`unexpected status ${res.status}`, res.status, await res.text());
  }
  const body = (await res.json()) as { subscription?: { id?: string } };
  const id = body.subscription?.id;
  if (!id) throw new DataSharingError("server returned no subscription id", res.status);
  return String(id);
}

/** DELETE /data_sharing/v0/event_subscriptions/:id */
export async function unsubscribe(
  rec: ServerRecord,
  subscriptionId: string,
  options?: CallOptions,
): Promise<void> {
  const res = await callServer(
    rec,
    "DELETE",
    `/data_sharing/v0/event_subscriptions/${encodeURIComponent(subscriptionId)}`,
    undefined,
    options,
  );
  if (res.status !== 204) {
    throw new DataSharingError(`unexpected status ${res.status}`, res.status, await res.text());
  }
}

/** POST /data_sharing/v0/backfill_requests — returns the new request id. */
export async function requestBackfill(
  rec: ServerRecord,
  req: { category: Category; maxCount: number },
  options?: CallOptions,
): Promise<string> {
  const res = await callServer(rec, "POST", "/data_sharing/v0/backfill_requests", req, options);
  if (res.status !== 201) {
    throw new DataSharingError(`unexpected status ${res.status}`, res.status, await res.text());
  }
  const body = (await res.json()) as { backfillRequest?: { id?: string } };
  const id = body.backfillRequest?.id;
  if (!id) throw new DataSharingError("server returned no backfillRequest id", res.status);
  return String(id);
}

/**
 * POST /data_sharing/v0/backfill_requests/{id}/continuation
 *
 * Resolves true when more content is coming (204) and false when the request is
 * exhausted or unknown (404). Per the spec a FASP should not call this until an
 * announcement has said more is available.
 */
export async function continueBackfill(
  rec: ServerRecord,
  backfillRequestId: string,
  options?: CallOptions,
): Promise<boolean> {
  const res = await callServer(
    rec,
    "POST",
    `/data_sharing/v0/backfill_requests/${encodeURIComponent(backfillRequestId)}/continuation`,
    undefined,
    options,
  );
  if (res.status === 204) return true;
  if (res.status === 404) return false;
  throw new DataSharingError(`unexpected status ${res.status}`, res.status, await res.text());
}

// ---------------------------------------------------------------------------
// Consent-gated retrieval
// ---------------------------------------------------------------------------

export interface ProcessedObject {
  uri: string;
  accepted: boolean;
  /** Why it was rejected, for the audit log. */
  reason?: string;
  document?: JsonObject;
  /** The author's actor document, when one was fetched for a content object. */
  actor?: JsonObject;
}

export interface RetrievalOptions extends FetchObjectOptions {
  /** Cache of author actors, so a burst of posts by one account is one fetch. */
  actorCache?: Map<string, JsonObject>;
}

/**
 * Fetch one announced URI and decide whether it may be indexed.
 *
 * Every path that is not an explicit allow returns `accepted: false` with a
 * reason. Consent is deny-by-default: a fetch failure, a malformed document, or
 * an unreachable author is a rejection, not a pass.
 */
export async function retrieveWithConsent(
  uri: string,
  category: Category,
  opts: RetrievalOptions,
): Promise<ProcessedObject> {
  const fetched = await fetchObject(uri, opts);
  if (!fetched.ok || !fetched.document) {
    return {
      uri,
      accepted: false,
      reason: fetched.error ?? `could not retrieve object (HTTP ${fetched.status ?? "error"})`,
    };
  }
  const document = fetched.document as JsonObject;

  if (category === "account") {
    const verdict = evaluateAccount(document);
    return { uri, accepted: verdict.allowed, reason: verdict.reason, document };
  }

  // Content consent lives on the author (FEP-5feb), so the actor must be
  // retrieved too. An object can never establish consent on its own.
  const author = attributedTo(document);
  if (!author) {
    return { uri, accepted: false, reason: "object has no attributedTo, so consent cannot be established", document };
  }

  let actor = opts.actorCache?.get(author);
  if (!actor) {
    const fetchedActor = await fetchObject(author, opts);
    if (fetchedActor.ok && fetchedActor.document) {
      actor = fetchedActor.document as JsonObject;
      opts.actorCache?.set(author, actor);
    }
  }

  const verdict: ConsentResult = evaluateContent(document, actor);
  return { uri, accepted: verdict.allowed, reason: verdict.reason, document, actor };
}

// ---------------------------------------------------------------------------
// Server: the announcement receiver (fediverse server => FASP)
// ---------------------------------------------------------------------------

export interface AnnouncementContext {
  announcement: Announcement;
  server: ServerRecord;
  /** URIs left after removing ones already seen from any server. */
  freshUris: string[];
  /** URIs dropped as duplicates. */
  duplicateUris: string[];
}

export interface DataSharingHandlers {
  /**
   * Called for every announcement, after deduplication and before retrieval.
   * Return false to skip retrieval entirely (useful for delete events).
   */
  onAnnouncement?: (ctx: AnnouncementContext) => void | boolean | Promise<void | boolean>;
  /** Called once per object that passed the consent gate. */
  onAccepted?: (obj: ProcessedObject, ctx: AnnouncementContext) => void | Promise<void>;
  /** Called once per object that was rejected, with the reason. */
  onRejected?: (obj: ProcessedObject, ctx: AnnouncementContext) => void | Promise<void>;
  /** Called when an object is announced as deleted; drop it from your index. */
  onDelete?: (uri: string, ctx: AnnouncementContext) => void | Promise<void>;
  /** Called on a backfill announcement that says more content is available. */
  onMoreAvailable?: (backfillRequestId: string, ctx: AnnouncementContext) => void | Promise<void>;
}

function parseAnnouncement(body: unknown): Announcement | string {
  if (!body || typeof body !== "object") return "body must be a JSON object";
  const b = body as Record<string, unknown>;

  const source = b.source as Announcement["source"] | undefined;
  const hasSource =
    !!source &&
    typeof source === "object" &&
    (typeof source.subscription?.id === "string" || typeof source.backfillRequest?.id === "string");
  if (!hasSource) return "source must name either a subscription or a backfillRequest id";

  if (b.category !== "content" && b.category !== "account") return "category must be content or account";

  if (!Array.isArray(b.objectUris) || b.objectUris.length === 0) {
    return "objectUris must be a non-empty array";
  }
  if (!b.objectUris.every((u) => typeof u === "string")) return "objectUris must contain only strings";

  if (b.eventType !== undefined) {
    if (!["new", "update", "delete", "trending"].includes(b.eventType as string)) {
      return `unknown eventType ${String(b.eventType)}`;
    }
    if (source!.backfillRequest) return "eventType must not be present on a backfill response";
  }

  return {
    source: source!,
    category: b.category,
    eventType: b.eventType as EventType | undefined,
    objectUris: b.objectUris as string[],
    moreObjectsAvailable:
      typeof b.moreObjectsAvailable === "boolean" ? b.moreObjectsAvailable : undefined,
  };
}

export interface DataSharingOptions extends Omit<RetrievalOptions, "actorCache"> {
  handlers?: DataSharingHandlers;
  /**
   * Retrieve announced objects and run the consent gate. Defaults to true.
   * Setting false gives you the raw announcement and leaves retrieval to you —
   * but then enforcing consent becomes your responsibility.
   */
  retrieve?: boolean;
}

/**
 * Build the `data_sharing` capability.
 *
 * The announcement endpoint answers `204` as the spec requires, and does so
 * promptly: retrieval of announced objects happens after the response, because
 * fetching dozens of remote objects inline would hold the instance's request
 * open for as long as the slowest origin server takes to answer.
 */
export function dataSharingCapability(opts: DataSharingOptions): Capability {
  const handlers = opts.handlers ?? {};
  const styleCache = opts.styleCache ?? createStyleCache();
  const shouldRetrieve = opts.retrieve !== false;

  return {
    id: "data_sharing",
    version: "0.1",
    register(router) {
      router.post("/data_sharing/v0/announcements", async (req, res) => {
        const parsed = parseAnnouncement(req.body);
        if (typeof parsed === "string") {
          return sendSigned(req, res, 422, { error: parsed });
        }

        const server = req.faspServer!;

        // Deduplicate: the same object reaches us from every connected server
        // that has seen it, and re-fetching it wastes the origin's bandwidth as
        // much as ours.
        //
        // `update` and `delete` are exempt, because they exist precisely to
        // report that a URI we already know about has changed. Deduplicating
        // them would discard the only notification we get. `new`, `trending`
        // and backfill fulfilment all describe objects in their current state,
        // so those do dedupe.
        const isDelete = parsed.eventType === "delete";
        const bypassDedup = isDelete || parsed.eventType === "update";
        const deduped = markSeen(parsed.objectUris);
        const freshUris = bypassDedup ? parsed.objectUris : deduped;
        const duplicateUris = bypassDedup
          ? []
          : parsed.objectUris.filter((u) => !deduped.includes(u));

        const ctx: AnnouncementContext = { announcement: parsed, server, freshUris, duplicateUris };

        // Answer before doing any outbound work.
        sendSigned(req, res, 204, undefined);

        try {
          const proceed = await handlers.onAnnouncement?.(ctx);

          if (isDelete) {
            for (const uri of parsed.objectUris) {
              forgetSeen(uri);
              await handlers.onDelete?.(uri, ctx);
            }
            return;
          }

          if (parsed.moreObjectsAvailable && parsed.source.backfillRequest) {
            await handlers.onMoreAvailable?.(parsed.source.backfillRequest.id, ctx);
          }

          if (proceed === false || !shouldRetrieve || freshUris.length === 0) return;

          const actorCache = new Map<string, JsonObject>();
          for (const uri of freshUris) {
            const result = await retrieveWithConsent(uri, parsed.category, {
              ...opts,
              styleCache,
              actorCache,
            });
            if (result.accepted) {
              await handlers.onAccepted?.(result, ctx);
            } else {
              // A rejected URI stays in the seen set on purpose. Dropping it
              // would mean re-fetching every private or deleted object each
              // time any connected server mentions it again, which is the
              // hammering dedup exists to prevent. Consent that changes later
              // reaches us through an `update` event, which bypasses dedup, or
              // through the periodic revalidation pass (plan task 3.5).
              console.log(`[data_sharing] rejected ${uri}: ${result.reason}`);
              await handlers.onRejected?.(result, ctx);
            }
          }
        } catch (err) {
          console.error("[data_sharing] announcement processing failed:", err);
        }
      });
    },
  };
}
