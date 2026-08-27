import { Capability, sendSigned } from "./server.js";

/**
 * The three query capabilities a discovery FASP exposes to fediverse servers:
 * `account_search`, `trends` and `follow_recommendation`.
 *
 * These are the read side of the FASP layer. `data_sharing` brings content in;
 * these answer questions about it. faspkit implements the protocol — parameter
 * parsing, defaults, validation, language filtering, rank checking, ordering,
 * pagination headers, signed responses — and delegates the actual searching and
 * ranking to a provider you supply.
 *
 * That split is deliberate and follows the spec, which explicitly declines to
 * define how trends are computed and says implementations MAY compete on the
 * algorithm. The protocol is the part everyone must get identically right; the
 * ranking is the part nobody agrees on.
 */

// ---------------------------------------------------------------------------
// Shared parameter handling
// ---------------------------------------------------------------------------

/** A query parameter arrives as a string, an array, or not at all. */
type RawParam = undefined | string | string[] | Record<string, unknown>;

function single(value: RawParam): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return typeof value[0] === "string" ? value[0] : undefined;
  return undefined;
}

/**
 * Parse a parameter the spec describes as "a positive integer".
 *
 * Returns undefined when absent, and null when present but not a positive
 * integer — the caller decides whether that is a 422 or a fallback to the
 * default. Accepting "0", "-5", "abc" or "10.5" as a count silently produces
 * nonsense responses, so they are rejected rather than coerced.
 */
export function positiveInteger(value: RawParam): number | undefined | null {
  const raw = single(value);
  if (raw === undefined || raw.trim() === "") return undefined;
  if (!/^\d+$/.test(raw.trim())) return null;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/**
 * RFC 4647 basic filtering.
 *
 * A range matches a tag when it equals it, or is a prefix of it terminated by
 * "-". So "en" matches "en-GB" but not "eng"; the wildcard "*" matches
 * everything. Both sides compare case-insensitively.
 */
export function languageMatches(range: string | undefined, tag: string | undefined): boolean {
  if (!range || range === "*") return true;
  if (!tag) return false;
  const r = range.toLowerCase();
  const t = tag.toLowerCase();
  return t === r || t.startsWith(`${r}-`);
}

/** Options every trends request may carry. */
export interface TrendsQuery {
  /** Hours back from now to consider. Defaults to 24. */
  withinLastHours: number;
  /** Maximum results. Defaults to 20. */
  maxCount: number;
  /** BCP47 language range, if the server asked to filter. */
  language?: string;
}

/** The spec requires supporting at least a week; larger values are allowed. */
export const MAX_REQUIRED_WITHIN_LAST_HOURS = 168;
export const DEFAULT_WITHIN_LAST_HOURS = 24;
export const DEFAULT_MAX_COUNT = 20;
export const DEFAULT_SEARCH_LIMIT = 20;

export interface TrendsQueryOptions {
  /**
   * Largest `withinLastHours` this FASP will honour. The spec sets a floor of
   * 168; a bigger window is allowed but costs more to compute, so requests
   * beyond the cap are clamped rather than refused.
   */
  maxWithinLastHours?: number;
  /** Cap on `maxCount`, to bound response size. */
  maxResults?: number;
}

export function parseTrendsQuery(
  query: Record<string, RawParam>,
  options: TrendsQueryOptions = {},
): TrendsQuery | { error: string } {
  const hoursCap = Math.max(MAX_REQUIRED_WITHIN_LAST_HOURS, options.maxWithinLastHours ?? MAX_REQUIRED_WITHIN_LAST_HOURS);
  const countCap = options.maxResults ?? 200;

  const hours = positiveInteger(query.withinLastHours);
  if (hours === null) return { error: "withinLastHours must be a positive integer" };

  const maxCount = positiveInteger(query.maxCount);
  if (maxCount === null) return { error: "maxCount must be a positive integer" };

  return {
    // Clamp rather than reject: a server asking for a longer window than we
    // keep should get the longest we can honour, not an error.
    withinLastHours: Math.min(hours ?? DEFAULT_WITHIN_LAST_HOURS, hoursCap),
    maxCount: Math.min(maxCount ?? DEFAULT_MAX_COUNT, countCap),
    language: single(query.language),
  };
}

// ---------------------------------------------------------------------------
// account_search
// ---------------------------------------------------------------------------

export interface AccountSearchQuery {
  term: string;
  limit: number;
  /** Opaque cursor from a previous page's `Link: rel="next"`. */
  cursor?: string;
}

export interface AccountSearchResult {
  /** ActivityPub actor URIs, most relevant first. */
  uris: string[];
  /** Set when more results exist, to be echoed back as `cursor`. */
  nextCursor?: string;
}

export type AccountSearchProvider = (
  query: AccountSearchQuery,
) => AccountSearchResult | string[] | Promise<AccountSearchResult | string[]>;

export interface AccountSearchOptions {
  /** Cap on `limit`, to bound response size. Defaults to 200. */
  maxLimit?: number;
}

/**
 * `discovery/account_search/v0.1` — GET /account_search/v0/search
 *
 * Answers a JSON array of actor URIs sorted by relevance, or 422 when `term`
 * is missing. Note the response is a bare array, not an object: that is what
 * the spec specifies, and wrapping it would break every conforming client.
 */
export function accountSearchCapability(
  provider: AccountSearchProvider,
  options: AccountSearchOptions = {},
): Capability {
  const maxLimit = options.maxLimit ?? 200;

  return {
    id: "account_search",
    version: "0.1",
    register(router) {
      router.get("/account_search/v0/search", async (req, res) => {
        const query = req.query as Record<string, RawParam>;
        const term = single(query.term);
        if (term === undefined || term.trim() === "") {
          return sendSigned(req, res, 422, { error: "term is required" });
        }

        const limit = positiveInteger(query.limit);
        if (limit === null) {
          return sendSigned(req, res, 422, { error: "limit must be a positive integer" });
        }

        const result = await provider({
          term,
          limit: Math.min(limit ?? DEFAULT_SEARCH_LIMIT, maxLimit),
          cursor: single(query.cursor),
        });
        const { uris, nextCursor } = Array.isArray(result) ? { uris: result, nextCursor: undefined } : result;

        // RFC 5988 Link header is how the spec signals a further page.
        if (nextCursor) {
          const next = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
          next.searchParams.set("cursor", nextCursor);
          res.set("link", `<${next.toString()}>; rel="next"`);
        }
        sendSigned(req, res, 200, uris);
      });
    },
  };
}

// ---------------------------------------------------------------------------
// trends
// ---------------------------------------------------------------------------

/** `rank` is a positive integer up to 100, where 100 is most trending. */
export interface Ranked {
  rank: number;
}

export interface TrendingContent extends Ranked {
  uri: string;
}

export interface TrendingHashtag extends Ranked {
  /** Includes the leading "#". */
  name: string;
  /** URIs of content using the hashtag, so a server can fill its cache. */
  examples: string[];
}

export interface TrendingLink extends Ranked {
  url: string;
  examples: string[];
}

export interface TrendsProvider {
  content?: (query: TrendsQuery) => TrendingContent[] | Promise<TrendingContent[]>;
  hashtags?: (query: TrendsQuery) => TrendingHashtag[] | Promise<TrendingHashtag[]>;
  links?: (query: TrendsQuery) => TrendingLink[] | Promise<TrendingLink[]>;
}

/**
 * Enforce the response contract a provider might get wrong.
 *
 * Ranks must be integers in 1..100 and results must be sorted by rank
 * descending. A server merging results from several FASPs relies on both, so a
 * provider returning rank 0, 250, or an unsorted list would silently corrupt
 * the merge. Clamping and re-sorting here means a slightly sloppy provider
 * still produces a conforming response.
 */
function normalizeRanked<T extends Ranked>(items: T[], maxCount: number): T[] {
  return items
    .map((item) => ({
      ...item,
      rank: Math.min(100, Math.max(1, Math.round(item.rank))),
    }))
    .sort((a, b) => b.rank - a.rank)
    .slice(0, maxCount);
}

/**
 * `discovery/trends/v0.1` — GET /trends/v0/{content,hashtags,links}
 *
 * The spec deliberately does not define how trends are computed, and says
 * implementations may compete on the algorithm. So this handles the protocol
 * and leaves ranking to the provider. An endpoint whose provider function is
 * absent answers an empty list rather than 404, so a server can query all three
 * without having to know which this FASP actually computes.
 */
export function trendsCapability(
  provider: TrendsProvider,
  options: TrendsQueryOptions = {},
): Capability {
  return {
    id: "trends",
    version: "0.1",
    register(router) {
      const endpoint = <T extends Ranked>(
        path: string,
        key: string,
        fn: ((q: TrendsQuery) => T[] | Promise<T[]>) | undefined,
      ) => {
        router.get(path, async (req, res) => {
          const parsed = parseTrendsQuery(req.query as Record<string, RawParam>, options);
          if ("error" in parsed) return sendSigned(req, res, 422, { error: parsed.error });
          const items = fn ? await fn(parsed) : [];
          sendSigned(req, res, 200, { [key]: normalizeRanked(items, parsed.maxCount) });
        });
      };

      endpoint("/trends/v0/content", "content", provider.content);
      endpoint("/trends/v0/hashtags", "hashtags", provider.hashtags);
      endpoint("/trends/v0/links", "links", provider.links);
    },
  };
}

// ---------------------------------------------------------------------------
// follow_recommendation
// ---------------------------------------------------------------------------

export interface FollowRecommendationQuery {
  /** The actor URI to recommend follows for. */
  accountUri: string;
  language?: string;
}

export type FollowRecommendationProvider = (
  query: FollowRecommendationQuery,
) => string[] | Promise<string[]>;

/**
 * `discovery/follow_recommendation/v0.1` — GET /follow_recommendation/v0/accounts
 *
 * Answers a JSON array of recommended actor URIs, or 422 when `accountUri` is
 * missing.
 *
 * Filtering out accounts the user already follows, has blocked, or whose domain
 * is blocked is explicitly the fediverse server's job, not ours — we have no
 * way to know any of it.
 */
export function followRecommendationCapability(
  provider: FollowRecommendationProvider,
): Capability {
  return {
    id: "follow_recommendation",
    version: "0.1",
    register(router) {
      router.get("/follow_recommendation/v0/accounts", async (req, res) => {
        const query = req.query as Record<string, RawParam>;
        const accountUri = single(query.accountUri);
        if (accountUri === undefined || accountUri.trim() === "") {
          return sendSigned(req, res, 422, { error: "accountUri is required" });
        }
        const uris = await provider({ accountUri, language: single(query.language) });
        sendSigned(req, res, 200, uris);
      });
    },
  };
}
