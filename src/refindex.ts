import { JsonObject, attributedTo } from "./consent.js";
import {
  AccountSearchQuery,
  AccountSearchResult,
  FollowRecommendationQuery,
  TrendsQuery,
  TrendingContent,
  TrendingHashtag,
  TrendingLink,
  languageMatches,
} from "./discovery.js";
import { ProcessedObject } from "./datasharing.js";

/**
 * A reference index: the smallest thing that makes faspkit an actually working
 * FASP rather than a set of interfaces.
 *
 * It consumes objects that have already passed the consent gate and answers the
 * three discovery capabilities from them. The ranking is deliberately obvious —
 * count occurrences in a time window and scale to 1..100 — because the spec
 * declines to define ranking and says implementations may compete on it. This
 * is the baseline to beat, not an attempt to win.
 *
 * It is in-memory, so it starts empty on restart and is bounded by RAM. A real
 * deployment should implement the same provider signatures against whatever
 * search engine it already runs. The point of this file is that the protocol
 * layer above it is exercised end to end by something real.
 *
 * Nothing here re-checks consent: everything it stores has already been through
 * `retrieveWithConsent`, and `revalidate()` removes what is later withdrawn.
 * Feed it only accepted objects — see `indexAcceptedObjects`.
 */

interface ContentEntry {
  uri: string;
  author?: string;
  publishedMs: number;
  language?: string;
  hashtags: string[];
  links: string[];
  text: string;
}

interface AccountEntry {
  uri: string;
  username: string;
  name: string;
  summary: string;
  language?: string;
  indexedMs: number;
}

const AS_HASHTAG = "Hashtag";

/** Strip HTML tags and collapse whitespace, for naive text matching. */
function plainText(html: unknown): string {
  if (typeof html !== "string") return "";
  return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function asArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Normalise a hashtag for counting: case-folded, with the leading "#" ensured.
 *
 * The spec asks FASPs to normalise when *computing* trends so that "#cats" and
 * "#Cats" clear the threshold together, while leaving the returned
 * representation free. We count folded and display the first spelling seen.
 */
export function normalizeHashtag(name: string): string {
  const trimmed = name.trim();
  const withHash = trimmed.startsWith("#") ? trimmed : `#${trimmed}`;
  return withHash.toLowerCase();
}

/**
 * Normalise a URL for counting, per the RFC 3986 techniques the spec points at:
 * lowercase scheme and host, drop the fragment, drop a bare trailing slash.
 */
export function normalizeLink(url: string): string {
  try {
    const parsed = new URL(url.trim());
    parsed.hash = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.protocol = parsed.protocol.toLowerCase();
    let out = parsed.toString();
    if (out.endsWith("/") && parsed.pathname === "/" && !parsed.search) out = out.slice(0, -1);
    return out;
  } catch {
    return url.trim();
  }
}

/** Pull hashtags out of an object's `tag` array and, failing that, its text. */
export function extractHashtags(object: JsonObject, text: string): string[] {
  const tagged = asArray(object.tag)
    .filter((t): t is JsonObject => !!t && typeof t === "object")
    .filter((t) => t.type === AS_HASHTAG && typeof t.name === "string")
    .map((t) => String(t.name));

  // Not every implementation populates `tag`, so fall back to the text.
  const inline = text.match(/(?:^|\s)(#[\p{L}\p{N}_]+)/gu)?.map((m) => m.trim()) ?? [];
  return [...new Set([...tagged, ...inline].map((h) => h.trim()).filter(Boolean))];
}

/** Pull outbound links from an object's markup, ignoring tag and mention hrefs. */
export function extractLinks(object: JsonObject): string[] {
  const tagHrefs = new Set(
    asArray(object.tag)
      .filter((t): t is JsonObject => !!t && typeof t === "object")
      .map((t) => (typeof t.href === "string" ? t.href : ""))
      .filter(Boolean),
  );

  const html = typeof object.content === "string" ? object.content : "";
  const hrefs = [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
  const bare = plainText(html).match(/https?:\/\/[^\s<>"]+/g) ?? [];

  return [...new Set([...hrefs, ...bare])]
    .filter((u) => /^https?:\/\//i.test(u))
    .filter((u) => !tagHrefs.has(u));
}

function languageOf(object: JsonObject): string | undefined {
  if (typeof object.language === "string") return object.language;
  const map = object.contentMap;
  if (map && typeof map === "object") {
    const first = Object.keys(map as Record<string, unknown>)[0];
    if (first) return first;
  }
  return undefined;
}

function publishedMs(object: JsonObject): number {
  const raw = object.published ?? object.updated;
  if (typeof raw === "string") {
    const t = Date.parse(raw);
    if (!Number.isNaN(t)) return t;
  }
  return Date.now();
}

/**
 * Scale raw counts to the spec's 1..100 rank, where 100 is most trending.
 *
 * Ranks must be comparable across servers running the same FASP software so a
 * fediverse server can merge results from several of them, which is why this is
 * a documented function of the count rather than an arbitrary ordering.
 */
function rankByCount<T>(items: { item: T; count: number }[], maxCount: number): (T & { rank: number })[] {
  if (items.length === 0) return [];
  const sorted = [...items].sort((a, b) => b.count - a.count);
  const top = sorted[0].count || 1;
  return sorted
    .slice(0, maxCount)
    .map(({ item, count }) => ({ ...item, rank: Math.max(1, Math.round((count / top) * 100)) }));
}

export interface ReferenceIndexOptions {
  /** Cap on retained content entries. Oldest are dropped first. */
  maxContent?: number;
  /** Cap on retained account entries. */
  maxAccounts?: number;
}

export interface ReferenceIndex {
  /** Index one object that has already passed the consent gate. */
  add(object: ProcessedObject, category: "content" | "account"): void;
  /** Remove an object, e.g. when revalidation revokes it. */
  remove(uri: string): void;
  accountSearch(query: AccountSearchQuery): AccountSearchResult;
  trendingContent(query: TrendsQuery): TrendingContent[];
  trendingHashtags(query: TrendsQuery): TrendingHashtag[];
  trendingLinks(query: TrendsQuery): TrendingLink[];
  followRecommendations(query: FollowRecommendationQuery): string[];
  stats(): { content: number; accounts: number };
}

export function createReferenceIndex(options: ReferenceIndexOptions = {}): ReferenceIndex {
  const maxContent = options.maxContent ?? 100_000;
  const maxAccounts = options.maxAccounts ?? 100_000;

  const content = new Map<string, ContentEntry>();
  const accounts = new Map<string, AccountEntry>();

  function evict<T>(map: Map<string, T>, cap: number) {
    // Map preserves insertion order, so the oldest keys come first.
    while (map.size > cap) {
      const oldest = map.keys().next();
      if (oldest.done) break;
      map.delete(oldest.value);
    }
  }

  function within(query: TrendsQuery): ContentEntry[] {
    const cutoff = Date.now() - query.withinLastHours * 60 * 60 * 1000;
    return [...content.values()].filter(
      (e) => e.publishedMs >= cutoff && languageMatches(query.language, e.language),
    );
  }

  return {
    add(object, category) {
      const doc = object.document;
      if (!doc) return;

      if (category === "account") {
        const uri = typeof doc.id === "string" ? doc.id : object.uri;
        accounts.set(uri, {
          uri,
          username: String(doc.preferredUsername ?? ""),
          name: String(doc.name ?? ""),
          summary: plainText(doc.summary),
          language: languageOf(doc),
          indexedMs: Date.now(),
        });
        evict(accounts, maxAccounts);
        return;
      }

      const text = plainText(doc.content);
      content.set(object.uri, {
        uri: object.uri,
        author: attributedTo(doc),
        publishedMs: publishedMs(doc),
        language: languageOf(doc),
        hashtags: extractHashtags(doc, text),
        links: extractLinks(doc),
        text,
      });
      evict(content, maxContent);

      // A content object carries its author's actor, so the account index gets
      // populated for free rather than needing a separate announcement.
      if (object.actor && typeof object.actor.id === "string") {
        const actorId = object.actor.id;
        if (!accounts.has(actorId)) {
          accounts.set(actorId, {
            uri: actorId,
            username: String(object.actor.preferredUsername ?? ""),
            name: String(object.actor.name ?? ""),
            summary: plainText(object.actor.summary),
            language: languageOf(object.actor),
            indexedMs: Date.now(),
          });
          evict(accounts, maxAccounts);
        }
      }
    },

    remove(uri) {
      content.delete(uri);
      accounts.delete(uri);
    },

    accountSearch({ term, limit, cursor }) {
      const needle = term.trim().toLowerCase().replace(/^@/, "");
      const scored = [...accounts.values()]
        .map((a) => {
          const username = a.username.toLowerCase();
          const name = a.name.toLowerCase();
          // Rank exact and prefix matches on the handle above body text, so
          // searching a username does not surface everyone who mentioned it.
          let score = 0;
          if (username === needle) score = 100;
          else if (username.startsWith(needle)) score = 80;
          else if (name.toLowerCase() === needle) score = 70;
          else if (username.includes(needle)) score = 50;
          else if (name.includes(needle)) score = 40;
          else if (a.summary.toLowerCase().includes(needle)) score = 10;
          return { uri: a.uri, score };
        })
        .filter((s) => s.score > 0)
        .sort((a, b) => b.score - a.score || a.uri.localeCompare(b.uri));

      // The cursor is just an offset. It is opaque to the caller by contract,
      // so a real implementation can make it a keyset cursor without breaking
      // anyone.
      const offset = Number.parseInt(cursor ?? "0", 10) || 0;
      const page = scored.slice(offset, offset + limit);
      const nextOffset = offset + page.length;
      return {
        uris: page.map((s) => s.uri),
        nextCursor: nextOffset < scored.length ? String(nextOffset) : undefined,
      };
    },

    trendingContent(query) {
      // Without interaction counts, recency is the only signal available: this
      // index is told that content exists, not how often it was boosted.
      const entries = within(query);
      const newest = Math.max(...entries.map((e) => e.publishedMs), 1);
      const oldest = Math.min(...entries.map((e) => e.publishedMs), newest);
      const span = Math.max(1, newest - oldest);
      return entries
        .map((e) => ({ uri: e.uri, rank: Math.max(1, Math.round(((e.publishedMs - oldest) / span) * 100)) }))
        .sort((a, b) => b.rank - a.rank)
        .slice(0, query.maxCount);
    },

    trendingHashtags(query) {
      const counts = new Map<string, { display: string; count: number; examples: string[] }>();
      for (const entry of within(query)) {
        for (const tag of entry.hashtags) {
          const key = normalizeHashtag(tag);
          const hit = counts.get(key) ?? { display: tag, count: 0, examples: [] };
          hit.count++;
          if (hit.examples.length < 5) hit.examples.push(entry.uri);
          counts.set(key, hit);
        }
      }
      return rankByCount(
        [...counts.values()].map((c) => ({ item: { name: c.display, examples: c.examples }, count: c.count })),
        query.maxCount,
      );
    },

    trendingLinks(query) {
      const counts = new Map<string, { display: string; count: number; examples: string[] }>();
      for (const entry of within(query)) {
        for (const link of entry.links) {
          const key = normalizeLink(link);
          const hit = counts.get(key) ?? { display: key, count: 0, examples: [] };
          hit.count++;
          if (hit.examples.length < 5) hit.examples.push(entry.uri);
          counts.set(key, hit);
        }
      }
      return rankByCount(
        [...counts.values()].map((c) => ({ item: { url: c.display, examples: c.examples }, count: c.count })),
        query.maxCount,
      );
    },

    followRecommendations({ accountUri, language }) {
      // "People who post about what you post about." Crude, but it is a real
      // signal and it demonstrates the shape a better one would take.
      const mine = [...content.values()].filter((e) => e.author === accountUri);
      const myTags = new Set(mine.flatMap((e) => e.hashtags.map(normalizeHashtag)));

      const scores = new Map<string, number>();
      for (const entry of content.values()) {
        if (!entry.author || entry.author === accountUri) continue;
        if (!languageMatches(language, entry.language)) continue;
        const overlap = entry.hashtags.filter((t) => myTags.has(normalizeHashtag(t))).length;
        if (overlap > 0) scores.set(entry.author, (scores.get(entry.author) ?? 0) + overlap);
      }

      return [...scores.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([uri]) => uri);
    },

    stats: () => ({ content: content.size, accounts: accounts.size }),
  };
}
