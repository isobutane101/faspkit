/**
 * Consent enforcement for shared content.
 *
 * This is the part of `data_sharing` that matters most, and the part it is
 * easiest to get quietly wrong. The rules come from two documents:
 *
 * - discovery/data_sharing/v0.1: a FASP MUST check the `to:` property to
 *   confirm content is really meant for public consumption, MUST verify the
 *   creator opted in to discovery via FEP-5feb, and for accounts MUST confirm
 *   `discoverable` is true.
 * - FEP-5feb: consent lives on the *actor* as an `indexable` attribute, and a
 *   missing attribute is to be treated as `indexable: false`.
 *
 * Two consequences worth stating plainly, because both are easy to miss:
 *
 * 1. Consent is deny-by-default. Absent, malformed, or unfetchable data is a
 *    rejection, never a pass.
 * 2. Public addressing means the Public collection appears in `to`. Mastodon's
 *    "unlisted" / "quiet public" posts carry Public in `cc` instead, and are
 *    publicly fetchable — which is exactly why checking "is it reachable?" or
 *    looking at `to` and `cc` together silently indexes content the spec
 *    forbids. Only `to` counts.
 *
 * Pure functions, no I/O, so the rules can be tested against fixtures.
 */

/** The three spellings of the public collection in circulation. */
const PUBLIC_ALIASES = new Set([
  "https://www.w3.org/ns/activitystreams#Public",
  "as:Public",
  "Public",
]);

export type JsonObject = Record<string, unknown>;

export interface ConsentResult {
  allowed: boolean;
  /** Why it was rejected, for the audit log. Absent when allowed. */
  reason?: string;
}

const ALLOW: ConsentResult = { allowed: true };
const deny = (reason: string): ConsentResult => ({ allowed: false, reason });

/** Normalise a JSON-LD value that may be a string, an object, or an array. */
function asArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function idsOf(value: unknown): string[] {
  return asArray(value)
    .map((v) => {
      if (typeof v === "string") return v;
      if (v && typeof v === "object" && typeof (v as JsonObject).id === "string") {
        return (v as JsonObject).id as string;
      }
      return undefined;
    })
    .filter((v): v is string => v !== undefined);
}

/**
 * Read a property that may appear under several JSON-LD spellings: the plain
 * term, the `toot:` prefix, or the full IRI. Which one arrives depends on how
 * the origin server compacted its document.
 */
function readNamespaced(obj: JsonObject, term: string): unknown {
  const candidates = [term, `toot:${term}`, `http://joinmastodon.org/ns#${term}`];
  for (const key of candidates) {
    if (key in obj) return obj[key];
  }
  return undefined;
}

/** A strict boolean read: only a real `true` counts as consent. */
function isExplicitlyTrue(value: unknown): boolean {
  return value === true;
}

/**
 * True when the object is addressed to the public collection via `to`.
 *
 * Deliberately ignores `cc`. Public-in-`cc`-only is Mastodon's unlisted
 * visibility, which the data_sharing spec forbids sharing.
 */
export function isPubliclyAddressed(object: JsonObject): boolean {
  return idsOf(object.to).some((id) => PUBLIC_ALIASES.has(id));
}

/** True when the object carries Public in `cc` but not `to` — i.e. unlisted. */
export function isUnlisted(object: JsonObject): boolean {
  if (isPubliclyAddressed(object)) return false;
  return idsOf(object.cc).some((id) => PUBLIC_ALIASES.has(id));
}

/**
 * Whether an actor has opted in to search indexing (FEP-5feb).
 * A missing attribute is treated as `false`.
 */
export function isIndexable(actor: JsonObject): boolean {
  return isExplicitlyTrue(readNamespaced(actor, "indexable"));
}

/** Whether an actor has set Mastodon's `discoverable` flag. */
export function isDiscoverable(actor: JsonObject): boolean {
  return isExplicitlyTrue(readNamespaced(actor, "discoverable"));
}

/** The actor URI that authored an object, however the origin spelled it. */
export function attributedTo(object: JsonObject): string | undefined {
  return idsOf(object.attributedTo)[0] ?? idsOf(object.actor)[0];
}

/**
 * Decide whether a retrieved content object may be indexed.
 *
 * `actor` is the object's author, which the caller must fetch separately:
 * FEP-5feb puts consent on the actor, so an object alone can never establish it.
 */
export function evaluateContent(object: JsonObject, actor: JsonObject | undefined): ConsentResult {
  if (object.type === "Tombstone") return deny("object is a Tombstone (deleted)");
  if (isUnlisted(object)) return deny("unlisted / quiet public visibility (Public in cc, not to)");
  if (!isPubliclyAddressed(object)) return deny("not addressed to the public collection");

  const author = attributedTo(object);
  if (!author) return deny("object has no attributedTo, so consent cannot be established");
  if (!actor) return deny(`author ${author} could not be retrieved`);

  const actorId = typeof actor.id === "string" ? actor.id : undefined;
  if (actorId !== author) {
    return deny(`author mismatch: object claims ${author}, actor document is ${actorId ?? "unidentified"}`);
  }
  if (!isIndexable(actor)) return deny(`author ${author} has not opted in to indexing (FEP-5feb)`);

  return ALLOW;
}

/** Decide whether a retrieved actor may be indexed as an account. */
export function evaluateAccount(actor: JsonObject): ConsentResult {
  // The data_sharing spec requires `discoverable`; FEP-5feb requires
  // `indexable`. Both apply to account data, and both default to deny.
  if (!isDiscoverable(actor)) return deny("actor has not set discoverable: true");
  if (!isIndexable(actor)) return deny("actor has not opted in to indexing (FEP-5feb)");
  return ALLOW;
}
