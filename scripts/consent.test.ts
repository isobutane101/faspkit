/**
 * Consent-gate tests for the `data_sharing` capability.
 *
 * The spec's requirements here are the ones with real consequences for real
 * people: indexing a post whose author did not opt in, or an "unlisted" post
 * that is technically fetchable, is exactly the failure this gate exists to
 * prevent. So these fixtures are deliberately adversarial — every plausible way
 * a document could sneak past is asserted to fail closed.
 */
import {
  isPubliclyAddressed,
  isUnlisted,
  isIndexable,
  isDiscoverable,
  attributedTo,
  evaluateContent,
  evaluateAccount,
  JsonObject,
} from "../src/consent.js";

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}

const PUBLIC = "https://www.w3.org/ns/activitystreams#Public";
const AUTHOR = "https://example.social/users/alice";
const FOLLOWERS = `${AUTHOR}/followers`;

/** An actor who has opted in to indexing. */
const indexableActor: JsonObject = {
  id: AUTHOR,
  type: "Person",
  preferredUsername: "alice",
  indexable: true,
  discoverable: true,
};

/** The same actor, having not opted in. */
const optedOutActor: JsonObject = { id: AUTHOR, type: "Person", preferredUsername: "alice" };

/** A public post: Public in `to`. */
const publicNote: JsonObject = {
  id: "https://example.social/users/alice/statuses/1",
  type: "Note",
  attributedTo: AUTHOR,
  to: [PUBLIC],
  cc: [FOLLOWERS],
  content: "hello world",
};

/** Mastodon "unlisted" / "quiet public": Public in `cc`, followers in `to`. */
const unlistedNote: JsonObject = {
  id: "https://example.social/users/alice/statuses/2",
  type: "Note",
  attributedTo: AUTHOR,
  to: [FOLLOWERS],
  cc: [PUBLIC],
  content: "quietly public",
};

/** Followers-only. */
const privateNote: JsonObject = {
  id: "https://example.social/users/alice/statuses/3",
  type: "Note",
  attributedTo: AUTHOR,
  to: [FOLLOWERS],
  cc: [],
  content: "just for followers",
};

console.log("\n1. public addressing");
{
  check("Public in `to` is public", isPubliclyAddressed(publicNote));
  check("Public in `cc` only is NOT public", !isPubliclyAddressed(unlistedNote));
  check("followers-only is not public", !isPubliclyAddressed(privateNote));
  check("unlisted is detected as unlisted", isUnlisted(unlistedNote));
  check("a genuinely public post is not flagged unlisted", !isUnlisted(publicNote));
  check("followers-only is not 'unlisted' either", !isUnlisted(privateNote));

  // The public collection has three spellings in circulation.
  for (const alias of [PUBLIC, "as:Public", "Public"]) {
    check(`"${alias}" recognised as the public collection`, isPubliclyAddressed({ to: [alias] }));
  }
  check("a lookalike collection URI is not accepted", !isPubliclyAddressed({ to: ["https://example.com/Public"] }));

  // `to` may be a bare string or contain objects rather than strings.
  check("`to` as a bare string works", isPubliclyAddressed({ to: PUBLIC }));
  check("`to` containing objects with ids works", isPubliclyAddressed({ to: [{ id: PUBLIC }] }));
  check("missing `to` is not public", !isPubliclyAddressed({}));
  check("null `to` is not public", !isPubliclyAddressed({ to: null }));
}

console.log("\n2. FEP-5feb opt-in (actor level)");
{
  check("indexable: true is opt-in", isIndexable(indexableActor));
  check("a missing indexable attribute is treated as false", !isIndexable(optedOutActor));
  check("indexable: false is opt-out", !isIndexable({ indexable: false }));

  // JSON-LD compaction may leave the term prefixed or as a full IRI.
  check("toot:indexable is honoured", isIndexable({ "toot:indexable": true }));
  check("the full IRI form is honoured", isIndexable({ "http://joinmastodon.org/ns#indexable": true }));

  // Only a real boolean true counts; truthy strings must not slip through.
  for (const value of ["true", 1, "yes", {}, []] as unknown[]) {
    check(`indexable: ${JSON.stringify(value)} does not count as consent`, !isIndexable({ indexable: value }));
  }

  check("discoverable: true is detected", isDiscoverable({ discoverable: true }));
  check("missing discoverable is false", !isDiscoverable({}));
  check("discoverable: \"true\" (string) does not count", !isDiscoverable({ discoverable: "true" }));
}

console.log("\n3. content decisions — the mandatory fixtures");
{
  const publicResult = evaluateContent(publicNote, indexableActor);
  check("public post by an opted-in author is ACCEPTED", publicResult.allowed, publicResult.reason ?? "");

  const unlistedResult = evaluateContent(unlistedNote, indexableActor);
  check("unlisted post is REJECTED even though the author opted in", !unlistedResult.allowed);
  check("rejection names unlisted visibility", (unlistedResult.reason ?? "").includes("unlisted"), unlistedResult.reason ?? "");

  const privateResult = evaluateContent(privateNote, indexableActor);
  check("followers-only post is REJECTED", !privateResult.allowed);

  const optedOutResult = evaluateContent(publicNote, optedOutActor);
  check("public post by an author who has NOT opted in is REJECTED", !optedOutResult.allowed);
  check("rejection cites FEP-5feb", (optedOutResult.reason ?? "").includes("FEP-5feb"), optedOutResult.reason ?? "");

  // The gate must fail closed when the author cannot be established at all.
  check("post with an unreachable author is REJECTED", !evaluateContent(publicNote, undefined).allowed);
  check("post with no attributedTo is REJECTED", !evaluateContent({ to: [PUBLIC] }, indexableActor).allowed);

  // An actor document that does not match the claimed author proves nothing —
  // otherwise anyone could launder consent through their own opted-in actor.
  const impostor = evaluateContent(publicNote, { ...indexableActor, id: "https://elsewhere.example/users/mallory" });
  check("actor document for a different account is REJECTED", !impostor.allowed);
  check("rejection names the mismatch", (impostor.reason ?? "").includes("mismatch"), impostor.reason ?? "");

  // A deleted object arrives as a Tombstone and must never be indexed.
  check("a Tombstone is REJECTED", !evaluateContent({ type: "Tombstone", to: [PUBLIC], attributedTo: AUTHOR }, indexableActor).allowed);

  // An empty document must not pass by omission.
  check("an empty document is REJECTED", !evaluateContent({}, indexableActor).allowed);
}

console.log("\n4. account decisions");
{
  const ok = evaluateAccount(indexableActor);
  check("actor with discoverable + indexable is ACCEPTED", ok.allowed, ok.reason ?? "");

  const noDiscover = evaluateAccount({ id: AUTHOR, indexable: true });
  check("actor without discoverable is REJECTED", !noDiscover.allowed);
  check("rejection names discoverable", (noDiscover.reason ?? "").includes("discoverable"), noDiscover.reason ?? "");

  const noIndex = evaluateAccount({ id: AUTHOR, discoverable: true });
  check("actor without indexable is REJECTED", !noIndex.allowed);

  check("bare actor with neither flag is REJECTED", !evaluateAccount({ id: AUTHOR }).allowed);
  check("explicitly opted-out actor is REJECTED", !evaluateAccount({ id: AUTHOR, discoverable: false, indexable: false }).allowed);
}

console.log("\n5. author extraction");
{
  check("attributedTo as a string", attributedTo({ attributedTo: AUTHOR }) === AUTHOR);
  check("attributedTo as an array", attributedTo({ attributedTo: [AUTHOR] }) === AUTHOR);
  check("attributedTo as an object with an id", attributedTo({ attributedTo: { id: AUTHOR } }) === AUTHOR);
  check("falls back to actor", attributedTo({ actor: AUTHOR }) === AUTHOR);
  check("absent author is undefined", attributedTo({}) === undefined);
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
