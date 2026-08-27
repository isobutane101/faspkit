/**
 * Integration tests for the `data_sharing` capability.
 *
 * Three servers, no network:
 *   - a mock fediverse server that the FASP is registered with (subscriptions,
 *     backfill requests),
 *   - a mock *origin* server in the wider fediverse that actually holds the
 *     announced objects and verifies our fetch signatures,
 *   - the FASP under test.
 *
 * The important assertions are the ones where an object is announced and then
 * refused: announcement does not imply consent, and a server telling us about a
 * URI is not permission to index it.
 */
import express from "express";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-ds-"));
process.env.FASPKIT_DATA = DATA_DIR;

import { signRequest, generateKeypair } from "../src/crypto.js";
import { createFasp, registerWithServer } from "../src/server.js";
import { newId, defaultStore } from "../src/store.js";
import {
  dataSharingCapability,
  subscribe,
  unsubscribe,
  requestBackfill,
  continueBackfill,
  retrieveWithConsent,
  revalidate,
  startRevalidation,
  REVALIDATION_INTERVAL_MS,
  ProcessedObject,
  AnnouncementContext,
  DataSharingError,
} from "../src/datasharing.js";
import { generateActorKeypair, actorRoutes, createStyleCache, ActorIdentity } from "../src/activitypub.js";

const FEDI_PORT = 4101;
const ORIGIN_PORT = 4102;
const FASP_PORT = 4103;
const LEGACY_PORT = 4104;
const FEDI_URL = `http://localhost:${FEDI_PORT}`;
const ORIGIN_URL = `http://localhost:${ORIGIN_PORT}`;
const FASP_URL = `http://localhost:${FASP_PORT}`;
const LEGACY_URL = `http://localhost:${LEGACY_PORT}`;

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}
async function waitFor(pred: () => boolean, ms = 4000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return pred();
}

const PUBLIC = "https://www.w3.org/ns/activitystreams#Public";
const ALICE = `${ORIGIN_URL}/users/alice`;
const BOB = `${ORIGIN_URL}/users/bob`;

// ---- Mock fediverse server (the one we are registered with) ----------------
const fediKeys = generateKeypair();
let faspRecord: { serverId: string; publicKey: string; faspId: string } | null = null;
let lastSubscription: unknown = null;
let lastBackfill: unknown = null;
let deletedSubscriptionId: string | null = null;

const fedi = express();
fedi.use(express.json({ verify: (req, _res, buf) => { (req as any).rawBody = buf.toString("utf8"); } }));

fedi.get("/.well-known/nodeinfo", (_req, res) => {
  res.json({ links: [{ rel: "http://nodeinfo.diaspora.software/ns/schema/2.0", href: `${FEDI_URL}/nodeinfo/2.0` }] });
});
fedi.get("/nodeinfo/2.0", (_req, res) => {
  res.json({ version: "2.0", software: { name: "mockodon", version: "4.4.0" }, protocols: ["activitypub"],
    services: { outbound: [], inbound: [] }, openRegistrations: false,
    metadata: { faspBaseUrl: `${FEDI_URL}/fasp` } });
});
fedi.post("/fasp/registration", (req, res) => {
  const faspId = newId();
  faspRecord = { serverId: req.body.serverId, publicKey: req.body.publicKey, faspId };
  res.status(201).json({ faspId, publicKey: fediKeys.publicKey, registrationCompletionUri: `${FEDI_URL}/admin/fasps` });
});

fedi.post("/fasp/data_sharing/v0/event_subscriptions", (req, res) => {
  lastSubscription = req.body;
  // Mirror the spec: the server validates and answers 422 when invalid.
  if (!req.body?.category || !req.body?.subscriptionType) return res.status(422).json({ error: "invalid" });
  if (req.body.category === "account" && req.body.subscriptionType === "trends") {
    return res.status(422).json({ error: "trends is content-only" });
  }
  res.status(201).json({ subscription: { id: "3446" } });
});
fedi.delete("/fasp/data_sharing/v0/event_subscriptions/:id", (req, res) => {
  deletedSubscriptionId = req.params.id;
  res.status(204).end();
});
fedi.post("/fasp/data_sharing/v0/backfill_requests", (req, res) => {
  lastBackfill = req.body;
  res.status(201).json({ backfillRequest: { id: "672" } });
});
fedi.post("/fasp/data_sharing/v0/backfill_requests/:id/continuation", (req, res) => {
  // 204 => more available, 404 => exhausted or unknown id.
  if (req.params.id === "672") return res.status(204).end();
  res.status(404).end();
});
fedi.post("/fasp/data_sharing/v0/backfill_requests/:id/broken", (_req, res) => res.status(500).end());

// ---- Mock origin server (the wider fediverse) ------------------------------
// Serves the actual objects, and verifies that we signed the fetch.
let fetchCounts: Record<string, number> = {};
let seenStyles: Record<string, string> = {};

const origin = express();

function recordFetch(req: express.Request): string {
  fetchCounts[req.path] = (fetchCounts[req.path] ?? 0) + 1;
  const style = req.headers["signature-input"] ? "rfc9421" : req.headers["signature"] ? "cavage" : "unsigned";
  seenStyles[req.path] = style;
  return style;
}

origin.use((req, res, next) => {
  const style = recordFetch(req);
  if (style === "unsigned") return res.status(401).json({ error: "signature required" });
  next();
});

let aliceIndexable = true;
const alice = () => ({ id: ALICE, type: "Person", preferredUsername: "alice", indexable: aliceIndexable, discoverable: true });
const bob = { id: BOB, type: "Person", preferredUsername: "bob", indexable: false, discoverable: false };

const note = (id: string, author: string, to: string[], cc: string[] = []) => ({
  id: `${ORIGIN_URL}${id}`, type: "Note", attributedTo: author, to, cc, content: "hi",
});

origin.get("/users/alice", (_req, res) => res.json(alice()));
origin.get("/users/bob", (_req, res) => res.json(bob));
origin.get("/statuses/public", (_req, res) => res.json(note("/statuses/public", ALICE, [PUBLIC], [`${ALICE}/followers`])));
origin.get("/statuses/unlisted", (_req, res) => res.json(note("/statuses/unlisted", ALICE, [`${ALICE}/followers`], [PUBLIC])));
origin.get("/statuses/by-bob", (_req, res) => res.json(note("/statuses/by-bob", BOB, [PUBLIC])));
origin.get("/statuses/missing", (_req, res) => res.status(404).json({ error: "gone" }));

// ---- Mock legacy origin ----------------------------------------------------
// A separate host that only verifies the older cavage draft, which is what most
// deployed fediverse software still does. The style cache is keyed per host, so
// this has to be its own server to exercise double-knocking honestly.
let legacyAttempts: string[] = [];
const legacy = express();
const LEGACY_ALICE = `${LEGACY_URL}/users/alice`;
legacy.use((req, res, next) => {
  const style = req.headers["signature-input"] ? "rfc9421" : req.headers["signature"] ? "cavage" : "unsigned";
  legacyAttempts.push(`${req.path} ${style}`);
  if (style !== "cavage") return res.status(401).json({ error: "only draft-cavage signatures are supported" });
  next();
});
legacy.get("/users/alice", (_req, res) =>
  res.json({ id: LEGACY_ALICE, type: "Person", preferredUsername: "alice", indexable: true, discoverable: true }));
legacy.get("/statuses/public", (_req, res) =>
  res.json({ id: `${LEGACY_URL}/statuses/public`, type: "Note", attributedTo: LEGACY_ALICE, to: [PUBLIC], content: "hi" }));

// ---- FASP ------------------------------------------------------------------
const identity: ActorIdentity = {
  baseUrl: FASP_URL,
  preferredUsername: "faspkit",
  keypair: generateActorKeypair(2048),
};

const accepted: ProcessedObject[] = [];
const rejected: ProcessedObject[] = [];
const announcements: AnnouncementContext[] = [];
const deletes: string[] = [];
const moreAvailable: string[] = [];

const capability = dataSharingCapability({
  identity,
  styleCache: createStyleCache(),
  timeoutMs: 3000,
  handlers: {
    onAnnouncement: (ctx) => { announcements.push(ctx); },
    onAccepted: (obj) => { accepted.push(obj); },
    onRejected: (obj) => { rejected.push(obj); },
    onDelete: (uri) => { deletes.push(uri); },
    onMoreAvailable: (id) => { moreAvailable.push(id); },
  },
});

const faspOptions = {
  name: "faspkit data_sharing test",
  baseUrl: FASP_URL,
  capabilities: [capability],
};
const fasp = createFasp(faspOptions);
fasp.use(actorRoutes(identity));

const announcementsUrl = `${FASP_URL}/data_sharing/v0/announcements`;

function announce(body: unknown, faspId: string) {
  const payload = JSON.stringify(body);
  const h = signRequest({
    method: "POST", targetUri: announcementsUrl, body: payload,
    keyid: faspId, privateKey: fediKeys.privateKey, nonce: newId(),
  });
  return fetch(announcementsUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-digest": h["content-digest"],
      "signature-input": h["signature-input"],
      signature: h.signature,
    },
    body: payload,
  });
}

async function main() {
  const s1 = fedi.listen(FEDI_PORT);
  const s2 = origin.listen(ORIGIN_PORT);
  const s3 = fasp.listen(FASP_PORT);
  const s4 = legacy.listen(LEGACY_PORT);
  await new Promise((r) => setTimeout(r, 300));

  const reg = await registerWithServer(faspOptions, FEDI_URL);
  const rec = (await defaultStore.getServer(reg.record.serverId))!;
  const faspId = rec.faspId!;

  console.log("\n1. actor and webfinger (required to fetch objects at all)");
  {
    const actorRes = await fetch(`${FASP_URL}/actor`);
    const actor = await actorRes.json();
    check("actor document served at /actor", actorRes.status === 200 && actor.id === `${FASP_URL}/actor`);
    check("actor is an Application", actor.type === "Application");
    check("actor advertises a public key PEM", String(actor.publicKey?.publicKeyPem).includes("BEGIN PUBLIC KEY"));
    check("actor key is separate from the FASP registration key",
      String(actor.publicKey.publicKeyPem) !== rec.ourPublicKey);
    check("actor has inbox and outbox", !!actor.inbox && !!actor.outbox);
    check("actor gives a preferredUsername", actor.preferredUsername === "faspkit");

    const wf = await fetch(`${FASP_URL}/.well-known/webfinger?resource=acct:faspkit@localhost:${FASP_PORT}`);
    const jrd = await wf.json();
    check("webfinger resolves the actor", wf.status === 200 && jrd.links[0].href === `${FASP_URL}/actor`);
    const wrong = await fetch(`${FASP_URL}/.well-known/webfinger?resource=acct:nobody@example.com`);
    check("webfinger 404s an unknown account", wrong.status === 404, `got ${wrong.status}`);
  }

  console.log("\n2. subscription client");
  {
    const id = await subscribe(rec, { category: "content", subscriptionType: "trends", maxBatchSize: 10, threshold: { timeframe: 15, shares: 3 } });
    check("subscribe returns the subscription id", id === "3446", id);
    check("threshold and batch size are sent through", JSON.stringify(lastSubscription).includes('"shares":3'));

    // trends is content-only; catch it before spending a round trip.
    let localReject = false;
    try { await subscribe(rec, { category: "account", subscriptionType: "trends" }); }
    catch (e) { localReject = e instanceof DataSharingError && e.status === 422; }
    check("trends + account rejected without calling the server", localReject);

    let serverReject = false;
    try { await subscribe(rec, { category: "content", subscriptionType: undefined as any }); }
    catch (e) { serverReject = e instanceof DataSharingError && e.status === 422; }
    check("server-side 422 surfaces as a DataSharingError", serverReject);

    await unsubscribe(rec, "3446");
    check("unsubscribe issues DELETE with the id", deletedSubscriptionId === "3446", String(deletedSubscriptionId));
  }

  console.log("\n3. backfill client");
  {
    const id = await requestBackfill(rec, { category: "content", maxCount: 100 });
    check("requestBackfill returns the request id", id === "672", id);
    check("category and maxCount are sent", JSON.stringify(lastBackfill) === '{"category":"content","maxCount":100}');

    check("continuation returns true on 204 (more available)", (await continueBackfill(rec, "672")) === true);
    check("continuation returns false on 404 (exhausted)", (await continueBackfill(rec, "999")) === false);
  }

  console.log("\n4. announcement endpoint");
  {
    const unsigned = await fetch(announcementsUrl, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: { subscription: { id: "1" } }, category: "content", objectUris: ["x"] }),
    });
    check("unsigned announcement rejected with 401", unsigned.status === 401, `got ${unsigned.status}`);

    const res = await announce({
      source: { subscription: { id: "3446" } },
      category: "content",
      eventType: "new",
      objectUris: [`${ORIGIN_URL}/statuses/public`],
    }, faspId);
    check("valid announcement answers 204 as the spec requires", res.status === 204, `got ${res.status}`);
    check("204 carries no body", (await res.text()) === "");

    for (const [label, body] of [
      ["missing objectUris", { source: { subscription: { id: "1" } }, category: "content" }],
      ["empty objectUris", { source: { subscription: { id: "1" } }, category: "content", objectUris: [] }],
      ["missing source", { category: "content", objectUris: ["x"] }],
      ["bad category", { source: { subscription: { id: "1" } }, category: "nonsense", objectUris: ["x"] }],
      ["unknown eventType", { source: { subscription: { id: "1" } }, category: "content", eventType: "exploded", objectUris: ["x"] }],
      ["eventType on a backfill response", { source: { backfillRequest: { id: "1" } }, category: "content", eventType: "new", objectUris: ["x"] }],
    ] as [string, unknown][]) {
      const r = await announce(body, faspId);
      check(`${label} rejected with 422`, r.status === 422, `got ${r.status}`);
    }
  }

  console.log("\n5. consent gate on announced objects");
  {
    accepted.length = 0; rejected.length = 0;
    await announce({
      source: { subscription: { id: "3446" } },
      category: "content",
      eventType: "new",
      objectUris: [
        `${ORIGIN_URL}/statuses/unlisted`,
        `${ORIGIN_URL}/statuses/by-bob`,
        `${ORIGIN_URL}/statuses/missing`,
      ],
    }, faspId);

    await waitFor(() => rejected.length >= 3);
    check("nothing was accepted", accepted.length === 0, JSON.stringify(accepted.map((a) => a.uri)));
    check("all three were rejected", rejected.length === 3, String(rejected.length));

    const reasonFor = (frag: string) => rejected.find((r) => r.uri.includes(frag))?.reason ?? "";
    check("unlisted post rejected as unlisted", reasonFor("unlisted").includes("unlisted"), reasonFor("unlisted"));
    check("post by an opted-out author rejected via FEP-5feb", reasonFor("by-bob").includes("FEP-5feb"), reasonFor("by-bob"));
    check("unfetchable object rejected, not skipped silently", reasonFor("missing").length > 0, reasonFor("missing"));

    // A rejected URI stays recorded, so the origin is not re-fetched every
    // time another connected server mentions the same object.
    check("rejected URIs stay in the seen set", await defaultStore.hasSeen(`${ORIGIN_URL}/statuses/unlisted`));
  }

  console.log("\n6. accepted content");
  {
    accepted.length = 0; rejected.length = 0;
    fetchCounts = {};
    await announce({
      source: { subscription: { id: "3446" } }, category: "content", eventType: "new",
      objectUris: [`${ORIGIN_URL}/statuses/public`],
    }, faspId);
    await waitFor(() => accepted.length + rejected.length >= 1);
    // It was already announced in section 4, so this is a duplicate.
    check("a repeat announcement is deduplicated, not refetched",
      accepted.length === 0 && rejected.length === 0 && !fetchCounts["/statuses/public"],
      JSON.stringify({ accepted: accepted.length, rejected: rejected.length, fetches: fetchCounts }));

    // A URI never seen before is fetched and accepted.
    accepted.length = 0;
    await announce({
      source: { subscription: { id: "3446" } }, category: "content", eventType: "new",
      objectUris: [`${LEGACY_URL}/statuses/public`],
    }, faspId);
    check("public post by an opted-in author is accepted", await waitFor(() => accepted.length === 1),
      JSON.stringify(rejected.map((r) => [r.uri, r.reason])));
    check("the accepted document is passed to the handler",
      accepted[0]?.document?.id === `${LEGACY_URL}/statuses/public`);
    check("the author's actor is passed along too", accepted[0]?.actor?.id === LEGACY_ALICE);
  }

  console.log("\n7. double-knocking");
  {
    check("RFC 9421 was tried first against the legacy host",
      legacyAttempts[0] === "/statuses/public rfc9421", JSON.stringify(legacyAttempts.slice(0, 2)));
    check("cavage was tried after the 401",
      legacyAttempts[1] === "/statuses/public cavage", JSON.stringify(legacyAttempts.slice(0, 2)));
    check("the actor fetch went straight to cavage using the cached style",
      legacyAttempts.includes("/users/alice cavage") && !legacyAttempts.includes("/users/alice rfc9421"),
      JSON.stringify(legacyAttempts));
    check("no host ever saw an unsigned fetch",
      !Object.values(seenStyles).includes("unsigned") && !legacyAttempts.some((a) => a.endsWith("unsigned")),
      JSON.stringify({ seenStyles, legacyAttempts }));

    // A modern host is reached first try, and the style is cached per host.
    const cache = createStyleCache();
    const first = await retrieveWithConsent(`${ORIGIN_URL}/statuses/public`, "content", { identity, styleCache: cache });
    check("modern host served over RFC 9421", first.accepted, first.reason ?? "");
    check("style cache remembers the host", cache.get(`localhost:${ORIGIN_PORT}`) === "rfc9421");

    // A stale cache entry must not strand us: if the remembered style starts
    // failing auth, the other one is still tried.
    const stale = createStyleCache();
    stale.set(`localhost:${LEGACY_PORT}`, "rfc9421");
    legacyAttempts = [];
    const recovered = await retrieveWithConsent(`${LEGACY_URL}/statuses/public`, "content", { identity, styleCache: stale });
    check("a stale cached style falls back to the other one", recovered.accepted, recovered.reason ?? "");
    check("the cache is corrected after the fallback", stale.get(`localhost:${LEGACY_PORT}`) === "cavage");
  }

  console.log("\n8. account category");
  {
    accepted.length = 0; rejected.length = 0;
    await announce({
      source: { subscription: { id: "3446" } }, category: "account", eventType: "new",
      objectUris: [ALICE, BOB],
    }, faspId);
    await waitFor(() => accepted.length + rejected.length >= 2);
    check("discoverable + indexable account accepted", accepted.some((a) => a.uri === ALICE), JSON.stringify(accepted.map((a) => a.uri)));
    check("account with neither flag rejected", rejected.some((r) => r.uri === BOB));
    check("account rejection names discoverable",
      (rejected.find((r) => r.uri === BOB)?.reason ?? "").includes("discoverable"));
  }

  console.log("\n9. deletes and backfill continuation");
  {
    deletes.length = 0;
    const before = await defaultStore.seenCount();
    await announce({
      source: { subscription: { id: "3446" } }, category: "content", eventType: "delete",
      objectUris: [`${ORIGIN_URL}/statuses/public`],
    }, faspId);
    check("delete event dispatched to onDelete", await waitFor(() => deletes.length === 1));
    check("deleted URI is forgotten so it can be re-indexed later",
      !(await defaultStore.hasSeen(`${ORIGIN_URL}/statuses/public`)) && (await defaultStore.seenCount()) < before);

    moreAvailable.length = 0;
    await announce({
      source: { backfillRequest: { id: "672" } }, category: "content",
      objectUris: [`${ORIGIN_URL}/statuses/backfilled`], moreObjectsAvailable: true,
    }, faspId);
    check("backfill announcement signalling more content triggers onMoreAvailable",
      await waitFor(() => moreAvailable.includes("672")), JSON.stringify(moreAvailable));

    const backfillCtx = announcements.at(-1)!;
    check("backfill announcement carries no eventType", backfillCtx.announcement.eventType === undefined);
    check("backfill source is recognised", backfillCtx.announcement.source.backfillRequest?.id === "672");
  }

  console.log("\n10. deduplication across servers");
  {
    accepted.length = 0; rejected.length = 0;
    fetchCounts = {};
    const uri = `${ORIGIN_URL}/statuses/public`;
    const ctxBefore = announcements.length;
    // The same URI announced twice, as two connected servers would.
    await announce({ source: { subscription: { id: "3446" } }, category: "content", eventType: "new", objectUris: [uri] }, faspId);
    await waitFor(() => announcements.length > ctxBefore);
    await announce({ source: { subscription: { id: "3446" } }, category: "content", eventType: "new", objectUris: [uri] }, faspId);
    await waitFor(() => announcements.length > ctxBefore + 1);
    await waitFor(() => accepted.length >= 1);

    const first = announcements.at(-2)!;
    const second = announcements.at(-1)!;
    check("the first announcement treats the URI as fresh", first.freshUris.includes(uri),
      JSON.stringify({ fresh: first.freshUris, dup: first.duplicateUris }));
    check("the second announcement reports the URI as a duplicate", second.duplicateUris.includes(uri),
      JSON.stringify({ fresh: second.freshUris, dup: second.duplicateUris }));
    check("the second announcement has nothing fresh to retrieve", second.freshUris.length === 0);
    check("the object was fetched exactly once", fetchCounts["/statuses/public"] === 1,
      JSON.stringify(fetchCounts));

    // `update` exists to say a known object changed, so it must not be deduped
    // away — that notification is the only one we get.
    const beforeUpdate = announcements.length;
    await announce({ source: { subscription: { id: "3446" } }, category: "content", eventType: "update", objectUris: [uri] }, faspId);
    await waitFor(() => announcements.length > beforeUpdate);
    await waitFor(() => (fetchCounts["/statuses/public"] ?? 0) >= 2);
    const updateCtx = announcements.at(-1)!;
    check("an update event bypasses deduplication", updateCtx.freshUris.includes(uri),
      JSON.stringify({ fresh: updateCtx.freshUris, dup: updateCtx.duplicateUris }));
    check("the changed object is refetched", fetchCounts["/statuses/public"] === 2,
      JSON.stringify(fetchCounts));
  }

  console.log("\n11. revalidation");
  {
    check("the spec floor is one week", REVALIDATION_INTERVAL_MS === 7 * 24 * 60 * 60 * 1000);

    // Index a fresh public post by an opted-in author.
    accepted.length = 0;
    const uri = `${ORIGIN_URL}/statuses/revalidate-me`;
    origin.get("/statuses/revalidate-me", (_req, res) =>
      res.json({ id: uri, type: "Note", attributedTo: ALICE, to: [PUBLIC], content: "hi" }));
    await announce({
      source: { subscription: { id: "3446" } }, category: "content", eventType: "new", objectUris: [uri],
    }, faspId);
    check("the object is accepted and indexed", await waitFor(() => accepted.some((a) => a.uri === uri)),
      JSON.stringify(rejected.map((r) => [r.uri, r.reason])));
    check("an accepted object is recorded for revalidation",
      (await defaultStore.listIndexed()).some((r) => r.uri === uri));

    // Nothing is due yet, so a pass does no work.
    const idle = await revalidate({ identity, store: defaultStore });
    check("nothing is due immediately after indexing", idle.checked === 0, JSON.stringify(idle));

    // Backdate the check clock to make this record due, rather than relying on
    // maxAgeMs: 0 plus millisecond timing to decide what counts as overdue.
    const weekAgo = () => new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    await defaultStore.markRevalidated(uri, weekAgo());

    const revoked: string[] = [];
    const revalidated: string[] = [];
    const fresh = await revalidate({
      identity, store: defaultStore, maxAgeMs: 0,
      handlers: { onRevoked: (u) => { revoked.push(u); }, onRevalidated: (o) => { revalidated.push(o.uri); } },
    });
    check("a due pass re-checks the object", fresh.checked > 0, JSON.stringify(fresh));
    check("it is still allowed", revalidated.includes(uri), JSON.stringify({ revalidated, revoked }));
    check("and is not revoked", !revoked.includes(uri));
    check("the check clock was reset",
      (await defaultStore.listIndexed({ checkedBefore: new Date(Date.now() - 1000) })).every((r) => r.uri !== uri));

    // The acceptance case: the author withdraws consent.
    aliceIndexable = false;
    revoked.length = 0; revalidated.length = 0;
    await defaultStore.markRevalidated(uri, weekAgo());
    const afterOptOut = await revalidate({
      identity, store: defaultStore, maxAgeMs: 0,
      handlers: { onRevoked: (u) => { revoked.push(u); }, onRevalidated: (o) => { revalidated.push(o.uri); } },
    });
    check("an author opting out revokes their indexed content", revoked.includes(uri),
      JSON.stringify({ revoked, revalidated, afterOptOut }));
    check("the revoked record is dropped from the index",
      !(await defaultStore.listIndexed()).some((r) => r.uri === uri));
    check("and from the dedup set, so it can return if consent comes back",
      !(await defaultStore.hasSeen(uri)));
    check("the summary counts it", afterOptOut.revoked >= 1, JSON.stringify(afterOptOut));
    aliceIndexable = true;

    // A limited pass takes the most overdue first, so a large index drains.
    const limited = await revalidate({ identity, store: defaultStore, maxAgeMs: 0, limit: 1 });
    check("limit caps how much one pass does", limited.checked <= 1, JSON.stringify(limited));

    const stop = startRevalidation({ identity, store: defaultStore, everyMs: 60_000 });
    check("startRevalidation returns a stop function", typeof stop === "function");
    stop();
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  s1.close(); s2.close(); s3.close(); s4.close();
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}

main();
