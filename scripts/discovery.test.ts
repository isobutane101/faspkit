/**
 * Tests for the three discovery capabilities, and for the whole FASP layer
 * working end to end.
 *
 * Section 6 is the one that matters: content is announced by a fediverse
 * server, fetched from its origin, passed through the consent gate, indexed,
 * and then queried back out over signed HTTP through all three capabilities.
 * Everything before it tests the protocol edges in isolation.
 */
import express from "express";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-disc-"));
process.env.FASPKIT_DATA = DATA_DIR;

import { signRequest, generateKeypair, verifyResponse } from "../src/crypto.js";
import { createFasp, registerWithServer, sendSigned } from "../src/server.js";
import { newId, defaultStore } from "../src/store.js";
import { dataSharingCapability } from "../src/datasharing.js";
import {
  accountSearchCapability,
  trendsCapability,
  followRecommendationCapability,
  positiveInteger,
  languageMatches,
  parseTrendsQuery,
  DEFAULT_WITHIN_LAST_HOURS,
  DEFAULT_MAX_COUNT,
} from "../src/discovery.js";
import { createReferenceIndex, normalizeHashtag, normalizeLink, extractHashtags, extractLinks } from "../src/refindex.js";
import { generateActorKeypair, ActorIdentity } from "../src/activitypub.js";

const FEDI_PORT = 4201;
const ORIGIN_PORT = 4202;
const FASP_PORT = 4203;
const FEDI_URL = `http://localhost:${FEDI_PORT}`;
const ORIGIN_URL = `http://localhost:${ORIGIN_PORT}`;
const FASP_URL = `http://localhost:${FASP_PORT}`;

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}
async function waitFor(pred: () => boolean, ms = 5000): Promise<boolean> {
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

// ---- Mock fediverse server -------------------------------------------------
const fediKeys = generateKeypair();
const fedi = express();
fedi.use(express.json({ verify: (req, _res, buf) => { (req as any).rawBody = buf.toString("utf8"); } }));
fedi.get("/.well-known/nodeinfo", (_req, res) =>
  res.json({ links: [{ rel: "nodeinfo", href: `${FEDI_URL}/nodeinfo/2.0` }] }));
fedi.get("/nodeinfo/2.0", (_req, res) => res.json({ metadata: { faspBaseUrl: `${FEDI_URL}/fasp` } }));
fedi.post("/fasp/registration", (req, res) =>
  res.status(201).json({
    faspId: newId(),
    publicKey: fediKeys.publicKey,
    registrationCompletionUri: `${FEDI_URL}/admin/fasps`,
  }));

// ---- Mock origin server ----------------------------------------------------
const origin = express();
origin.use((req, res, next) => {
  if (!req.headers["signature-input"] && !req.headers["signature"]) {
    return res.status(401).json({ error: "signature required" });
  }
  next();
});

const actor = (uri: string, username: string, name: string, summary: string, opts: Record<string, unknown> = {}) => ({
  id: uri, type: "Person", preferredUsername: username, name, summary,
  indexable: true, discoverable: true, ...opts,
});

origin.get("/users/alice", (_req, res) => res.json(actor(ALICE, "alice", "Alice Example", "I like teapots and cats")));
origin.get("/users/bob", (_req, res) => res.json(actor(BOB, "bob", "Bob Example", "Mostly cats")));

// Alice: two posts about #cats, one linking out. Bob: one #cats post.
const notes: Record<string, unknown> = {
  "/statuses/a1": {
    id: `${ORIGIN_URL}/statuses/a1`, type: "Note", attributedTo: ALICE, to: [PUBLIC],
    published: new Date().toISOString(), language: "en",
    content: '<p>Look at my <a href="https://blog.example.com/cats">cats post</a> <a href="#">#cats</a></p>',
    tag: [{ type: "Hashtag", name: "#cats", href: `${ORIGIN_URL}/tags/cats` }],
  },
  "/statuses/a2": {
    id: `${ORIGIN_URL}/statuses/a2`, type: "Note", attributedTo: ALICE, to: [PUBLIC],
    published: new Date().toISOString(), language: "en",
    content: "<p>More #Cats and #teapots</p>",
    tag: [{ type: "Hashtag", name: "#Cats" }, { type: "Hashtag", name: "#teapots" }],
  },
  "/statuses/b1": {
    id: `${ORIGIN_URL}/statuses/b1`, type: "Note", attributedTo: BOB, to: [PUBLIC],
    published: new Date().toISOString(), language: "en",
    content: '<p>#cats forever <a href="https://blog.example.com/cats">same link</a></p>',
    tag: [{ type: "Hashtag", name: "#cats" }],
  },
  "/statuses/fr1": {
    id: `${ORIGIN_URL}/statuses/fr1`, type: "Note", attributedTo: BOB, to: [PUBLIC],
    published: new Date().toISOString(), language: "fr",
    content: "<p>#chats en français</p>",
    tag: [{ type: "Hashtag", name: "#chats" }],
  },
};
for (const [p, doc] of Object.entries(notes)) origin.get(p, (_req, res) => res.json(doc));

// ---- FASP ------------------------------------------------------------------
const identity: ActorIdentity = {
  baseUrl: FASP_URL, preferredUsername: "faspkit", keypair: generateActorKeypair(2048),
};
const index = createReferenceIndex();
const accepted: string[] = [];

const faspOptions = {
  name: "faspkit discovery test",
  baseUrl: FASP_URL,
  capabilities: [
    dataSharingCapability({
      identity,
      handlers: {
        onAccepted: (obj, ctx) => { index.add(obj, ctx.announcement.category); accepted.push(obj.uri); },
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
};
const fasp = createFasp(faspOptions);

let faspId = "";
function signedGet(url: string) {
  const h = signRequest({
    method: "GET", targetUri: url, body: "", keyid: faspId,
    privateKey: fediKeys.privateKey, nonce: newId(),
  });
  return fetch(url, {
    headers: {
      "content-digest": h["content-digest"],
      "signature-input": h["signature-input"],
      signature: h.signature,
    },
  });
}
function announce(body: unknown) {
  const payload = JSON.stringify(body);
  const url = `${FASP_URL}/data_sharing/v0/announcements`;
  const h = signRequest({
    method: "POST", targetUri: url, body: payload, keyid: faspId,
    privateKey: fediKeys.privateKey, nonce: newId(),
  });
  return fetch(url, {
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
  await new Promise((r) => setTimeout(r, 300));

  const reg = await registerWithServer(faspOptions, FEDI_URL);
  faspId = reg.record.faspId!;
  const rec = (await defaultStore.getServer(reg.record.serverId))!;
  const verifyKey = (keyid: string) => (keyid === rec.serverId ? rec.ourPublicKey : undefined);

  console.log("\n1. parameter parsing");
  {
    check("absent is undefined", positiveInteger(undefined) === undefined);
    check("empty is undefined", positiveInteger("") === undefined);
    check("a positive integer parses", positiveInteger("10") === 10);
    check("zero is rejected", positiveInteger("0") === null);
    check("negative is rejected", positiveInteger("-5") === null);
    check("non-numeric is rejected", positiveInteger("abc") === null);
    check("a decimal is rejected", positiveInteger("10.5") === null);
    check("an array takes the first value", positiveInteger(["7", "9"]) === 7);
  }

  console.log("\n2. RFC 4647 basic filtering");
  {
    check("no range matches anything", languageMatches(undefined, "en"));
    check("wildcard matches anything", languageMatches("*", "de"));
    check("exact match", languageMatches("en", "en"));
    check("case-insensitive", languageMatches("EN", "en-GB"));
    check("prefix match on a subtag boundary", languageMatches("en", "en-GB"));
    check("does NOT match a longer primary tag", !languageMatches("en", "eng"));
    check("different language does not match", !languageMatches("en", "de"));
    check("a range with no tag does not match", !languageMatches("en", undefined));
  }

  console.log("\n3. trends query defaults and clamping");
  {
    const d = parseTrendsQuery({});
    check("withinLastHours defaults to 24", !("error" in d) && d.withinLastHours === DEFAULT_WITHIN_LAST_HOURS);
    check("maxCount defaults to 20", !("error" in d) && d.maxCount === DEFAULT_MAX_COUNT);

    const w = parseTrendsQuery({ withinLastHours: "168", maxCount: "5", language: "fr" });
    check("a week is honoured, as the spec requires",
      !("error" in w) && w.withinLastHours === 168 && w.maxCount === 5 && w.language === "fr");

    const clamped = parseTrendsQuery({ withinLastHours: "100000" });
    check("an oversized window is clamped, not rejected",
      !("error" in clamped) && clamped.withinLastHours === 168);

    check("a bad withinLastHours is a 422", "error" in parseTrendsQuery({ withinLastHours: "soon" }));
    check("a bad maxCount is a 422", "error" in parseTrendsQuery({ maxCount: "-1" }));
  }

  console.log("\n4. normalisation and extraction");
  {
    check("hashtags fold case", normalizeHashtag("#Cats") === normalizeHashtag("#cats"));
    check("a missing # is added", normalizeHashtag("cats") === "#cats");
    check("link host folds case",
      normalizeLink("https://EXAMPLE.com/test") === normalizeLink("https://example.com/test"));
    check("fragments are dropped",
      normalizeLink("https://example.com/a#frag") === "https://example.com/a");
    check("a bare trailing slash is dropped",
      normalizeLink("https://example.com/") === "https://example.com");
    check("paths stay case-sensitive",
      normalizeLink("https://example.com/A") !== normalizeLink("https://example.com/a"));

    const doc = notes["/statuses/a2"] as any;
    const tags = extractHashtags(doc, "More #Cats and #teapots");
    check("hashtags come from the tag array", tags.includes("#Cats") && tags.includes("#teapots"));
    const linked = extractLinks(notes["/statuses/a1"] as any);
    check("outbound links are extracted", linked.includes("https://blog.example.com/cats"));
    check("hashtag hrefs are not treated as links",
      !extractLinks(notes["/statuses/a1"] as any).includes(`${ORIGIN_URL}/tags/cats`));
  }

  console.log("\n5. protocol edges over signed HTTP");
  {
    const missingTerm = await signedGet(`${FASP_URL}/account_search/v0/search`);
    check("account_search without a term is 422", missingTerm.status === 422, `got ${missingTerm.status}`);
    const sigOk = verifyResponse({
      status: 422, rawBody: await missingTerm.text(),
      headers: Object.fromEntries(missingTerm.headers.entries()), lookupKey: verifyKey,
    });
    check("even the 422 is signed", sigOk.ok, sigOk.reason ?? "");

    const blankTerm = await signedGet(`${FASP_URL}/account_search/v0/search?term=%20`);
    check("a whitespace-only term is 422", blankTerm.status === 422, `got ${blankTerm.status}`);

    const badLimit = await signedGet(`${FASP_URL}/account_search/v0/search?term=x&limit=0`);
    check("limit=0 is 422", badLimit.status === 422, `got ${badLimit.status}`);

    const noAccount = await signedGet(`${FASP_URL}/follow_recommendation/v0/accounts`);
    check("follow_recommendation without accountUri is 422", noAccount.status === 422, `got ${noAccount.status}`);

    const badHours = await signedGet(`${FASP_URL}/trends/v0/content?withinLastHours=nope`);
    check("a malformed trends parameter is 422", badHours.status === 422, `got ${badHours.status}`);

    const unsigned = await fetch(`${FASP_URL}/account_search/v0/search?term=x`);
    check("an unsigned query is 401", unsigned.status === 401, `got ${unsigned.status}`);

    // Empty results are still well-formed documents of the right shape.
    const empty = await signedGet(`${FASP_URL}/trends/v0/hashtags`);
    check("trends answers 200 with an empty index", empty.status === 200);
    check("and the response has the documented shape", Array.isArray((await empty.json()).hashtags));
  }

  console.log("\n6. the whole layer, end to end");
  {
    // A fediverse server announces content. The FASP fetches it from its
    // origin, applies the consent gate, and indexes what passes.
    await announce({
      source: { subscription: { id: "1" } }, category: "content", eventType: "new",
      objectUris: Object.keys(notes).map((p) => `${ORIGIN_URL}${p}`),
    });
    check("all four posts were fetched, consented and indexed",
      await waitFor(() => accepted.length === 4), `${accepted.length}: ${accepted.join(", ")}`);
    check("authors were indexed as accounts from their posts", index.stats().accounts >= 2, JSON.stringify(index.stats()));

    // account_search
    const search = await signedGet(`${FASP_URL}/account_search/v0/search?term=alice`);
    const found = await search.json();
    check("account_search returns a bare JSON array, as specified", Array.isArray(found));
    check("it finds the account", found.includes(ALICE), JSON.stringify(found));
    check("the response is signed", verifyResponse({
      status: 200, rawBody: JSON.stringify(found),
      headers: Object.fromEntries(search.headers.entries()), lookupKey: verifyKey,
    }).ok);

    const bySummary = await (await signedGet(`${FASP_URL}/account_search/v0/search?term=teapots`)).json();
    check("it matches on profile text too", bySummary.includes(ALICE), JSON.stringify(bySummary));
    const noHits = await (await signedGet(`${FASP_URL}/account_search/v0/search?term=zzzznobody`)).json();
    check("no matches gives an empty array, not an error", Array.isArray(noHits) && noHits.length === 0);

    // Pagination via the RFC 5988 Link header.
    const paged = await signedGet(`${FASP_URL}/account_search/v0/search?term=example&limit=1`);
    const firstPage = await paged.json();
    check("limit is honoured", firstPage.length === 1, JSON.stringify(firstPage));
    const link = paged.headers.get("link");
    check("a next page is advertised with rel=next", !!link && link.includes('rel="next"'), String(link));
    if (link) {
      const nextUrl = link.slice(1, link.indexOf(">"));
      const second = await (await signedGet(nextUrl)).json();
      check("the next page returns different results",
        second.length > 0 && second[0] !== firstPage[0], JSON.stringify({ firstPage, second }));
    }

    // trends
    const hashtags = (await (await signedGet(`${FASP_URL}/trends/v0/hashtags`)).json()).hashtags;
    check("trending hashtags are returned", hashtags.length > 0, JSON.stringify(hashtags));
    check("#cats and #Cats were counted as one tag",
      hashtags.filter((h: any) => normalizeHashtag(h.name) === "#cats").length === 1, JSON.stringify(hashtags));
    check("the most-used hashtag ranks first", normalizeHashtag(hashtags[0].name) === "#cats", JSON.stringify(hashtags));
    check("the top rank is 100", hashtags[0].rank === 100);
    check("ranks are 1..100 integers",
      hashtags.every((h: any) => Number.isInteger(h.rank) && h.rank >= 1 && h.rank <= 100));
    check("results are sorted by rank descending",
      hashtags.every((h: any, i: number) => i === 0 || hashtags[i - 1].rank >= h.rank));
    check("hashtags carry example URIs, as the spec requires",
      Array.isArray(hashtags[0].examples) && hashtags[0].examples.length > 0);

    const links = (await (await signedGet(`${FASP_URL}/trends/v0/links`)).json()).links;
    check("trending links are returned", links.length > 0, JSON.stringify(links));
    check("the shared link was counted from both posts",
      links[0].url.includes("blog.example.com/cats") && links[0].examples.length === 2, JSON.stringify(links));

    const contentTrends = (await (await signedGet(`${FASP_URL}/trends/v0/content`)).json()).content;
    check("trending content is returned", contentTrends.length > 0);
    check("content entries carry uri and rank",
      contentTrends.every((c: any) => typeof c.uri === "string" && Number.isInteger(c.rank)));

    // Language filtering, end to end.
    const french = (await (await signedGet(`${FASP_URL}/trends/v0/hashtags?language=fr`)).json()).hashtags;
    check("language filtering narrows to French content",
      french.length === 1 && normalizeHashtag(french[0].name) === "#chats", JSON.stringify(french));
    const english = (await (await signedGet(`${FASP_URL}/trends/v0/hashtags?language=en`)).json()).hashtags;
    check("and English excludes the French tag",
      !english.some((h: any) => normalizeHashtag(h.name) === "#chats"), JSON.stringify(english));

    // maxCount, end to end.
    const capped = (await (await signedGet(`${FASP_URL}/trends/v0/hashtags?maxCount=1`)).json()).hashtags;
    check("maxCount limits the result set", capped.length === 1, JSON.stringify(capped));

    // A window that excludes everything returns an empty list, not an error.
    const stale = (await (await signedGet(`${FASP_URL}/trends/v0/hashtags?withinLastHours=1`)).json()).hashtags;
    check("a narrow window still returns a valid document", Array.isArray(stale));

    // follow_recommendation
    const recs = await (await signedGet(
      `${FASP_URL}/follow_recommendation/v0/accounts?accountUri=${encodeURIComponent(ALICE)}`)).json();
    check("follow recommendations are a bare array", Array.isArray(recs));
    check("Bob is recommended to Alice, via their shared #cats", recs.includes(BOB), JSON.stringify(recs));
    check("the account itself is never recommended", !recs.includes(ALICE));
  }

  console.log("\n7. revocation flows through to queries");
  {
    // Whatever the index holds must disappear when consent is withdrawn.
    index.remove(`${ORIGIN_URL}/statuses/a1`);
    index.remove(`${ORIGIN_URL}/statuses/a2`);
    const links = (await (await signedGet(`${FASP_URL}/trends/v0/links`)).json()).links;
    check("a revoked post stops contributing to trends",
      links.every((l: any) => !l.examples.includes(`${ORIGIN_URL}/statuses/a1`)), JSON.stringify(links));
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  s1.close(); s2.close(); s3.close();
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}

main();
