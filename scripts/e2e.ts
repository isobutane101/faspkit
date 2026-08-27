/**
 * End-to-end test: spins up a mock fediverse server (nodeinfo + /registration
 * + debug callback endpoint) and a FASP, then runs the full handshake and a
 * signed debug round-trip. No external network needed.
 *
 * The FASP is deliberately mounted under a base URL *with* path segments
 * (`/fasp/v1`), because that is the case the spec requires and the case naive
 * `@target-uri` reconstruction gets wrong.
 */
import express from "express";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Point the store at a scratch directory before anything touches it. store.ts
// resolves FASPKIT_DATA per call, so setting it here is enough.
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-e2e-"));
process.env.FASPKIT_DATA = DATA_DIR;

import {
  generateKeypair,
  verifyRequest,
  verifyResponse,
  signRequest,
  keyFingerprint,
} from "../src/crypto.js";
import {
  createFasp,
  debugCapability,
  registerWithServer,
  getServer,
  callServer,
  sendSigned,
  splitBaseUrl,
  Capability,
} from "../src/server.js";
import { newId } from "../src/store.js";

const FEDI_PORT = 4001;
const FASP_PORT = 4002;
const FEDI_URL = `http://localhost:${FEDI_PORT}`;
const FASP_ORIGIN = `http://localhost:${FASP_PORT}`;
const FASP_BASE = `${FASP_ORIGIN}/fasp/v1`;

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}

// ---- Mock fediverse server -------------------------------------------------
const fediKeys = generateKeypair();
let faspRecord: { serverId: string; publicKey: string; faspId: string } | null = null;
let callbackReceived: unknown = undefined;
let rateLimitedHits = 0;
let alwaysLimitedHits = 0;

const fedi = express();
fedi.use(express.json({
  verify: (req, _res, buf) => { (req as any).rawBody = buf.toString("utf8"); },
}));

fedi.get("/.well-known/nodeinfo", (_req, res) => {
  res.json({ links: [{ rel: "http://nodeinfo.diaspora.software/ns/schema/2.0", href: `${FEDI_URL}/nodeinfo/2.0` }] });
});

fedi.get("/nodeinfo/2.0", (_req, res) => {
  res.json({
    version: "2.0",
    software: { name: "mockodon", version: "4.4.0" },
    protocols: ["activitypub"],
    services: { outbound: [], inbound: [] },
    openRegistrations: false,
    metadata: { nodeName: "mock", faspBaseUrl: `${FEDI_URL}/fasp` },
  });
});

// Registration: verify the FASP's signature, then return our own identity.
fedi.post("/fasp/registration", (req, res) => {
  const body = req.body;
  const result = verifyRequest({
    method: "POST",
    targetUri: `${FEDI_URL}/fasp/registration`,
    rawBody: (req as any).rawBody,
    headers: req.headers as any,
    lookupKey: (keyid) => (keyid === body.serverId ? body.publicKey : undefined),
  });
  check("fedi verifies FASP registration signature", result.ok, result.reason ?? "");

  const faspId = newId();
  faspRecord = { serverId: body.serverId, publicKey: body.publicKey, faspId };
  res.status(201).json({
    faspId,
    publicKey: fediKeys.publicKey,
    registrationCompletionUri: `${FEDI_URL}/admin/fasps`,
  });
});

// Debug callback target: the FASP calls this back, signed.
fedi.post("/fasp/debug/v0/callback/responses", (req, res) => {
  const result = verifyRequest({
    method: "POST",
    targetUri: `${FEDI_URL}/fasp/debug/v0/callback/responses`,
    rawBody: (req as any).rawBody,
    headers: req.headers as any,
    lookupKey: (keyid) => (faspRecord && keyid === faspRecord.serverId ? faspRecord.publicKey : undefined),
  });
  check("fedi verifies FASP callback signature", result.ok, result.reason ?? "");
  callbackReceived = req.body;
  res.status(201).end();
});

// Rate limiting: 429 with Retry-After on the first hit, then success.
fedi.post("/fasp/ratelimited", (_req, res) => {
  rateLimitedHits++;
  if (rateLimitedHits === 1) return res.set("retry-after", "1").status(429).end();
  res.status(201).json({ ok: true });
});

// Permanently rate limited: the client must give up rather than loop forever.
fedi.post("/fasp/always-limited", (_req, res) => {
  alwaysLimitedHits++;
  res.set("retry-after", "1").status(429).end();
});

// Never answers within the client timeout.
fedi.post("/fasp/slow", (_req, _res) => { /* intentionally no response */ });

// ---- FASP ------------------------------------------------------------------

/** A GET capability with query parameters, mirroring account_search's shape. */
function echoSearchCapability(): Capability {
  return {
    id: "echo_search",
    version: "0.1",
    register(router) {
      router.get("/echo_search/v0/search", (req, res) => {
        if (!req.query.term) return sendSigned(req, res, 422, { error: "term required" });
        sendSigned(req, res, 200, { term: req.query.term, limit: Number(req.query.limit ?? 20) });
      });
    },
  };
}

const faspOptions = {
  name: "faspkit demo",
  baseUrl: FASP_BASE,
  privacyPolicy: [{ url: `${FASP_BASE}/privacy`, language: "en" }],
  contactEmail: "demo@example.com",
  capabilities: [debugCapability(), echoSearchCapability()],
};
const fasp = createFasp(faspOptions);

/** Sign a request the way the *instance* would: keyid is the faspId it issued. */
function instanceSigns(
  method: string,
  url: string,
  body: string,
  faspId: string,
  created?: number,
  nonce?: string,
) {
  const h = signRequest({ method, targetUri: url, body, keyid: faspId, privateKey: fediKeys.privateKey, created, nonce });
  return {
    "content-type": "application/json",
    "content-digest": h["content-digest"],
    "signature-input": h["signature-input"],
    signature: h.signature,
  };
}

async function main() {
  const s1 = fedi.listen(FEDI_PORT);
  const s2 = fasp.listen(FASP_PORT);
  await new Promise((r) => setTimeout(r, 300));

  console.log("\n1. base URL handling");
  {
    const split = splitBaseUrl(FASP_BASE);
    check("base URL splits into origin and path prefix", split.origin === FASP_ORIGIN && split.basePath === "/fasp/v1",
      JSON.stringify(split));
    check("trailing slash is normalised away", splitBaseUrl(`${FASP_BASE}/`).basePath === "/fasp/v1");
    check("root base URL yields an empty prefix", splitBaseUrl(FASP_ORIGIN).basePath === "");

    const unprefixed = await fetch(`${FASP_ORIGIN}/provider_info`);
    check("routes are NOT served at the unprefixed path", unprefixed.status === 404, `got ${unprefixed.status}`);
  }

  console.log("\n2. provider_info");
  const info = await (await fetch(`${FASP_BASE}/provider_info`)).json();
  check("provider_info has name", !!info.name);
  check("provider_info lists capabilities", Array.isArray(info.capabilities) && info.capabilities[0].id === "callback");
  check("provider_info has privacyPolicy array", Array.isArray(info.privacyPolicy));

  console.log("\n3. registration handshake");
  const reg = await registerWithServer(faspOptions, FEDI_URL);
  check("FASP discovered faspBaseUrl via nodeinfo", reg.record.baseUrl === `${FEDI_URL}/fasp`);
  check("FASP received faspId", !!reg.record.faspId);
  check("FASP stored server public key", !!reg.record.theirPublicKey);
  check("fingerprint is base64 sha-256", reg.fingerprint === keyFingerprint(reg.record.ourPublicKey));
  console.log(`     fingerprint: ${reg.fingerprint}`);

  const rec = getServer(reg.record.serverId)!;
  const faspId = rec.faspId!;
  const logsUrl = `${FASP_BASE}/debug/v0/callback/logs`;

  console.log("\n4. signed inbound request (instance -> FASP debug capability)");
  const payload = JSON.stringify({ hello: "from the instance" });
  const cbRes = await fetch(logsUrl, { method: "POST", headers: instanceSigns("POST", logsUrl, payload, faspId), body: payload });
  check("FASP accepted signed request (201)", cbRes.status === 201, `got ${cbRes.status}`);

  // Responses must be signed too, over @status + content-digest.
  const cbBody = await cbRes.text();
  const respVerify = verifyResponse({
    status: cbRes.status,
    rawBody: cbBody,
    headers: Object.fromEntries(cbRes.headers.entries()),
    lookupKey: (keyid) => (keyid === rec.serverId ? rec.ourPublicKey : undefined),
  });
  check("FASP response carries a valid signature", respVerify.ok, respVerify.reason ?? "");

  await new Promise((r) => setTimeout(r, 300));
  check("FASP called instance back with body intact", JSON.stringify(callbackReceived) === payload,
    JSON.stringify(callbackReceived));

  console.log("\n5. signed GET with query string (account_search shape)");
  {
    const url = `${FASP_BASE}/echo_search/v0/search?term=teapot&limit=5`;
    const res = await fetch(url, { headers: instanceSigns("GET", url, "", faspId) });
    check("signed GET with query params accepted", res.status === 200, `got ${res.status}`);
    const body = await res.json();
    check("query string survived routing", body.term === "teapot" && body.limit === 5, JSON.stringify(body));

    // Signing without the query string must not authorise a request that has one.
    const bare = `${FASP_BASE}/echo_search/v0/search`;
    const mismatched = await fetch(url, { headers: instanceSigns("GET", bare, "", faspId) });
    check("signature over the query-less URI is rejected", mismatched.status === 401, `got ${mismatched.status}`);

    const missingTerm = await fetch(bare, { headers: instanceSigns("GET", bare, "", faspId) });
    check("missing required param yields signed 422", missingTerm.status === 422, `got ${missingTerm.status}`);
    const mtVerify = verifyResponse({
      status: 422,
      rawBody: await missingTerm.text(),
      headers: Object.fromEntries(missingTerm.headers.entries()),
      lookupKey: (keyid) => (keyid === rec.serverId ? rec.ourPublicKey : undefined),
    });
    check("even error responses are signed", mtVerify.ok, mtVerify.reason ?? "");
  }

  console.log("\n6. replay protection");
  {
    const body = JSON.stringify({ hello: "replay me" });
    const headers = instanceSigns("POST", logsUrl, body, faspId);
    const first = await fetch(logsUrl, { method: "POST", headers, body });
    check("first delivery accepted", first.status === 201, `got ${first.status}`);
    const second = await fetch(logsUrl, { method: "POST", headers, body });
    check("byte-identical replay rejected with 401", second.status === 401, `got ${second.status}`);
    check("rejection reason names the replay", (await second.json()).reason === "replayed signature");

    // Ed25519 is deterministic and `created` is whole seconds, so re-signing an
    // identical payload inside the same second reproduces the same signature
    // byte-for-byte — genuinely indistinguishable from a replay. RFC 9421's
    // remedy is a nonce, which changes the signature base.
    const nonced = await fetch(logsUrl, {
      method: "POST",
      headers: instanceSigns("POST", logsUrl, body, faspId, undefined, "unique-per-send"),
      body,
    });
    check("the same payload re-sent with a nonce is accepted", nonced.status === 201, `got ${nonced.status}`);

    // A later second also yields a different signature, so ordinary traffic is unaffected.
    await new Promise((r) => setTimeout(r, 1100));
    const later = await fetch(logsUrl, { method: "POST", headers: instanceSigns("POST", logsUrl, body, faspId), body });
    check("the same payload re-sent a second later is accepted", later.status === 201, `got ${later.status}`);
  }

  console.log("\n7. outbound rate limiting and timeouts");
  {
    const res = await callServer(rec, "POST", "/ratelimited", { x: 1 }, { maxRetries: 3, maxDelayMs: 50 });
    check("429 + Retry-After is retried and then succeeds", res.status === 201, `got ${res.status}`);
    check("retry actually re-issued the request", rateLimitedHits === 2, `hits: ${rateLimitedHits}`);

    const giveUp = await callServer(rec, "POST", "/always-limited", { x: 1 }, { maxRetries: 2, maxDelayMs: 20 });
    check("permanent 429 gives up and returns the 429", giveUp.status === 429, `got ${giveUp.status}`);
    check("gave up after maxRetries + 1 attempts", alwaysLimitedHits === 3, `hits: ${alwaysLimitedHits}`);

    let timedOut = false;
    try {
      await callServer(rec, "POST", "/slow", { x: 1 }, { timeoutMs: 100, maxRetries: 0 });
    } catch {
      timedOut = true;
    }
    check("a server that never answers times out rather than hanging", timedOut);
  }

  console.log("\n8. response signing cannot be skipped");
  {
    let threw = false;
    try {
      sendSigned({ faspServer: undefined } as any, {} as any, 200, { a: 1 });
    } catch {
      threw = true;
    }
    check("sendSigned throws instead of emitting an unsigned response", threw);
  }

  console.log("\n9. negative tests");
  {
    const unsignedRes = await fetch(logsUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
    });
    check("unsigned request rejected with 401", unsignedRes.status === 401, `got ${unsignedRes.status}`);

    const good = instanceSigns("POST", logsUrl, payload, faspId);
    const tampered = await fetch(logsUrl, { method: "POST", headers: good, body: JSON.stringify({ hello: "tampered" }) });
    check("tampered body rejected (digest mismatch)", tampered.status === 401, `got ${tampered.status}`);

    const staleHeaders = instanceSigns("POST", logsUrl, payload, faspId, Math.floor(Date.now() / 1000) - 9999);
    const staleRes = await fetch(logsUrl, { method: "POST", headers: staleHeaders, body: payload });
    check("stale timestamp rejected", staleRes.status === 401, `got ${staleRes.status}`);

    // An instance signing with the wrong identifier is the classic keyid-direction bug.
    const wrongKeyid = instanceSigns("POST", logsUrl, payload, rec.serverId);
    const wrongRes = await fetch(logsUrl, { method: "POST", headers: wrongKeyid, body: payload });
    check("signing with our serverId instead of the faspId is rejected", wrongRes.status === 401, `got ${wrongRes.status}`);
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  s1.close(); s2.close();
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}

main();
