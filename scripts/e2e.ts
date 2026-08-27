/**
 * End-to-end test: spins up a mock fediverse server (nodeinfo + /registration
 * + debug callback endpoint) and a FASP, then runs the full handshake and a
 * signed debug round-trip. No external network needed.
 */
import express from "express";
import { generateKeypair, verifyRequest, signResponse, keyFingerprint } from "../src/crypto.js";
import { createFasp, debugCapability, registerWithServer, getServer, callServer } from "../src/server.js";
import { newId } from "../src/store.js";

const FEDI_PORT = 4001;
const FASP_PORT = 4002;
const FEDI_URL = `http://localhost:${FEDI_PORT}`;
const FASP_URL = `http://localhost:${FASP_PORT}`;

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

// ---- FASP ------------------------------------------------------------------
const fasp = createFasp({
  name: "faspkit demo",
  baseUrl: FASP_URL,
  privacyPolicy: [{ url: `${FASP_URL}/privacy`, language: "en" }],
  contactEmail: "demo@example.com",
  capabilities: [debugCapability()],
});

async function main() {
  const s1 = fedi.listen(FEDI_PORT);
  const s2 = fasp.listen(FASP_PORT);
  await new Promise((r) => setTimeout(r, 300));

  console.log("\n1. provider_info");
  const info = await (await fetch(`${FASP_URL}/provider_info`)).json();
  check("provider_info has name", !!info.name);
  check("provider_info lists capabilities", Array.isArray(info.capabilities) && info.capabilities[0].id === "callback");
  check("provider_info has privacyPolicy array", Array.isArray(info.privacyPolicy));

  console.log("\n2. registration handshake");
  const reg = await registerWithServer(
    { name: "faspkit demo", baseUrl: FASP_URL, capabilities: [debugCapability()] },
    FEDI_URL,
  );
  check("FASP discovered faspBaseUrl via nodeinfo", reg.record.baseUrl === `${FEDI_URL}/fasp`);
  check("FASP received faspId", !!reg.record.faspId);
  check("FASP stored server public key", !!reg.record.theirPublicKey);
  check("fingerprint is base64 sha-256", reg.fingerprint === keyFingerprint(reg.record.ourPublicKey));
  console.log(`     fingerprint: ${reg.fingerprint}`);

  console.log("\n3. signed inbound request (instance -> FASP debug capability)");
  const rec = getServer(reg.record.serverId)!;
  const payload = JSON.stringify({ hello: "from the instance" });
  const { signRequest } = await import("../src/crypto.js");
  const hdrs = signRequest({
    method: "POST",
    targetUri: `${FASP_URL}/debug/v0/callback/logs`,
    body: payload,
    keyid: rec.faspId!,          // instance signs with the ID the FASP gave it
    privateKey: fediKeys.privateKey,
  });
  const cbRes = await fetch(`${FASP_URL}/debug/v0/callback/logs`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-digest": hdrs["content-digest"],
      "signature-input": hdrs["signature-input"],
      signature: hdrs.signature,
    },
    body: payload,
  });
  check("FASP accepted signed request (201)", cbRes.status === 201, `got ${cbRes.status}`);
  await new Promise((r) => setTimeout(r, 300));
  check("FASP called instance back with body intact", JSON.stringify(callbackReceived) === payload,
    JSON.stringify(callbackReceived));

  console.log("\n4. negative tests");
  const badRes = await fetch(`${FASP_URL}/debug/v0/callback/logs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: payload,
  });
  check("unsigned request rejected with 401", badRes.status === 401, `got ${badRes.status}`);

  const tampered = await fetch(`${FASP_URL}/debug/v0/callback/logs`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-digest": hdrs["content-digest"],
      "signature-input": hdrs["signature-input"],
      signature: hdrs.signature,
    },
    body: JSON.stringify({ hello: "tampered" }),
  });
  check("tampered body rejected (digest mismatch)", tampered.status === 401, `got ${tampered.status}`);

  const stale = signRequest({
    method: "POST",
    targetUri: `${FASP_URL}/debug/v0/callback/logs`,
    body: payload,
    keyid: rec.faspId!,
    privateKey: fediKeys.privateKey,
    created: Math.floor(Date.now() / 1000) - 9999,
  });
  const staleRes = await fetch(`${FASP_URL}/debug/v0/callback/logs`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-digest": stale["content-digest"],
      "signature-input": stale["signature-input"],
      signature: stale.signature,
    },
    body: payload,
  });
  check("stale timestamp rejected", staleRes.status === 401, `got ${staleRes.status}`);

  console.log(`\n${pass} passed, ${fail} failed\n`);
  s1.close(); s2.close();
  process.exit(fail === 0 ? 0 : 1);
}

main();
