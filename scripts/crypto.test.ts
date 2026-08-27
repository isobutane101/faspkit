/**
 * Unit tests for src/crypto.ts — the RFC 9421 / RFC 9530 layer.
 *
 * These are deliberately known-answer tests where possible: a fixed keypair and
 * a fixed `created` produce one exact signature base and one exact signature.
 * Ed25519 is deterministic, so any refactor that reorders components, changes
 * separators, or re-serializes the body fails here loudly instead of failing
 * silently against a real Mastodon weeks later.
 */
import crypto from "node:crypto";
import {
  generateKeypair,
  importPrivateKey,
  importPublicKey,
  contentDigest,
  keyFingerprint,
  requestSignatureBase,
  responseSignatureBase,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
  createReplayGuard,
  REQUEST_COMPONENTS,
} from "../src/crypto.js";

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name} ${detail}`);
  }
}
function eq(name: string, actual: unknown, expected: unknown) {
  check(name, Object.is(actual, expected), `\n        expected: ${expected}\n        actual:   ${actual}`);
}

// ---- Fixed vectors ---------------------------------------------------------
// Seed is bytes 0x00..0x1f. Any 32 bytes is a valid Ed25519 seed.
const SEED = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const PUB = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const KEYID = "b2ks6vm8p23w";
const CREATED = 1728467285;
const TARGET = "https://fasp.example.com/registration";
const BODY = '{"hello":"world"}';
const DIGEST = "sha-256=:k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg=:";

const lookup = (keyid: string) => (keyid === KEYID ? PUB : undefined);
const now = () => Math.floor(Date.now() / 1000);

/**
 * Sign an arbitrary signature base. Used to forge headers whose parameter
 * order or labels our own signer would never emit, which is exactly what a
 * different implementation will send us.
 */
function signBase(base: string): string {
  return crypto.sign(null, Buffer.from(base), importPrivateKey(SEED)).toString("base64");
}
function buildBase(components: string[], values: Record<string, string>, paramsRaw: string) {
  return [...components.map((c) => `"${c}": ${values[c]}`), `"@signature-params": ${paramsRaw}`].join("\n");
}
const requestValues = (digest = DIGEST) => ({
  "@method": "POST",
  "@target-uri": TARGET,
  "content-digest": digest,
});

console.log("\n1. key formats");
{
  const kp = generateKeypair();
  eq("generated public key is raw 32 bytes", Buffer.from(kp.publicKey, "base64").length, 32);
  eq("generated private key is raw 32 bytes", Buffer.from(kp.privateKey, "base64").length, 32);
  check("keys are base64, never PEM", !kp.publicKey.includes("BEGIN") && !kp.privateKey.includes("BEGIN"));

  // The fixed seed must derive the fixed public key, or every vector below is wrong.
  const derived = crypto
    .createPublicKey(importPrivateKey(SEED))
    .export({ type: "spki", format: "der" })
    .subarray(12)
    .toString("base64");
  eq("fixed seed derives the expected public key", derived, PUB);

  const reimported = importPublicKey(PUB).export({ type: "spki", format: "der" }).subarray(12).toString("base64");
  eq("public key survives export/import round trip", reimported, PUB);
}

console.log("\n2. content-digest (RFC 9530)");
{
  eq("empty body digest", contentDigest(""), "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
  eq("fixed body digest", contentDigest(BODY), DIGEST);
  eq("Buffer and string agree", contentDigest(Buffer.from(BODY)), contentDigest(BODY));
  check("key order changes the digest", contentDigest('{"b":1,"a":2}') !== contentDigest('{"a":2,"b":1}'));
}

console.log("\n3. signature base (known answer)");
{
  const base = requestSignatureBase({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, created: CREATED });
  eq(
    "request signature base is byte-exact",
    base,
    '"@method": POST\n' +
      `"@target-uri": ${TARGET}\n` +
      `"content-digest": ${DIGEST}\n` +
      `"@signature-params": ("@method" "@target-uri" "content-digest");created=${CREATED};keyid="${KEYID}"`,
  );

  const rbase = responseSignatureBase({ status: 201, body: BODY, keyid: KEYID, created: CREATED });
  eq(
    "response signature base is byte-exact",
    rbase,
    '"@status": 201\n' +
      `"content-digest": ${DIGEST}\n` +
      `"@signature-params": ("@status" "content-digest");created=${CREATED};keyid="${KEYID}"`,
  );

  check("requests and responses cover different components", !rbase.includes("@target-uri") && base.includes("@target-uri"));
}

console.log("\n4. signatures (known answer)");
{
  const h = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED, created: CREATED });
  eq(
    "request signature is deterministic and exact",
    h.signature,
    "sig1=:lMmDPB5p8IDIouoqDemyscVA3wo10rOvZOBxYZEhb8lCi01Fzn6OGCbXhmks1afhvQUxDXYlutBY4rpYSOU1Dg==:",
  );
  eq(
    "signature-input is exact",
    h["signature-input"],
    `sig1=("@method" "@target-uri" "content-digest");created=${CREATED};keyid="${KEYID}"`,
  );

  const r = signResponse({ status: 201, body: BODY, keyid: KEYID, privateKey: SEED, created: CREATED });
  eq(
    "response signature is deterministic and exact",
    r.signature,
    "sig1=:f9vOjC2FVqpUqYuR8DynKl8a8IUDcsWaOb0BMx757MmHcM+NcLsZd4ORlLAmrjR8s07M56BJhEn/Ti6vbE/FAw==:",
  );

  eq("fingerprint is base64 sha-256 of the raw key", keyFingerprint(PUB), crypto.createHash("sha256").update(Buffer.from(PUB, "base64")).digest("base64"));
  eq("fingerprint length", keyFingerprint(PUB).length, 44);
}

console.log("\n5. verification round trips");
{
  const h = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED });
  const headers = {
    "content-digest": h["content-digest"],
    "signature-input": h["signature-input"],
    signature: h.signature,
  };
  const ok = verifyRequest({ method: "POST", targetUri: TARGET, rawBody: BODY, headers, lookupKey: lookup });
  check("valid request verifies", ok.ok, ok.reason ?? "");
  eq("verify reports the keyid", ok.keyid, KEYID);
  eq("verify reports the label", ok.label, "sig1");

  const r = signResponse({ status: 201, body: BODY, keyid: KEYID, privateKey: SEED });
  const rok = verifyResponse({
    status: 201,
    rawBody: BODY,
    headers: { "content-digest": r["content-digest"], "signature-input": r["signature-input"], signature: r.signature },
    lookupKey: lookup,
  });
  check("valid response verifies", rok.ok, rok.reason ?? "");

  const wrongStatus = verifyResponse({
    status: 200,
    rawBody: BODY,
    headers: { "content-digest": r["content-digest"], "signature-input": r["signature-input"], signature: r.signature },
    lookupKey: lookup,
  });
  check("response signed for 201 does not verify as 200", !wrongStatus.ok);
}

console.log("\n6. interoperability: labels, ordering, multiple signatures");
{
  // Another implementation may use any label it likes.
  const h = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED, label: "mysig" });
  const custom = verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: { "content-digest": h["content-digest"], "signature-input": h["signature-input"], signature: h.signature },
    lookupKey: lookup,
  });
  check("arbitrary label 'mysig' verifies", custom.ok, custom.reason ?? "");
  eq("label is reported back", custom.label, "mysig");

  // Parameters may appear in any order; the base uses them verbatim as sent.
  const created = now();
  const reordered = `("@method" "@target-uri" "content-digest");keyid="${KEYID}";created=${created}`;
  const sig = signBase(buildBase([...REQUEST_COMPONENTS], requestValues(), reordered));
  const ro = verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: { "content-digest": DIGEST, "signature-input": `sig1=${reordered}`, signature: `sig1=:${sig}:` },
    lookupKey: lookup,
  });
  check("reordered params (keyid before created) verify", ro.ok, ro.reason ?? "");

  // A sender may offer several signatures; one good one is enough.
  const good = `("@method" "@target-uri" "content-digest");created=${created};keyid="${KEYID}"`;
  const goodSig = signBase(buildBase([...REQUEST_COMPONENTS], requestValues(), good));
  const multi = verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: {
      "content-digest": DIGEST,
      "signature-input": `sigA=${good}, sigB=${good}`,
      // sigA is garbage; sigB is valid. The comma split must not be confused
      // by the commas and quotes inside each member.
      signature: `sigA=:${Buffer.alloc(64).toString("base64")}:, sigB=:${goodSig}:`,
    },
    lookupKey: lookup,
  });
  check("multi-signature header accepted when one signature is valid", multi.ok, multi.reason ?? "");
  eq("the valid signature's label is reported", multi.label, "sigB");

  const allBad = verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: {
      "content-digest": DIGEST,
      "signature-input": `sigA=${good}, sigB=${good}`,
      signature: `sigA=:${Buffer.alloc(64).toString("base64")}:, sigB=:${Buffer.alloc(64).toString("base64")}:`,
    },
    lookupKey: lookup,
  });
  check("multi-signature header rejected when every signature is bad", !allBad.ok);

  // alg is optional, but if present it must be the one the spec mandates.
  for (const [alg, expected] of [["ed25519", true], ["rsa-pss-sha512", false]] as const) {
    const params = `("@method" "@target-uri" "content-digest");created=${created};keyid="${KEYID}";alg="${alg}"`;
    const s = signBase(buildBase([...REQUEST_COMPONENTS], requestValues(), params));
    const res = verifyRequest({
      method: "POST",
      targetUri: TARGET,
      rawBody: BODY,
      headers: { "content-digest": DIGEST, "signature-input": `sig1=${params}`, signature: `sig1=:${s}:` },
      lookupKey: lookup,
    });
    check(`alg="${alg}" ${expected ? "accepted" : "rejected"}`, res.ok === expected, res.reason ?? "");
  }
}

console.log("\n7. query strings and derived components");
{
  // account_search is a GET with query parameters. Dropping the query from
  // @target-uri is the single easiest way to break that capability.
  const target = "https://fasp.example.com/account_search/v0/search?term=teapot&limit=5";
  const h = signRequest({ method: "GET", targetUri: target, body: "", keyid: KEYID, privateKey: SEED });
  const res = verifyRequest({
    method: "GET",
    targetUri: target,
    rawBody: "",
    headers: { "content-digest": h["content-digest"], "signature-input": h["signature-input"], signature: h.signature },
    lookupKey: lookup,
  });
  check("signed GET with a query string verifies", res.ok, res.reason ?? "");

  const dropped = verifyRequest({
    method: "GET",
    targetUri: "https://fasp.example.com/account_search/v0/search",
    rawBody: "",
    headers: { "content-digest": h["content-digest"], "signature-input": h["signature-input"], signature: h.signature },
    lookupKey: lookup,
  });
  check("same request with the query dropped does NOT verify", !dropped.ok);

  // Components beyond the mandated set, if a peer chooses to cover them.
  const created = now();
  const extra = `("@method" "@target-uri" "content-digest" "@authority" "@path" "content-type");created=${created};keyid="${KEYID}"`;
  const values = {
    ...requestValues(),
    "@authority": "fasp.example.com",
    "@path": "/registration",
    "content-type": "application/json",
  };
  const s = signBase(buildBase(["@method", "@target-uri", "content-digest", "@authority", "@path", "content-type"], values, extra));
  const extraRes = verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: {
      "content-digest": DIGEST,
      "content-type": "application/json",
      "signature-input": `sig1=${extra}`,
      signature: `sig1=:${s}:`,
    },
    lookupKey: lookup,
  });
  check("extra covered components (@authority, @path, a header) verify", extraRes.ok, extraRes.reason ?? "");

  const missingHeader = verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: { "content-digest": DIGEST, "signature-input": `sig1=${extra}`, signature: `sig1=:${s}:` },
    lookupKey: lookup,
  });
  check("covered header absent from the request is rejected", !missingHeader.ok);
}

console.log("\n8. rejections");
{
  const h = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED });
  const base = {
    "content-digest": h["content-digest"],
    "signature-input": h["signature-input"],
    signature: h.signature,
  };
  const req = (over: Record<string, string | undefined>, body = BODY, target = TARGET, method = "POST") =>
    verifyRequest({
      method,
      targetUri: target,
      rawBody: body,
      headers: { ...base, ...over },
      lookupKey: lookup,
    });

  check("missing signature headers rejected", !req({ signature: undefined, "signature-input": undefined }).ok);
  check("missing content-digest rejected", !req({ "content-digest": undefined }).ok);
  check("tampered body rejected (digest mismatch)", !req({}, '{"hello":"tampered"}').ok);
  check("changed method rejected", !req({}, BODY, TARGET, "PUT").ok);
  check("changed target-uri rejected", !req({}, BODY, "https://evil.example.com/registration").ok);
  check("unknown keyid rejected", !verifyRequest({ method: "POST", targetUri: TARGET, rawBody: BODY, headers: base, lookupKey: () => undefined }).ok);
  check("garbage signature-input rejected", !req({ "signature-input": "not-a-dictionary" }).ok);
  check("malformed target-uri rejected", !req({}, BODY, "not a url").ok);

  const forged = `sig1=:${Buffer.alloc(64).toString("base64")}:`;
  check("forged signature rejected", !req({ signature: forged }).ok);

  const stale = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED, created: now() - 9999 });
  check(
    "stale created rejected",
    !req({ "signature-input": stale["signature-input"], signature: stale.signature }).ok,
  );
  const future = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED, created: now() + 9999 });
  check(
    "far-future created rejected",
    !req({ "signature-input": future["signature-input"], signature: future.signature }).ok,
  );

  // A signature that covers nothing meaningful must not be treated as valid.
  const created = now();
  const weak = `("@method");created=${created};keyid="${KEYID}"`;
  const weakSig = signBase(buildBase(["@method"], requestValues(), weak));
  check(
    "signature not covering @target-uri and content-digest rejected",
    !req({ "signature-input": `sig1=${weak}`, signature: `sig1=:${weakSig}:` }).ok,
  );

  const unknownDerived = `("@method" "@target-uri" "content-digest" "@request-response");created=${created};keyid="${KEYID}"`;
  const udSig = signBase(buildBase([...REQUEST_COMPONENTS, "@request-response"], { ...requestValues(), "@request-response": "x" }, unknownDerived));
  check(
    "unsupported derived component rejected",
    !req({ "signature-input": `sig1=${unknownDerived}`, signature: `sig1=:${udSig}:` }).ok,
  );

  const expired = `("@method" "@target-uri" "content-digest");created=${created};keyid="${KEYID}";expires=${created - 1}`;
  const expSig = signBase(buildBase([...REQUEST_COMPONENTS], requestValues(), expired));
  check("expired signature rejected", !req({ "signature-input": `sig1=${expired}`, signature: `sig1=:${expSig}:` }).ok);
}

console.log("\n9. replay protection");
{
  const guard = createReplayGuard(300);
  const h = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED });
  const headers = {
    "content-digest": h["content-digest"],
    "signature-input": h["signature-input"],
    signature: h.signature,
  };
  const attempt = () =>
    verifyRequest({ method: "POST", targetUri: TARGET, rawBody: BODY, headers, lookupKey: lookup, replayGuard: guard });

  check("first delivery accepted", attempt().ok);
  const second = attempt();
  check("identical replay rejected", !second.ok, second.reason ?? "");
  eq("replay reason is explicit", second.reason, "replayed signature");
  eq("guard records exactly one entry", guard.size(), 1);

  // A failed verification must not consume replay budget, or an attacker could
  // evict live entries by flooding garbage.
  const junkGuard = createReplayGuard(300);
  verifyRequest({
    method: "POST",
    targetUri: TARGET,
    rawBody: BODY,
    headers: { ...headers, signature: `sig1=:${Buffer.alloc(64).toString("base64")}:` },
    lookupKey: lookup,
    replayGuard: junkGuard,
  });
  eq("invalid signatures are not recorded", junkGuard.size(), 0);

  // Entries expire with the skew window they protect.
  const shortGuard = createReplayGuard(0);
  check("short-TTL guard accepts first", !shortGuard.seen("k", "s"));
  check("expired entry is not treated as a replay", !shortGuard.seen("k", "s"));

  const distinct = createReplayGuard(300);
  distinct.seen("keyA", "sig");
  check("same signature under a different keyid is not a replay", !distinct.seen("keyB", "sig"));
}

console.log("\n10. nonce (repeating an identical request legitimately)");
{
  // Ed25519 is deterministic and `created` is whole seconds, so an identical
  // request repeated within one second is byte-identical and a replay guard
  // cannot distinguish it. RFC 9421's nonce parameter is the way out.
  const sign = (nonce?: string) =>
    signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED, created: CREATED, nonce });

  eq("signatures are byte-identical without a nonce", sign().signature, sign().signature);
  check("a nonce changes the signature", sign("a").signature !== sign().signature);
  check("different nonces produce different signatures", sign("a").signature !== sign("b").signature);
  eq(
    "nonce is serialized into signature-input",
    sign("abc")["signature-input"],
    `sig1=("@method" "@target-uri" "content-digest");created=${CREATED};keyid="${KEYID}";nonce="abc"`,
  );

  const guard = createReplayGuard(300);
  const send = (nonce?: string) => {
    const h = signRequest({ method: "POST", targetUri: TARGET, body: BODY, keyid: KEYID, privateKey: SEED, nonce });
    return verifyRequest({
      method: "POST",
      targetUri: TARGET,
      rawBody: BODY,
      headers: { "content-digest": h["content-digest"], "signature-input": h["signature-input"], signature: h.signature },
      lookupKey: lookup,
      replayGuard: guard,
    });
  };
  check("first nonced request accepted", send("n1").ok);
  check("second request with a fresh nonce accepted", send("n2").ok);
  check("reusing the same nonce is a replay", !send("n1").ok);
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
