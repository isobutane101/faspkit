/**
 * Tests for the storage interface, encryption at rest, and key rotation.
 *
 * The assertion that matters most here is the one that reads the file back off
 * disk and looks for the private key in it. Encryption at rest is easy to
 * believe you have and easy not to have.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSecretBox, plaintextSecretBox, secretBoxFromEnv } from "../src/secretbox.js";
import {
  createJsonStore,
  acceptableTheirKeys,
  rotateTheirKey,
  rotateOurKeypair,
  ServerRecord,
} from "../src/store.js";
import { generateKeypair, signRequest, verifyRequest } from "../src/crypto.js";

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-store-"));
const dirs: string[] = [];
function scratch(): string {
  const d = tmp();
  dirs.push(d);
  return d;
}

async function main() {
  console.log("\n1. secret box");
  {
    const box = createSecretBox("correct horse battery staple");
    const secret = "a-private-key-value";
    const sealed = box.seal(secret);

    check("sealed value is versioned", sealed.startsWith("v1:"), sealed.slice(0, 12));
    check("sealed value does not contain the plaintext", !sealed.includes(secret));
    check("round trips", box.open(sealed) === secret);
    check("sealing twice gives different ciphertext (fresh IV)", box.seal(secret) !== box.seal(secret));
    check("both ciphertexts still open to the same plaintext", box.open(box.seal(secret)) === secret);

    let wrongSecretFailed = false;
    try { createSecretBox("wrong passphrase").open(sealed); } catch { wrongSecretFailed = true; }
    check("a different secret cannot open it", wrongSecretFailed);

    // GCM authenticates, so a modified ciphertext must fail rather than
    // silently decrypt to garbage.
    const [v, iv, tag, ct] = sealed.split(":");
    const flipped = Buffer.from(ct, "base64");
    flipped[0] ^= 0xff;
    let tamperFailed = false;
    try { box.open([v, iv, tag, flipped.toString("base64")].join(":")); } catch { tamperFailed = true; }
    check("tampered ciphertext is rejected", tamperFailed);

    // Self-describing format: an existing plaintext store stays readable.
    check("legacy bare values are read as-is", box.open("raw-legacy-value") === "raw-legacy-value");
    check("explicitly plain values are read", box.open("plain:hello") === "hello");

    const plain = plaintextSecretBox();
    check("passthrough box reports that it does not encrypt", plain.encrypts === false);
    check("passthrough tags its values", plain.seal("x") === "plain:x");
    check("real box reports that it encrypts", box.encrypts === true);
  }

  console.log("\n2. secret box from the environment");
  {
    const fromEnv = secretBoxFromEnv({ FASPKIT_SECRET: "s3cret" } as NodeJS.ProcessEnv);
    check("a configured secret yields a real box", fromEnv.encrypts);

    let productionThrew = false;
    let message = "";
    try {
      secretBoxFromEnv({ NODE_ENV: "production" } as NodeJS.ProcessEnv);
    } catch (err) {
      productionThrew = true;
      message = String(err);
    }
    check("production without a secret is fatal, not a silent downgrade", productionThrew);
    check("the error says why", message.includes("FASPKIT_SECRET"), message);

    const dev = secretBoxFromEnv({} as NodeJS.ProcessEnv);
    check("development without a secret falls back to passthrough", !dev.encrypts);
  }

  console.log("\n3. private keys are encrypted at rest");
  {
    const dir = scratch();
    const store = createJsonStore({ dataDir: dir, secretBox: createSecretBox("test-secret") });
    const rec = await store.createServer("https://fedi.example.com", "https://fedi.example.com/fasp");

    const raw = fs.readFileSync(path.join(dir, "servers.json"), "utf8");
    check("the private key is NOT on disk in plaintext", !raw.includes(rec.ourPrivateKey), rec.ourPrivateKey.slice(0, 12));
    check("the stored value is sealed", JSON.parse(raw)[rec.serverId].ourPrivateKey.startsWith("v1:"));
    check("the public key is stored as-is (nothing secret about it)", raw.includes(rec.ourPublicKey));

    const reread = await store.getServer(rec.serverId);
    check("reading decrypts transparently", reread?.ourPrivateKey === rec.ourPrivateKey);
    check("the decrypted key still signs", (() => {
      const h = signRequest({ method: "POST", targetUri: "https://x.example/y", body: "{}", keyid: "k", privateKey: reread!.ourPrivateKey });
      return verifyRequest({
        method: "POST", targetUri: "https://x.example/y", rawBody: "{}",
        headers: { "content-digest": h["content-digest"], "signature-input": h["signature-input"], signature: h.signature },
        lookupKey: () => reread!.ourPublicKey,
      }).ok;
    })());

    // A store opened with the wrong secret must fail loudly.
    const wrong = createJsonStore({ dataDir: dir, secretBox: createSecretBox("different-secret") });
    let openFailed = false;
    try { await wrong.getServer(rec.serverId); } catch { openFailed = true; }
    check("opening the store with the wrong secret fails loudly", openFailed);
  }

  console.log("\n4. store interface");
  {
    const store = createJsonStore({ dataDir: scratch(), secretBox: plaintextSecretBox() });
    const a = await store.createServer("https://a.example", "https://a.example/fasp");
    const b = await store.createServer("https://b.example", "https://b.example/fasp");

    check("server ids are distinct", a.serverId !== b.serverId);
    check("trailing slashes are normalised", (await store.createServer("https://c.example/", "https://c.example/fasp/")).baseUrl === "https://c.example/fasp");
    check("new records start pending", a.status === "pending");
    check("getServer returns the record", (await store.getServer(a.serverId))?.serverUrl === "https://a.example");
    check("getServer on an unknown id is undefined", (await store.getServer("nope")) === undefined);
    check("allServers lists them", (await store.allServers()).length === 3);

    await store.updateServer(a.serverId, { faspId: "fasp-a", theirPublicKey: "KEY-A", status: "active" });
    check("updateServer patches", (await store.getServer(a.serverId))?.status === "active");
    check("serverByFaspId finds by the id the instance issued", (await store.serverByFaspId("fasp-a"))?.serverId === a.serverId);
    check("serverByFaspId on an unknown id is undefined", (await store.serverByFaspId("fasp-zzz")) === undefined);

    let updateFailed = false;
    try { await store.updateServer("nope", { name: "x" }); } catch { updateFailed = true; }
    check("updating an unknown server throws", updateFailed);

    // Dedup set.
    check("markSeen returns everything the first time",
      (await store.markSeen(["u1", "u2"])).join() === "u1,u2");
    check("markSeen filters what it has already seen",
      (await store.markSeen(["u2", "u3"])).join() === "u3");
    check("hasSeen reflects that", (await store.hasSeen("u1")) && !(await store.hasSeen("u9")));
    check("seenCount counts", (await store.seenCount()) === 3);
    await store.forgetSeen("u1");
    check("forgetSeen removes one", !(await store.hasSeen("u1")) && (await store.seenCount()) === 2);
    await store.forgetSeen("u1");
    check("forgetting twice is harmless", (await store.seenCount()) === 2);
    check("markSeen preserves order", (await store.markSeen(["z", "y", "x"])).join() === "z,y,x");
  }

  console.log("\n5. key rotation");
  {
    const store = createJsonStore({ dataDir: scratch(), secretBox: plaintextSecretBox() });
    const rec = await store.createServer("https://fedi.example", "https://fedi.example/fasp");
    const oldKeys = generateKeypair();
    const newKeys = generateKeypair();
    await store.updateServer(rec.serverId, { faspId: "fasp-1", theirPublicKey: oldKeys.publicKey });

    check("before rotation only the current key is accepted",
      acceptableTheirKeys((await store.getServer(rec.serverId))!).join() === oldKeys.publicKey);

    const rotated = await rotateTheirKey(store, rec.serverId, newKeys.publicKey, 3600);
    const accepted = acceptableTheirKeys(rotated);
    check("after rotation the new key is accepted", accepted.includes(newKeys.publicKey));
    check("the previous key is still accepted during the overlap", accepted.includes(oldKeys.publicKey));
    check("rotation is timestamped", !!rotated.rotatedAt && !!rotated.previousKeyExpiresAt);

    // The acceptance criterion: a request signed with the retired key still
    // verifies during the overlap, and stops once it expires.
    const body = '{"a":1}';
    const signedWithOld = signRequest({
      method: "POST", targetUri: "https://fasp.example/x", body,
      keyid: "fasp-1", privateKey: oldKeys.privateKey,
    });
    const verifyWith = (record: ServerRecord) =>
      verifyRequest({
        method: "POST", targetUri: "https://fasp.example/x", rawBody: body,
        headers: {
          "content-digest": signedWithOld["content-digest"],
          "signature-input": signedWithOld["signature-input"],
          signature: signedWithOld.signature,
        },
        lookupKey: (keyid) => (keyid === "fasp-1" ? acceptableTheirKeys(record) : undefined),
      });

    check("a request signed with the old key still verifies during the overlap", verifyWith(rotated).ok);

    const expired = await store.updateServer(rec.serverId, {
      previousKeyExpiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    check("once the overlap expires the old key is dropped",
      acceptableTheirKeys(expired).join() === newKeys.publicKey);
    check("and a request signed with it no longer verifies", !verifyWith(expired).ok);

    const signedWithNew = signRequest({
      method: "POST", targetUri: "https://fasp.example/x", body,
      keyid: "fasp-1", privateKey: newKeys.privateKey,
    });
    check("the new key verifies after expiry", verifyRequest({
      method: "POST", targetUri: "https://fasp.example/x", rawBody: body,
      headers: {
        "content-digest": signedWithNew["content-digest"],
        "signature-input": signedWithNew["signature-input"],
        signature: signedWithNew.signature,
      },
      lookupKey: (keyid) => (keyid === "fasp-1" ? acceptableTheirKeys(expired) : undefined),
    }).ok);

    // Rotating our own keypair.
    const before = (await store.getServer(rec.serverId))!;
    const after = await rotateOurKeypair(store, rec.serverId);
    check("our keypair changes", after.ourPrivateKey !== before.ourPrivateKey && after.ourPublicKey !== before.ourPublicKey);
    check("the retired keypair is retained", after.previousOurPublicKey === before.ourPublicKey);
    check("the new private key is a working key", (() => {
      const h = signRequest({ method: "GET", targetUri: "https://x.example/", body: "", keyid: "k", privateKey: after.ourPrivateKey });
      return verifyRequest({
        method: "GET", targetUri: "https://x.example/", rawBody: "",
        headers: { "content-digest": h["content-digest"], "signature-input": h["signature-input"], signature: h.signature },
        lookupKey: () => after.ourPublicKey,
      }).ok;
    })());

    let unknownFailed = false;
    try { await rotateTheirKey(store, "nope", "k"); } catch { unknownFailed = true; }
    check("rotating an unknown server throws", unknownFailed);
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}

main();
