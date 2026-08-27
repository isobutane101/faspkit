/**
 * Tests for the runnable app: durable identity, admin auth, the dashboard API,
 * and the CLI argument parsing.
 *
 * The assertions worth reading are the identity one (an actor keypair that
 * changed on restart would silently break every signed fetch) and the auth ones
 * (the dashboard can register this FASP with other servers, so it must not be
 * open).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-app-"));
process.env.FASPKIT_DATA = DATA_DIR;
delete process.env.FASPKIT_ADMIN_TOKEN;

import { createJsonStore } from "../src/store.js";
import { plaintextSecretBox, createSecretBox } from "../src/secretbox.js";
import { loadActorKeypair, loadAdminToken, loadConfig, tokensMatch } from "../src/config.js";
import { createFaspApp } from "../src/app.js";
import { parseArgs } from "../src/cli.js";

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name} ${detail}`); }
}

const FEDI_PORT = 4301;
const FEDI_URL = `http://localhost:${FEDI_PORT}`;

// A mock fediverse server so "connect" has something real to talk to.
const fedi = express();
fedi.use(express.json());
fedi.get("/.well-known/nodeinfo", (_req, res) =>
  res.json({ links: [{ rel: "nodeinfo", href: `${FEDI_URL}/nodeinfo/2.0` }] }));
fedi.get("/nodeinfo/2.0", (_req, res) => res.json({ metadata: { faspBaseUrl: `${FEDI_URL}/fasp` } }));
fedi.post("/fasp/registration", (req, res) =>
  res.status(201).json({
    faspId: "issued-fasp-id",
    publicKey: req.body.publicKey,
    registrationCompletionUri: `${FEDI_URL}/admin/fasps`,
  }));
// A server that does not support FASP at all.
fedi.get("/plain/.well-known/nodeinfo", (_req, res) =>
  res.json({ links: [{ rel: "nodeinfo", href: `${FEDI_URL}/plain/nodeinfo` }] }));
fedi.get("/plain/nodeinfo", (_req, res) => res.json({ metadata: {} }));

async function main() {
  const fediServer = fedi.listen(FEDI_PORT);

  console.log("\n1. durable identity");
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-id-"));
    const store = createJsonStore({ dataDir: dir, secretBox: plaintextSecretBox() });

    const first = await loadActorKeypair(store);
    const second = await loadActorKeypair(store);
    check("the actor keypair is generated once", first.publicKeyPem === second.publicKeyPem);
    check("and its private half is stable too", first.privateKeyPem === second.privateKeyPem);

    // Simulate a restart: a brand new store over the same directory.
    const reopened = createJsonStore({ dataDir: dir, secretBox: plaintextSecretBox() });
    const afterRestart = await loadActorKeypair(reopened);
    check("it survives a restart", afterRestart.publicKeyPem === first.publicKeyPem);
    check("it is a real RSA key", first.publicKeyPem.includes("BEGIN PUBLIC KEY"));

    const token = await loadAdminToken(store);
    check("an admin token is generated", token.length >= 24);
    check("and is stable across calls", (await loadAdminToken(store)) === token);
    check("an explicit token overrides the stored one", (await loadAdminToken(store, "mine")) === "mine");

    // The admin token grants control of this FASP, so it must not sit in the
    // settings file in the clear once a secret is configured.
    const encDir = fs.mkdtempSync(path.join(os.tmpdir(), "faspkit-enc-"));
    const encStore = createJsonStore({ dataDir: encDir, secretBox: createSecretBox("a-secret") });
    const encToken = await loadAdminToken(encStore);
    const settingsRaw = fs.readFileSync(path.join(encDir, "settings.json"), "utf8");
    check("the admin token is encrypted at rest", !settingsRaw.includes(encToken), settingsRaw.slice(0, 80));
    check("the actor private key is encrypted at rest", (async () => {
      const kp = await loadActorKeypair(encStore);
      return !fs.readFileSync(path.join(encDir, "settings.json"), "utf8").includes(kp.privateKeyPem);
    })() !== undefined);
    const kp = await loadActorKeypair(encStore);
    check("but the actor private key still round-trips",
      (await loadActorKeypair(encStore)).privateKeyPem === kp.privateKeyPem);
    check("and is not readable in the file",
      !fs.readFileSync(path.join(encDir, "settings.json"), "utf8").includes(kp.privateKeyPem));
    fs.rmSync(encDir, { recursive: true, force: true });

    check("tokensMatch accepts an exact match", tokensMatch("abc", "abc"));
    check("tokensMatch rejects a different token", !tokensMatch("abc", "abd"));
    check("tokensMatch rejects a length mismatch", !tokensMatch("abc", "abcd"));

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log("\n2. config");
  {
    const config = await loadConfig({ port: 4302, name: "Test FASP" });
    check("a base URL is derived from the port", config.baseUrl === "http://localhost:4302");
    check("the name is applied", config.name === "Test FASP");
    check("a privacy policy URL is defaulted", config.privacyPolicyUrl.endsWith("/privacy"));
    check("the actor identity is built", config.identity.keypair.publicKeyPem.includes("BEGIN PUBLIC KEY"));
    check("a trailing slash is trimmed",
      (await loadConfig({ baseUrl: "https://fasp.example.com/" })).baseUrl === "https://fasp.example.com");

    let rejected = false;
    try { await loadConfig({ baseUrl: "not a url" }); } catch { rejected = true; }
    check("a malformed base URL is rejected at startup", rejected);

    // Getting the base URL wrong yields signatures that verify nowhere, so an
    // http URL in production is a startup failure rather than a mystery later.
    process.env.NODE_ENV = "production";
    let insecureRejected = false;
    try { await loadConfig({ baseUrl: "http://fasp.example.com" }); } catch { insecureRejected = true; }
    check("http in production is refused", insecureRejected);
    delete process.env.NODE_ENV;
  }

  console.log("\n3. the app boots and serves the protocol");
  // A fixed port, because the configured base URL is part of the identity:
  // WebFinger only answers for the account at its own configured host, and an
  // ephemeral port would not match what the config says.
  const APP_PORT = 4303;
  const base = `http://localhost:${APP_PORT}`;
  const fasp = await createFaspApp({ port: APP_PORT, baseUrl: base, name: "Dashboard FASP", revalidate: false });
  const { port, close } = await fasp.listen();
  const token = fasp.config.adminToken;
  const auth = { authorization: `Bearer ${token}` };
  {
    const info = await (await fetch(`${base}/provider_info`)).json();
    check("provider_info is public", Array.isArray(info.capabilities));
    check("all five capabilities are offered", info.capabilities.length === 5, JSON.stringify(info.capabilities));
    check("data_sharing is among them", info.capabilities.some((c: any) => c.id === "data_sharing"));

    const actor = await (await fetch(`${base}/actor`)).json();
    check("the actor is served", actor.type === "Application");

    const wf = await fetch(`${base}/.well-known/webfinger?resource=acct:faspkit@localhost:${port}`);
    check("webfinger answers", wf.status === 200, `got ${wf.status}`);

    const health = await (await fetch(`${base}/health`)).json();
    check("health is public and unauthenticated", health.ok === true);

    const root = await fetch(`${base}/`, { redirect: "manual" });
    check("the root redirects somewhere useful", root.status === 302, `got ${root.status}`);
  }

  console.log("\n4. the dashboard is not open");
  {
    const noAuth = await fetch(`${base}/admin/api/status`);
    check("the API rejects an unauthenticated caller", noAuth.status === 401, `got ${noAuth.status}`);

    const badToken = await fetch(`${base}/admin/api/status`, { headers: { authorization: "Bearer wrong" } });
    check("a wrong token is rejected", badToken.status === 401, `got ${badToken.status}`);

    const page = await fetch(`${base}/admin`, { redirect: "manual" });
    check("the dashboard redirects to a login page", page.status === 302, `got ${page.status}`);

    const login = await fetch(`${base}/admin/login`);
    check("the login page is served", login.status === 200 && (await login.text()).includes("Admin token"));

    const badLogin = await fetch(`${base}/admin/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "token=nope",
    });
    check("a wrong token does not sign in", badLogin.status === 401, `got ${badLogin.status}`);

    const goodLogin = await fetch(`${base}/admin/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `token=${encodeURIComponent(token)}`,
      redirect: "manual",
    });
    check("the right token signs in", goodLogin.status === 302, `got ${goodLogin.status}`);
    const cookie = goodLogin.headers.get("set-cookie") ?? "";
    check("the session cookie is httpOnly", cookie.includes("HttpOnly"), cookie);
    check("and is SameSite protected", cookie.includes("SameSite"), cookie);

    const viaCookie = await fetch(`${base}/admin/api/status`, {
      headers: { cookie: cookie.split(";")[0] },
    });
    check("the cookie authenticates the API", viaCookie.status === 200, `got ${viaCookie.status}`);
  }

  console.log("\n5. the dashboard API");
  {
    const status = await (await fetch(`${base}/admin/api/status`, { headers: auth })).json();
    check("status reports the name", status.name === "Dashboard FASP");
    check("status lists capabilities", status.capabilities.length === 5);
    check("status starts with no servers", status.counts.servers === 0);
    check("status includes index counts", typeof status.counts.content === "number");

    const page = await fetch(`${base}/admin`, { headers: auth });
    const html = await page.text();
    check("the dashboard renders when authenticated", page.status === 200);
    check("it is self-contained (no external assets)",
      !/src="https?:|href="https?:\/\/(?!localhost)/.test(html.replace(/rel="noreferrer"/g, "")));
    check("it names the FASP", html.includes("Dashboard FASP"));

    // Connect to the mock server: the handshake the operator would otherwise
    // have to perform by hand with a signed request.
    const connect = await fetch(`${base}/admin/api/connect`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ serverUrl: FEDI_URL }),
    });
    const result = await connect.json();
    check("connect completes the handshake", connect.status === 200, JSON.stringify(result));
    check("it returns the fingerprint to compare", typeof result.fingerprint === "string" && result.fingerprint.length === 44);
    check("it returns where to approve", String(result.registrationCompletionUri).includes("/admin/fasps"));

    const after = await (await fetch(`${base}/admin/api/status`, { headers: auth })).json();
    check("the server now appears", after.counts.servers === 1, JSON.stringify(after.counts));
    check("and is listed as active once registered", after.servers[0].status === "active", JSON.stringify(after.servers));
    check("private key material is never exposed",
      !JSON.stringify(after).toLowerCase().includes("privatekey"));

    const failed = await fetch(`${base}/admin/api/connect`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ serverUrl: `${FEDI_URL}/plain` }),
    });
    check("a server without FASP support gives a clear error", failed.status === 400, `got ${failed.status}`);
    check("and says why", String((await failed.json()).error).includes("faspBaseUrl"));

    const noUrl = await fetch(`${base}/admin/api/connect`, {
      method: "POST", headers: { ...auth, "content-type": "application/json" }, body: "{}",
    });
    check("connect without a URL is rejected", noUrl.status === 400);

    const search = await (await fetch(`${base}/admin/api/preview/search?term=nobody`, { headers: auth })).json();
    check("the search preview works on an empty index", Array.isArray(search.uris));

    const trends = await (await fetch(`${base}/admin/api/preview/trends`, { headers: auth })).json();
    check("the trends preview returns all three lists",
      Array.isArray(trends.hashtags) && Array.isArray(trends.links) && Array.isArray(trends.content));
  }

  console.log("\n6. CLI arguments");
  {
    const ok = parseArgs(["--port", "8080", "--name", "My FASP", "--base-url", "https://f.example"]);
    check("options parse", !("error" in ok) && ok.port === 8080 && ok.name === "My FASP");
    check("--help is recognised", (() => { const r = parseArgs(["--help"]); return !("error" in r) && r.help; })());
    check("--no-admin disables the dashboard", (() => { const r = parseArgs(["--no-admin"]); return !("error" in r) && !r.admin; })());
    check("admin is on by default", (() => { const r = parseArgs([]); return !("error" in r) && r.admin; })());
    check("an unknown option is an error", "error" in parseArgs(["--wat"]));
    check("a bad port is an error", "error" in parseArgs(["--port", "0"]));
    check("a non-numeric port is an error", "error" in parseArgs(["--port", "abc"]));
    check("a missing value is an error", "error" in parseArgs(["--name"]));
  }

  console.log("\n7. the dashboard can be turned off");
  {
    const headless = await createFaspApp({
      port: 4304, baseUrl: "http://localhost:4304", admin: false, revalidate: false,
    });
    const listener = await headless.listen();
    const res = await fetch(`http://localhost:${listener.port}/admin`, { redirect: "manual" });
    check("no dashboard is served with --no-admin", res.status === 404, `got ${res.status}`);
    const info = await fetch(`http://localhost:${listener.port}/provider_info`);
    check("but the FASP itself still works", info.status === 200);
    await listener.close();
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  await close();
  fasp.stop();
  fediServer.close();
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  process.exit(fail === 0 ? 0 : 1);
}

main();
