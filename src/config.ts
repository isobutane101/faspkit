import crypto from "node:crypto";
import { FaspStore, defaultStore } from "./store.js";
import { ActorIdentity, generateActorKeypair } from "./activitypub.js";

/**
 * Configuration and durable identity for a running faspkit instance.
 *
 * Everything here exists so that the answer to "how do I run this?" is one
 * command. Sensible defaults, nothing required beyond a base URL in production,
 * and identity that survives a restart.
 */

export interface FaspConfig {
  name: string;
  baseUrl: string;
  port: number;
  username: string;
  contactEmail?: string;
  fediverseAccount?: string;
  privacyPolicyUrl: string;
  adminToken: string;
  identity: ActorIdentity;
}

export interface ConfigOverrides {
  name?: string;
  baseUrl?: string;
  port?: number;
  username?: string;
  contactEmail?: string;
  fediverseAccount?: string;
  privacyPolicyUrl?: string;
  adminToken?: string;
  store?: FaspStore;
}

const ACTOR_PUBLIC = "actorPublicKeyPem";
const ACTOR_PRIVATE = "actorPrivateKey"; // sealed at rest — see store's isSecretSetting
const ADMIN_TOKEN = "adminToken";

/**
 * Load the ActivityPub actor keypair, generating it once on first run.
 *
 * This must be stable across restarts. Remote servers fetch our actor document,
 * cache the public key, and verify our object fetches against it — so a
 * regenerated key silently breaks every signed fetch until their cache expires.
 */
export async function loadActorKeypair(store: FaspStore) {
  const publicKeyPem = await store.getSetting(ACTOR_PUBLIC);
  const privateKeyPem = await store.getSetting(ACTOR_PRIVATE);
  if (publicKeyPem && privateKeyPem) return { publicKeyPem, privateKeyPem };

  const generated = generateActorKeypair();
  await store.setSetting(ACTOR_PUBLIC, generated.publicKeyPem);
  await store.setSetting(ACTOR_PRIVATE, generated.privateKeyPem);
  return generated;
}

/**
 * The admin token, generated once and persisted.
 *
 * The dashboard can register this FASP with other servers, so it cannot be
 * open. Requiring the operator to invent a secret before anything runs is the
 * kind of friction that makes people skip setup entirely, so one is generated
 * and printed instead — and `FASPKIT_ADMIN_TOKEN` overrides it for deployments
 * that manage secrets themselves.
 */
export async function loadAdminToken(store: FaspStore, override?: string): Promise<string> {
  if (override) return override;
  const existing = await store.getSetting(ADMIN_TOKEN);
  if (existing) return existing;
  const token = crypto.randomBytes(24).toString("base64url");
  await store.setSetting(ADMIN_TOKEN, token);
  return token;
}

/** Constant-time comparison, so a token cannot be guessed a character at a time. */
export function tokensMatch(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export async function loadConfig(overrides: ConfigOverrides = {}): Promise<FaspConfig> {
  const store = overrides.store ?? defaultStore;
  const env = process.env;

  const port = overrides.port ?? Number(env.PORT ?? 3000);
  const baseUrl = (overrides.baseUrl ?? env.FASP_BASE_URL ?? `http://localhost:${port}`).replace(/\/+$/, "");

  // A public base URL is part of the signature base on both sides, so getting
  // it wrong produces signatures that verify nowhere. Catch it at startup
  // rather than as a stream of 401s later.
  try {
    const parsed = new URL(baseUrl);
    if (env.NODE_ENV === "production" && parsed.protocol !== "https:") {
      throw new Error(`FASP_BASE_URL must be https in production, got ${baseUrl}`);
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("FASP_BASE_URL")) throw err;
    throw new Error(`FASP_BASE_URL is not a valid URL: ${baseUrl}`);
  }

  const username = overrides.username ?? env.FASP_USERNAME ?? "faspkit";
  const name = overrides.name ?? env.FASP_NAME ?? "faspkit";

  return {
    name,
    baseUrl,
    port,
    username,
    contactEmail: overrides.contactEmail ?? env.FASP_CONTACT_EMAIL,
    fediverseAccount: overrides.fediverseAccount ?? env.FASP_FEDIVERSE_ACCOUNT,
    privacyPolicyUrl: overrides.privacyPolicyUrl ?? env.FASP_PRIVACY_POLICY_URL ?? `${baseUrl}/privacy`,
    adminToken: await loadAdminToken(store, overrides.adminToken ?? env.FASPKIT_ADMIN_TOKEN),
    identity: { baseUrl, preferredUsername: username, keypair: await loadActorKeypair(store) },
  };
}
