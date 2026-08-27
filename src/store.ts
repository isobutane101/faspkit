import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { generateKeypair } from "./crypto.js";
import { SecretBox, secretBoxFromEnv } from "./secretbox.js";

export interface ServerRecord {
  serverId: string;        // ID we generated for the fediverse server
  faspId?: string;         // ID the server generated for us
  baseUrl: string;         // the server's FASP base URL
  serverUrl: string;       // the server's public URL
  name?: string;
  ourPublicKey: string;
  ourPrivateKey: string;
  theirPublicKey?: string;
  capabilities: string[];
  createdAt: string;
  status: "pending" | "active";

  // Key rotation. The FASP spec defines no rotation handshake, so these are a
  // local facility: they let a key change be absorbed without dropping requests
  // that were already in flight, signed with the key being retired.
  previousOurPublicKey?: string;
  previousOurPrivateKey?: string;
  previousTheirPublicKey?: string;
  /** ISO timestamp after which the previous key stops being accepted. */
  previousKeyExpiresAt?: string;
  rotatedAt?: string;
}

/** Their public keys we will currently accept: current, plus previous if unexpired. */
export function acceptableTheirKeys(rec: ServerRecord, now = new Date()): string[] {
  const keys: string[] = [];
  if (rec.theirPublicKey) keys.push(rec.theirPublicKey);
  if (
    rec.previousTheirPublicKey &&
    rec.previousKeyExpiresAt &&
    new Date(rec.previousKeyExpiresAt) > now
  ) {
    keys.push(rec.previousTheirPublicKey);
  }
  return keys;
}

/**
 * Persistence for server records, keys, and the dedup seen-set.
 *
 * Async throughout even though the bundled implementation is a synchronous JSON
 * file, so that a database-backed adapter can be dropped in without changing a
 * single call site.
 */
export interface FaspStore {
  createServer(serverUrl: string, baseUrl: string): Promise<ServerRecord>;
  getServer(serverId: string): Promise<ServerRecord | undefined>;
  updateServer(serverId: string, patch: Partial<ServerRecord>): Promise<ServerRecord>;
  allServers(): Promise<ServerRecord[]>;
  serverByFaspId(faspId: string): Promise<ServerRecord | undefined>;

  /** Record URIs, returning only those not seen before, order preserved. */
  markSeen(uris: string[]): Promise<string[]>;
  hasSeen(uri: string): Promise<boolean>;
  forgetSeen(uri: string): Promise<void>;
  seenCount(): Promise<number>;
}

export function newId(): string {
  return crypto.randomBytes(6).toString("hex");
}

// ---------------------------------------------------------------------------
// JSON file adapter
// ---------------------------------------------------------------------------

const PRIVATE_FIELDS = ["ourPrivateKey", "previousOurPrivateKey"] as const;

export interface JsonStoreOptions {
  /** Defaults to FASPKIT_DATA, or ./data. */
  dataDir?: string;
  /** Defaults to one built from the environment. */
  secretBox?: SecretBox;
}

export function createJsonStore(options: JsonStoreOptions = {}): FaspStore {
  // Resolved per call, not captured at construction, so tests and embedders can
  // point FASPKIT_DATA somewhere else after this module has been loaded.
  const dataDir = () => options.dataDir ?? process.env.FASPKIT_DATA ?? path.join(process.cwd(), "data");
  const serversPath = () => path.join(dataDir(), "servers.json");
  const seenPath = () => path.join(dataDir(), "seen.json");

  let box: SecretBox | undefined = options.secretBox;
  const secretBox = () => (box ??= secretBoxFromEnv());

  function readJson<T>(file: string, fallback: T): T {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8")) as T;
    } catch {
      return fallback;
    }
  }

  function writeJson(file: string, value: unknown) {
    fs.mkdirSync(dataDir(), { recursive: true });
    // Write via a temp file so a crash mid-write cannot truncate the store.
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
    fs.renameSync(tmp, file);
  }

  function decrypt(rec: ServerRecord): ServerRecord {
    const out = { ...rec };
    for (const field of PRIVATE_FIELDS) {
      const value = out[field];
      if (typeof value === "string") out[field] = secretBox().open(value);
    }
    return out;
  }

  function encrypt(rec: ServerRecord): ServerRecord {
    const out = { ...rec };
    for (const field of PRIVATE_FIELDS) {
      const value = out[field];
      if (typeof value === "string") out[field] = secretBox().seal(value);
    }
    return out;
  }

  function load(): Record<string, ServerRecord> {
    const raw = readJson<Record<string, ServerRecord>>(serversPath(), {});
    const out: Record<string, ServerRecord> = {};
    for (const [id, rec] of Object.entries(raw)) out[id] = decrypt(rec);
    return out;
  }

  function save(db: Record<string, ServerRecord>) {
    const out: Record<string, ServerRecord> = {};
    for (const [id, rec] of Object.entries(db)) out[id] = encrypt(rec);
    writeJson(serversPath(), out);
  }

  const loadSeen = () => readJson<Record<string, string>>(seenPath(), {});

  return {
    async createServer(serverUrl, baseUrl) {
      const db = load();
      const { publicKey, privateKey } = generateKeypair();
      const rec: ServerRecord = {
        serverId: newId(),
        baseUrl: baseUrl.replace(/\/$/, ""),
        serverUrl: serverUrl.replace(/\/$/, ""),
        ourPublicKey: publicKey,
        ourPrivateKey: privateKey,
        capabilities: [],
        createdAt: new Date().toISOString(),
        status: "pending",
      };
      db[rec.serverId] = rec;
      save(db);
      return rec;
    },

    async getServer(serverId) {
      return load()[serverId];
    },

    async updateServer(serverId, patch) {
      const db = load();
      if (!db[serverId]) throw new Error(`unknown server ${serverId}`);
      db[serverId] = { ...db[serverId], ...patch };
      save(db);
      return db[serverId];
    },

    async allServers() {
      return Object.values(load());
    },

    async serverByFaspId(faspId) {
      return Object.values(load()).find((s) => s.faspId === faspId);
    },

    async markSeen(uris) {
      const seen = loadSeen();
      const at = new Date().toISOString();
      const fresh: string[] = [];
      for (const uri of uris) {
        if (uri in seen) continue;
        seen[uri] = at;
        fresh.push(uri);
      }
      if (fresh.length) writeJson(seenPath(), seen);
      return fresh;
    },

    async hasSeen(uri) {
      return uri in loadSeen();
    },

    async forgetSeen(uri) {
      const seen = loadSeen();
      if (!(uri in seen)) return;
      delete seen[uri];
      writeJson(seenPath(), seen);
    },

    async seenCount() {
      return Object.keys(loadSeen()).length;
    },
  };
}

/** The store used when none is injected. */
export const defaultStore: FaspStore = createJsonStore();

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

const DEFAULT_OVERLAP_SECONDS = 24 * 60 * 60;

/**
 * Accept a new public key from a fediverse server, keeping the old one valid
 * for an overlap window.
 *
 * Without the overlap, every request already in flight and signed with the
 * retired key fails verification at the moment of the swap.
 */
export async function rotateTheirKey(
  store: FaspStore,
  serverId: string,
  newPublicKey: string,
  overlapSeconds = DEFAULT_OVERLAP_SECONDS,
): Promise<ServerRecord> {
  const rec = await store.getServer(serverId);
  if (!rec) throw new Error(`unknown server ${serverId}`);
  return store.updateServer(serverId, {
    previousTheirPublicKey: rec.theirPublicKey,
    theirPublicKey: newPublicKey,
    previousKeyExpiresAt: new Date(Date.now() + overlapSeconds * 1000).toISOString(),
    rotatedAt: new Date().toISOString(),
  });
}

/**
 * Roll our own keypair for one server. We sign with the new key immediately and
 * retain the old one for reference.
 *
 * Note the asymmetry, and the caveat: the spec defines no way to tell an
 * instance that our key changed, so it will keep verifying against the public
 * key it was given at registration and will reject everything we sign with the
 * new one. Until an upstream rotation handshake exists, this is only safe
 * alongside re-registration.
 */
export async function rotateOurKeypair(
  store: FaspStore,
  serverId: string,
): Promise<ServerRecord> {
  const rec = await store.getServer(serverId);
  if (!rec) throw new Error(`unknown server ${serverId}`);
  const { publicKey, privateKey } = generateKeypair();
  return store.updateServer(serverId, {
    previousOurPublicKey: rec.ourPublicKey,
    previousOurPrivateKey: rec.ourPrivateKey,
    ourPublicKey: publicKey,
    ourPrivateKey: privateKey,
    rotatedAt: new Date().toISOString(),
  });
}
