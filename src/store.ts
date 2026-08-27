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

/** Categories of object a FASP may index. Mirrors data_sharing's `category`. */
export type IndexedCategory = "content" | "account";

/**
 * What we have indexed and when we last confirmed it may still be indexed.
 *
 * The spec requires re-checking at least weekly that content is still public
 * and its author still consents. That is impossible without remembering what
 * was indexed in the first place, which is what this records.
 */
export interface IndexedRecord {
  uri: string;
  category: IndexedCategory;
  indexedAt: string;
  lastCheckedAt: string;
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

  /** Note that a URI passed the consent gate and is now indexed. */
  recordIndexed(uri: string, category: IndexedCategory): Promise<void>;
  /** Indexed records, oldest check first; `checkedBefore` filters by due date. */
  listIndexed(opts?: { checkedBefore?: Date; limit?: number }): Promise<IndexedRecord[]>;
  /** Reset a record's revalidation clock. */
  markRevalidated(uri: string, at?: Date): Promise<void>;
  /** Forget an indexed record, e.g. because consent was withdrawn. */
  removeIndexed(uri: string): Promise<void>;
  indexedCount(): Promise<number>;
}

export function newId(): string {
  return crypto.randomBytes(6).toString("hex");
}

// ---------------------------------------------------------------------------
// JSON file adapter
//
// Records are held in memory and written through to disk on change, with an
// atomic rename so an interrupted write cannot corrupt the file. That keeps the
// hot paths — a key lookup on every signature check, a dedup check on every
// announced URI — off the filesystem entirely.
//
// The tradeoff is deliberate and worth stating: this assumes a single process
// owns the directory. Two processes sharing one data directory will lose
// writes, because each holds its own copy in memory. A FASP that needs to run
// more than one instance wants a shared database behind the same `FaspStore`
// interface, which is exactly why that interface is async.
// ---------------------------------------------------------------------------

const PRIVATE_FIELDS = ["ourPrivateKey", "previousOurPrivateKey"] as const;

export interface JsonStoreOptions {
  /** Defaults to FASPKIT_DATA, or ./data. */
  dataDir?: string;
  /** Defaults to one built from the environment. */
  secretBox?: SecretBox;
  /**
   * Cap on the dedup set before the oldest entries are evicted.
   * Defaults to one million URIs.
   */
  maxSeenEntries?: number;
}

export function createJsonStore(options: JsonStoreOptions = {}): FaspStore {
  // Resolved per call, not captured at construction, so tests and embedders can
  // point FASPKIT_DATA somewhere else after this module has been loaded.
  const dataDir = () => options.dataDir ?? process.env.FASPKIT_DATA ?? path.join(process.cwd(), "data");
  const maxSeen = options.maxSeenEntries ?? 1_000_000;

  let box: SecretBox | undefined = options.secretBox;
  const secretBox = () => (box ??= secretBoxFromEnv());

  // Everything is held in memory and written through on change. Reads happen
  // on every signature verification and every announcement, so re-parsing the
  // file each time is the difference between a store that works at scale and
  // one that falls over. The cache is keyed by directory so that changing
  // FASPKIT_DATA — which the tests do — invalidates it.
  let cachedDir: string | undefined;
  let servers: Record<string, ServerRecord> | undefined;
  let seen: Record<string, string> | undefined;
  let indexed: Record<string, IndexedRecord> | undefined;

  function invalidateIfMoved() {
    const dir = dataDir();
    if (dir === cachedDir) return;
    cachedDir = dir;
    servers = undefined;
    seen = undefined;
    indexed = undefined;
  }

  function readJson<T>(file: string, fallback: T): T {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8")) as T;
    } catch {
      return fallback;
    }
  }

  function writeJson(name: string, value: unknown) {
    const dir = dataDir();
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, name);
    // Write to a temp file and rename, so a crash mid-write leaves the previous
    // contents intact rather than a truncated file.
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
    fs.renameSync(tmp, file);
  }

  function mapPrivateFields(rec: ServerRecord, fn: (v: string) => string): ServerRecord {
    const out = { ...rec };
    for (const field of PRIVATE_FIELDS) {
      const value = out[field];
      if (typeof value === "string") out[field] = fn(value);
    }
    return out;
  }

  function loadServers(): Record<string, ServerRecord> {
    invalidateIfMoved();
    if (servers) return servers;
    const raw = readJson<Record<string, ServerRecord>>(path.join(dataDir(), "servers.json"), {});
    const out: Record<string, ServerRecord> = {};
    for (const [id, rec] of Object.entries(raw)) out[id] = mapPrivateFields(rec, (v) => secretBox().open(v));
    return (servers = out);
  }

  function saveServers() {
    const out: Record<string, ServerRecord> = {};
    for (const [id, rec] of Object.entries(servers ?? {})) {
      out[id] = mapPrivateFields(rec, (v) => secretBox().seal(v));
    }
    writeJson("servers.json", out);
  }

  function loadSeen(): Record<string, string> {
    invalidateIfMoved();
    return (seen ??= readJson<Record<string, string>>(path.join(dataDir(), "seen.json"), {}));
  }

  function loadIndexed(): Record<string, IndexedRecord> {
    invalidateIfMoved();
    return (indexed ??= readJson<Record<string, IndexedRecord>>(path.join(dataDir(), "indexed.json"), {}));
  }

  /**
   * The dedup set grows without bound otherwise — a busy FASP is told about
   * millions of URIs. Evicting the oldest entries is safe: the worst case is
   * re-fetching an object we had already seen, which the consent gate re-checks
   * anyway. Anything currently indexed is kept regardless of age, because
   * forgetting that would let a revoked object silently reappear.
   */
  function pruneSeen(current: Record<string, string>) {
    const uris = Object.keys(current);
    if (uris.length <= maxSeen) return;
    const keep = loadIndexed();
    const evictable = uris
      .filter((u) => !(u in keep))
      .sort((a, b) => current[a].localeCompare(current[b]));
    for (const uri of evictable.slice(0, uris.length - maxSeen)) delete current[uri];
  }

  return {
    async createServer(serverUrl, baseUrl) {
      const db = loadServers();
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
      saveServers();
      return rec;
    },

    async getServer(serverId) {
      return loadServers()[serverId];
    },

    async updateServer(serverId, patch) {
      const db = loadServers();
      if (!db[serverId]) throw new Error(`unknown server ${serverId}`);
      db[serverId] = { ...db[serverId], ...patch };
      saveServers();
      return db[serverId];
    },

    async allServers() {
      return Object.values(loadServers());
    },

    async serverByFaspId(faspId) {
      return Object.values(loadServers()).find((s) => s.faspId === faspId);
    },

    async markSeen(uris) {
      const current = loadSeen();
      const at = new Date().toISOString();
      const fresh: string[] = [];
      for (const uri of uris) {
        if (uri in current) continue;
        current[uri] = at;
        fresh.push(uri);
      }
      if (fresh.length) {
        pruneSeen(current);
        writeJson("seen.json", current);
      }
      return fresh;
    },

    async hasSeen(uri) {
      return uri in loadSeen();
    },

    async forgetSeen(uri) {
      const current = loadSeen();
      if (!(uri in current)) return;
      delete current[uri];
      writeJson("seen.json", current);
    },

    async seenCount() {
      return Object.keys(loadSeen()).length;
    },

    async recordIndexed(uri, category) {
      const current = loadIndexed();
      const at = new Date().toISOString();
      // Re-indexing an object refreshes its check clock but keeps the original
      // indexedAt, so the record still says how long we have held it.
      current[uri] = { uri, category, indexedAt: current[uri]?.indexedAt ?? at, lastCheckedAt: at };
      writeJson("indexed.json", current);
    },

    async listIndexed(opts = {}) {
      let records = Object.values(loadIndexed());
      if (opts.checkedBefore) {
        const cutoff = opts.checkedBefore.getTime();
        records = records.filter((r) => new Date(r.lastCheckedAt).getTime() < cutoff);
      }
      // Oldest check first, so a limited pass always drains the most overdue.
      records = [...records].sort((a, b) => a.lastCheckedAt.localeCompare(b.lastCheckedAt));
      return opts.limit === undefined ? records : records.slice(0, opts.limit);
    },

    async markRevalidated(uri, at = new Date()) {
      const current = loadIndexed();
      if (!current[uri]) return;
      current[uri] = { ...current[uri], lastCheckedAt: at.toISOString() };
      writeJson("indexed.json", current);
    },

    async removeIndexed(uri) {
      const current = loadIndexed();
      if (!(uri in current)) return;
      delete current[uri];
      writeJson("indexed.json", current);
    },

    async indexedCount() {
      return Object.keys(loadIndexed()).length;
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
