import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { generateKeypair } from "./crypto.js";

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
}

// Resolved per call, not at import time, so tests and embedders can point
// FASPKIT_DATA somewhere else after this module has been loaded.
function dataDir(): string {
  return process.env.FASPKIT_DATA ?? path.join(process.cwd(), "data");
}

function dbPath(): string {
  return path.join(dataDir(), "servers.json");
}

function load(): Record<string, ServerRecord> {
  try {
    return JSON.parse(fs.readFileSync(dbPath(), "utf8"));
  } catch {
    return {};
  }
}

function save(db: Record<string, ServerRecord>) {
  fs.mkdirSync(dataDir(), { recursive: true });
  fs.writeFileSync(dbPath(), JSON.stringify(db, null, 2));
}

export function newId(): string {
  return crypto.randomBytes(6).toString("hex");
}

export function createServer(serverUrl: string, baseUrl: string): ServerRecord {
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
}

export function getServer(serverId: string): ServerRecord | undefined {
  return load()[serverId];
}

export function updateServer(serverId: string, patch: Partial<ServerRecord>) {
  const db = load();
  if (!db[serverId]) throw new Error(`unknown server ${serverId}`);
  db[serverId] = { ...db[serverId], ...patch };
  save(db);
  return db[serverId];
}

export function allServers(): ServerRecord[] {
  return Object.values(load());
}

/** Look up the public key a fediverse server signs with, by its faspId. */
export function lookupKeyByFaspId(faspId: string): string | undefined {
  return allServers().find((s) => s.faspId === faspId)?.theirPublicKey;
}

export function serverByFaspId(faspId: string): ServerRecord | undefined {
  return allServers().find((s) => s.faspId === faspId);
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/**
 * Servers share remote content as well as local, so a FASP connected to many
 * instances will be told about the same object repeatedly. The spec requires
 * deduplicating it; this is the persistent record of what has already been seen.
 *
 * JSON-file backed like the rest of the store today. Phase 2 moves both behind
 * a storage interface.
 */
function seenPath(): string {
  return path.join(dataDir(), "seen.json");
}

function loadSeen(): Record<string, string> {
  try {
    return JSON.parse(fs.readFileSync(seenPath(), "utf8"));
  } catch {
    return {};
  }
}

function saveSeen(seen: Record<string, string>) {
  fs.mkdirSync(dataDir(), { recursive: true });
  fs.writeFileSync(seenPath(), JSON.stringify(seen, null, 2));
}

export function hasSeen(uri: string): boolean {
  return uri in loadSeen();
}

/** Record these URIs and return only the ones not seen before, order preserved. */
export function markSeen(uris: string[]): string[] {
  const seen = loadSeen();
  const at = new Date().toISOString();
  const fresh: string[] = [];
  for (const uri of uris) {
    if (uri in seen) continue;
    seen[uri] = at;
    fresh.push(uri);
  }
  if (fresh.length) saveSeen(seen);
  return fresh;
}

/** Drop a URI from the seen set, so a deleted object can be re-indexed later. */
export function forgetSeen(uri: string): void {
  const seen = loadSeen();
  if (!(uri in seen)) return;
  delete seen[uri];
  saveSeen(seen);
}

export function seenCount(): number {
  return Object.keys(loadSeen()).length;
}
