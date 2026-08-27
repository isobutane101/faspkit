import crypto from "node:crypto";

/**
 * Encryption at rest for private keys.
 *
 * A FASP's store holds the private half of every per-server keypair. Anyone who
 * reads that file can impersonate the FASP to every instance it is registered
 * with, so it should not sit in plaintext JSON.
 *
 * The sealed format is self-describing, which matters more than it looks: it
 * lets an existing plaintext store be read and re-sealed on the next write
 * rather than becoming unreadable the moment a secret is configured.
 *
 *   v1:<iv>:<tag>:<ciphertext>   AES-256-GCM, all fields base64
 *   plain:<value>                explicitly unencrypted (development only)
 *   <value>                      legacy bare value, read but never written
 */

const VERSION = "v1";
const KDF_SALT = "faspkit-key-encryption-v1";

export interface SecretBox {
  seal(plaintext: string): string;
  open(sealed: string): string;
  /** False for the development passthrough, so callers can warn about it. */
  readonly encrypts: boolean;
}

/** AES-256-GCM, with the key derived from a passphrase of any length. */
export function createSecretBox(secret: string): SecretBox {
  if (!secret) throw new Error("createSecretBox requires a non-empty secret");
  const key = crypto.scryptSync(secret, KDF_SALT, 32);

  return {
    encrypts: true,

    seal(plaintext) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      return [
        VERSION,
        iv.toString("base64"),
        cipher.getAuthTag().toString("base64"),
        ct.toString("base64"),
      ].join(":");
    },

    open(sealed) {
      if (sealed.startsWith("plain:")) return sealed.slice("plain:".length);
      if (!sealed.startsWith(`${VERSION}:`)) return sealed; // legacy bare value

      const [, ivB64, tagB64, ctB64] = sealed.split(":");
      if (!ivB64 || !tagB64 || !ctB64) throw new Error("malformed sealed value");

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
      decipher.setAuthTag(Buffer.from(tagB64, "base64"));
      try {
        return Buffer.concat([
          decipher.update(Buffer.from(ctB64, "base64")),
          decipher.final(),
        ]).toString("utf8");
      } catch {
        // GCM authentication failed: wrong secret, or the file was tampered with.
        throw new Error(
          "could not decrypt stored key material — FASPKIT_SECRET does not match the one used to write it",
        );
      }
    },
  };
}

/** Passthrough for development. Values are tagged so their status is obvious. */
export function plaintextSecretBox(): SecretBox {
  return {
    encrypts: false,
    seal: (plaintext) => `plain:${plaintext}`,
    open: (sealed) => (sealed.startsWith("plain:") ? sealed.slice("plain:".length) : sealed),
  };
}

let warned = false;

/**
 * Build the box from the environment.
 *
 * Missing secret in production is fatal rather than a silent downgrade: the
 * failure mode of guessing wrong here is a plaintext key file on a live server,
 * which nobody notices until it matters.
 */
export function secretBoxFromEnv(env: NodeJS.ProcessEnv = process.env): SecretBox {
  const secret = env.FASPKIT_SECRET;
  if (secret) return createSecretBox(secret);

  if (env.NODE_ENV === "production") {
    throw new Error(
      "FASPKIT_SECRET is required in production: refusing to store private keys in plaintext",
    );
  }
  if (!warned) {
    warned = true;
    console.warn(
      "[faspkit] FASPKIT_SECRET is not set — private keys are being stored UNENCRYPTED. " +
        "Set it before running anywhere real.",
    );
  }
  return plaintextSecretBox();
}
