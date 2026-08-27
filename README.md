# faspkit

A TypeScript toolkit for building **Fediverse Auxiliary Service Providers** (FASPs) —
third-party services that fediverse servers can plug into for tasks a single
instance can't do well on its own (search, trends, spam detection, link previews).

Implements the [FASP general specification v0.1](https://github.com/mastodon/fediverse_auxiliary_service_provider_specifications)
from Mastodon. The only official SDK today is Ruby (`mastodon/fasp_ruby`);
this is the TypeScript one.

## Status

Working: RFC 9421 HTTP Message Signatures (Ed25519), RFC 9530 Content-Digest,
nodeinfo `faspBaseUrl` discovery, the full registration handshake, signed
request/response middleware, and the `debug/callback` capability.

Verified end-to-end against a mock fediverse server (`npm test` — 14 assertions
covering the handshake, signed round-trip, and rejection of unsigned, tampered,
and stale-timestamp requests).

## Quick start

```bash
npm install
npm test          # end-to-end handshake test, no network needed
FASPKIT_RUN=1 npm run dev
```

## Building a capability

```ts
import { createFasp, sendSigned, Capability } from "faspkit";

const spamScore: Capability = {
  id: "spam_score",
  version: "0.1",
  register(router) {
    // Every route registered here already requires a valid signature,
    // and req.faspServer is the authenticated fediverse server.
    router.post("/spam_score/v0/score", async (req, res) => {
      const score = await classify(req.body.content);
      sendSigned(req, res, 200, { score });
    });
  },
};

createFasp({
  name: "My FASP",
  baseUrl: "https://fasp.example.com",
  privacyPolicy: [{ url: "https://fasp.example.com/privacy", language: "en" }],
  capabilities: [spamScore],
}).listen(3000);
```

## Testing against real Mastodon

FASP support is behind a feature flag in Mastodon 4.4+:

```bash
EXPERIMENTAL_FEATURES=fasp bin/dev
```

Then in the admin UI, the FASP section lists registration requests. Your FASP
posts to `/registration`, the admin compares your public-key fingerprint, accepts,
and selects capabilities.

**Note on local dev:** the spec allows relaxing the HTTPS requirement in
development environments, but both sides must agree on the exact `@target-uri`
string when signing — a proxy that rewrites scheme or host will break signature
verification. Use a tunnel (ngrok/cloudflared) rather than plain localhost if
you hit mismatches.

## Implementation notes

Three things that bite people implementing this spec:

1. **Keys are raw, not PEM.** The spec exchanges base64-encoded 32-byte Ed25519
   keys. Node's `crypto` exports SPKI/PKCS8 DER, so you must strip the 12-byte
   (public) and 16-byte (private) headers. See `src/crypto.ts`.
2. **Requests and responses sign different components.** Requests cover
   `@method`, `@target-uri`, `content-digest`; responses cover `@status` and
   `content-digest`. Getting this backwards produces signatures that verify
   locally and fail against Mastodon.
3. **You need the raw body bytes.** Verify against the exact bytes received, not
   a re-serialized JSON object — key order changes break the digest.

## Roadmap

- [ ] `trends`, `account_search`, `follow_recommendation` capabilities (specs exist)
- [ ] Data-sharing spec (backfill + continuous event stream) with consent flags:
      public content only, `discoverable`/`indexable`, server- and user-level blocks
- [ ] Draft a `link_preview` capability spec and open a PR upstream
- [ ] Postgres store, multi-tenant admin UI, key rotation

## License

AGPL-3.0 — matching the norms of the fediverse tooling ecosystem.
