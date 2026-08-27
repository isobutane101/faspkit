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
request/response middleware, replay protection, outbound rate-limit and timeout
handling, and the `debug/callback` capability.

`npm test` runs 102 assertions against a mock fediverse server, with no network
needed: known-answer tests pinning the exact signature base and signature bytes,
interop cases another implementation will send (arbitrary signature labels,
several signatures in one header, parameters in any order, `alg`, extra covered
components), and the rejections that matter — unsigned, tampered, stale,
replayed, and wrong-`keyid` requests.

The signature layer is the part worth having. Three things break every
first-pass implementation, and all three are handled and tested here:

- The spec exchanges **raw 32-byte Ed25519 keys**, while Node exports SPKI and
  PKCS8 DER. The 12- and 16-byte headers have to be stripped and re-added.
- **Requests and responses cover different components.** Requests sign
  `@method`, `@target-uri` and `content-digest`; responses sign `@status` and
  `content-digest`.
- Verification must run against the **raw request bytes**. Re-serializing the
  JSON changes key order and breaks the digest.

Not built yet: `data_sharing`, `trends`, `account_search`,
`follow_recommendation`, and a Postgres store. See
[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).

## Quick start

```bash
npm install
npm test              # 102 assertions, no network needed
npm run test:crypto   # signature layer only
npm run typecheck
FASPKIT_RUN=1 npm run dev
```

### Base URLs with a path

If your FASP lives at `https://example.com/fasp/v1` rather than at the root of a
host, pass that as `baseUrl`. Routes mount under the prefix and `@target-uri` is
reconstructed to match, as the spec requires. Getting this wrong is a common
source of signatures that verify locally and fail in production, so it is
covered end to end in the test suite.

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
