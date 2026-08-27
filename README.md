# faspkit

Run your own **Fediverse Auxiliary Service Provider** — the service a Mastodon
server connects to for search, trends and follow recommendations that reach
beyond what any single instance can see.

```bash
npx faspkit
```

That's the whole install. It prints an admin token and a dashboard URL, you open
it, paste in your server's address, and compare a fingerprint. No config file,
no database, no build step.

---

## What it does

A fediverse server on its own only knows about content its own users have
encountered. A FASP sees across many servers, so it can answer questions a
single instance can't:

- **Account search** — find people across the fediverse, not just those your
  server already knows
- **Trends** — hashtags, links and posts that are actually trending network-wide
- **Follow recommendations** — accounts a user might want to follow

faspkit implements the [FASP specification](https://github.com/mastodon/fediverse_auxiliary_service_provider_specifications)
v0.1 in full, and runs as a complete service out of the box.

## Getting started

```bash
npx faspkit --port 3000
```

Open the dashboard at the URL it prints, sign in with the token it shows, and
use **Connect a server**. faspkit introduces itself to your fediverse server and
shows you a fingerprint; you compare that fingerprint in your server's own admin
interface and approve the registration. That comparison is the entire security
model of registration — it is how you confirm you're approving faspkit and not
someone impersonating it — so don't skip it.

Then use **Backfill** to pull in existing content, or **Subscribe** to receive
new posts as they're created.

### Running it for real

A fediverse server has to be able to reach your FASP, and the URL it reaches you
at is part of every signature — so it must match exactly.

```bash
FASP_BASE_URL=https://fasp.example.com \
FASPKIT_SECRET=$(openssl rand -base64 32) \
NODE_ENV=production \
npx faspkit --port 3000
```

`FASPKIT_SECRET` encrypts private keys at rest and is **required** in
production. Back it up alongside your data directory: without it, the stored
keys cannot be read.

For local experimentation, use a tunnel (`ngrok`, `cloudflared`) rather than
`localhost`, and pass the tunnel URL as `FASP_BASE_URL`. Signature verification
covers the full request URI, so a mismatch between what you configure and what
the other side calls produces 401s that are hard to diagnose.

### Docker

```bash
docker build -t faspkit .
docker run -p 3000:3000 -v faspkit-data:/data \
  -e FASP_BASE_URL=https://fasp.example.com \
  -e FASPKIT_SECRET=... -e NODE_ENV=production faspkit
```

### Options

```
--port <n>          Port to listen on (default 3000)
--base-url <url>    Public URL other servers reach this FASP at
--name <name>       Name shown to instance admins
--username <name>   Actor username for WebFinger
--data <dir>        Where to store keys and state (default ./data)
--no-admin          Don't serve the dashboard
```

Environment: `PORT`, `FASP_BASE_URL`, `FASP_NAME`, `FASP_USERNAME`,
`FASP_CONTACT_EMAIL`, `FASPKIT_DATA`, `FASPKIT_SECRET`, `FASPKIT_ADMIN_TOKEN`.

## Consent

Discovery infrastructure indexes things people wrote. faspkit refuses to index
anything that hasn't been consented to, and enforces that itself rather than
trusting the server that told it about the content:

- Posts must be addressed **`to`** the public collection. Mastodon's "unlisted"
  / "quiet public" posts are publicly fetchable but are **not** public in this
  sense, and are rejected.
- The author must have opted in to indexing via
  [FEP-5feb](https://codeberg.org/fediverse/fep/src/branch/main/fep/5feb/fep-5feb.md).
  A missing opt-in counts as a refusal.
- Accounts additionally need `discoverable: true`.
- Everything indexed is **re-checked at least weekly** and dropped when consent
  is withdrawn, a post is deleted, or its visibility changes.

A server announcing a URI is not permission to index it.

## Using it as a library

The service is assembled from parts you can use on their own. Swap the built-in
index for your own search engine by supplying provider functions:

```ts
import { createFaspApp, trendsCapability } from "faspkit";

const { listen } = await createFaspApp({
  baseUrl: "https://fasp.example.com",
  capabilities: [
    trendsCapability({
      hashtags: async ({ withinLastHours, maxCount, language }) =>
        myEngine.trendingTags({ withinLastHours, maxCount, language }),
    }),
  ],
});
await listen();
```

faspkit implements the protocol — parameter parsing and validation, defaults,
RFC 4647 language filtering, rank clamping and ordering, `Link: rel="next"`
pagination, signed responses — and leaves ranking to you. That follows the spec,
which declines to define how trends are computed and says implementations may
compete on it.

The signature layer (`crypto.ts`) is usable entirely on its own if you only want
RFC 9421 HTTP Message Signatures with Ed25519.

## Status

| Capability | Status |
| --- | --- |
| `general` (registration, signatures, `provider_info`) | done |
| `debug` (`callback`) | done |
| `data_sharing` (announcements, subscriptions, backfill, consent) | done |
| `account_search` | done |
| `trends` (content, hashtags, links) | done |
| `follow_recommendation` | done |
| `link_preview` | no spec exists yet |

`npm test` runs 431 assertions with no network needed, against mock fediverse
servers: known-answer tests pinning exact signature bytes, consent fixtures,
storage and encryption, the full handshake, `data_sharing` end to end including
double-knocking, all three query capabilities, and the app layer.

**Not yet validated against a live Mastodon instance.** The test suite mocks the
other side of every exchange, which catches protocol mistakes but cannot catch a
divergence between the spec text and what Mastodon actually does. If you run it
against a real server, findings are very welcome.

Three things break most first-pass FASP implementations, and all three are
handled and tested here: the spec exchanges **raw 32-byte Ed25519 keys** while
Node exports SPKI/PKCS8 DER; **requests and responses cover different signature
components**; and verification must run against the **raw request bytes**,
because re-serializing JSON changes key order and breaks the digest.

## Storage

No database required. State lives in a JSON store that caches in memory and
writes through atomically, which assumes one process owns the data directory.
For multi-instance deployments, implement the async `FaspStore` interface
against a shared database — that's why it's async.

## License

AGPL-3.0
