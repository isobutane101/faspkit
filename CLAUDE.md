# CLAUDE.md — faspkit

Context for Claude Code. Read this before making changes. It is loaded
automatically at the start of every session.

## What this project is

`faspkit` is a TypeScript toolkit for building **Fediverse Auxiliary Service
Providers (FASPs)** — third-party services that fediverse servers (Mastodon and
compatible) connect to for tasks a single instance can't do well alone: search,
trends, follow recommendations, spam scoring, link previews.

**The goal is the FASP layer**: everything a FASP needs between a fediverse
server and whatever clever thing it does. Registration, signed transport,
consent, getting content in, and answering the queries servers ask. faspkit
implements that layer completely, and ships a deliberately simple reference
index so it runs as a working FASP out of the box.

The only official SDK is Ruby (`mastodon/fasp_ruby`). This is the TypeScript one.
Strategic goal: become the reference implementation for non-Ruby FASP authors.

## Authoritative spec

- Repo: https://github.com/mastodon/fediverse_auxiliary_service_provider_specifications
- **Pinned commit: `f6322174618c3344aca97bc3b871030a137497e0` (2026-07-15)**
- The spec is v0.1 and actively changing. If you need to check spec behaviour,
  clone at that commit. Do not assume newer spec text without being told.
- Spec layout: `general/v0.1/` (protocol basics, registration, provider_info),
  `debug/v0.1/`, `discovery/{data_sharing,account_search,trends,follow_recommendation}/v0.1/`

If a task requires spec behaviour not documented in `docs/SPEC_NOTES.md`, say so
rather than inventing endpoint shapes.

## Architecture

```
src/crypto.ts       RFC 9421 signatures (Ed25519) + RFC 9530 content-digest. Pure, no I/O.
src/consent.ts      FEP-5feb / public-scope consent rules. Pure, no I/O.
src/secretbox.ts    AES-256-GCM encryption at rest for private keys.
src/store.ts        FaspStore interface + JSON adapter. Records, keys, seen-set.
src/activitypub.ts  Server actor, WebFinger, signed object fetching, double-knocking.
src/server.ts       createFasp(), registration handshake, signature middleware, debug capability.
src/datasharing.ts  data_sharing capability: announcements, subscriptions, backfill.
src/discovery.ts    account_search, trends, follow_recommendation. Protocol only.
src/refindex.ts     Reference index that answers those three. In-memory, simple.
src/index.ts        Public exports + a complete runnable FASP (FASPKIT_RUN=1).

scripts/crypto.test.ts       Known-answer unit tests for the signature layer.
scripts/consent.test.ts      Consent fixtures: public vs unlisted vs opted-out.
scripts/store.test.ts        Storage interface, encryption at rest, key rotation.
scripts/e2e.ts               Mock fediverse server + full handshake test.
scripts/datasharing.test.ts  Announcements, consent gate, dedup, double-knocking.
scripts/discovery.test.ts    The three query capabilities, and the layer end to end.
```

Dependency direction is strictly `crypto.ts`/`consent.ts` <- `store.ts` <-
`activitypub.ts` <- `server.ts` <- `datasharing.ts`/`discovery.ts` <-
`refindex.ts` <- `index.ts`.
Keep `crypto.ts` free of Express and filesystem imports — it must stay unit-testable
and reusable by people who don't want the rest of the toolkit.

## Non-negotiable invariants

Breaking any of these produces signatures that verify locally and fail against
real Mastodon. They are the reason this library exists.

1. **Keys are raw 32-byte Ed25519, base64 encoded — not PEM, not DER.**
   Node exports SPKI (12-byte header) and PKCS8 (16-byte header). We strip them
   in `rawPublicKey`/`rawPrivateKey` and re-add fixed DER prefixes on import.
   Never expose a PEM key across the FASP boundary.

2. **Requests and responses sign different component sets.**
   - Requests: `@method`, `@target-uri`, `content-digest`
   - Responses: `@status`, `content-digest`
   Signature params must include `created` and `keyid`.

3. **Verify against raw body bytes.** Never re-serialize JSON before hashing —
   key order changes break the digest. Express `verify` callback captures
   `req.rawBody`; use it.

4. **`keyid` direction matters.** When *we* sign outbound, `keyid` is our
   `serverId` (the ID we generated for that fediverse server). When the
   *instance* signs inbound, its `keyid` is the `faspId` that instance generated
   for us. Mixing these up is the most common integration bug.

5. **`@target-uri` must match byte-for-byte on both sides.** Any proxy that
   rewrites scheme/host/port breaks verification. This is why local dev over a
   tunnel is more reliable than plain localhost behind a reverse proxy.

6. **An identical request repeated within one second is indistinguishable
   from a replay.** Ed25519 is deterministic and `created` has second
   granularity, so the same payload signed twice in the same second produces
   byte-identical headers. `createReplayGuard` rejects the second one. That is
   correct and intended; the escape hatch is RFC 9421's `nonce` parameter,
   which `signRequest`/`signResponse` accept. Do not "fix" this by weakening
   the guard.

7. **Consent is not optional.** Any capability touching user content must honour:
   public content only (never "unlisted"/"quiet public"), FEP-5feb opt-in,
   `discoverable` flag for accounts, and server/user-level blocks. If a task
   asks you to index content without these checks, refuse and flag it.

## Conventions

- ESM only (`"type": "module"`). Use `.js` extensions in relative imports even
  for `.ts` files — required by `moduleResolution: bundler` + tsx.
- `strict: true`. Do not add `any` to silence errors; fix the type.
- **Express's `Response` type shadows the global `fetch` Response.** Import as
  `Response as ExpressResponse` and use `globalThis.Response` for fetch results.
  This has already bitten once.
- No new runtime dependencies without asking. Current runtime deps: `express`
  only. Node built-in `crypto` and global `fetch` cover everything else.
- **Storage goes through `FaspStore`**, which is async so a database adapter can
  replace the JSON one without touching a call site. Do not import store
  internals directly; take a `FaspStore` and default it to `defaultStore`.
- License AGPL-3.0, matching fediverse tooling norms.

## Testing

`npm test` runs six suites, 366 assertions in total, all passing:

- `scripts/crypto.test.ts` (63) — unit tests for the signature layer. A fixed
  keypair and a fixed `created` produce one exact signature base and one exact
  signature, asserted literally. Any refactor that reorders components, changes
  separators, or re-serializes the body fails here instead of failing silently
  against a real Mastodon weeks later. Also covers interop cases another
  implementation will send us: arbitrary labels, multiple signatures in one
  header, parameters in any order, `alg`, and extra covered components.
- `scripts/consent.test.ts` (50) — the consent gate, against fixtures for
  public, unlisted, followers-only, opted-out, and mismatched-author documents.
  These are the assertions with real consequences for real people; every
  plausible way a document could sneak past is asserted to fail closed.
- `scripts/store.test.ts` (67) — the storage interface, AES-256-GCM encryption
  at rest, key rotation, and revalidation bookkeeping. Includes an assertion that reads the file back off
  disk and confirms the private key is not in it.
- `scripts/e2e.ts` (45) — spins up a mock fediverse server and a FASP mounted
  under a base URL *with* path segments (`/fasp/v1`), then runs the handshake,
  a signed round-trip, a signed `GET` with a query string, replay rejection,
  outbound `429`/timeout handling, and the negative cases.
- `scripts/datasharing.test.ts` (72) — four servers: the registered instance, a
  modern origin, a legacy cavage-only origin, and the FASP. Covers the
  announcement endpoint, the consent gate end to end, deduplication,
  double-knocking, deletes, backfill continuation, and revalidation.
- `scripts/discovery.test.ts` (69) — the three query capabilities. Most of it is
  protocol edges, but section 6 runs the whole layer: content is announced,
  fetched from its origin, consent-gated, indexed, and queried back out over
  signed HTTP through all three capabilities.

Run `npm run test:crypto`, `test:consent`, `test:store`, `test:e2e`,
`test:datasharing` or `test:discovery` to run one of them.

**Every new capability must add both positive and negative assertions to the e2e
script.** A capability with only happy-path tests is not done.

Run `npx tsc --noEmit` before declaring any task complete. Typecheck-clean is a
hard gate.

## Protocol vs. algorithm

The capabilities split along one line, and it is the most important design
decision in the project. faspkit implements **the protocol**: parameter parsing,
defaults, validation, RFC 4647 language filtering, rank clamping and ordering,
pagination headers, signed responses, status codes. It delegates **the
algorithm** — what actually ranks or matches — to a provider function.

That follows the spec, which explicitly declines to define how trends are
computed and says implementations MAY compete on it. The protocol is the part
everyone must get identically right; the ranking is the part nobody agrees on.

`refindex.ts` is a reference provider so the layer runs and is testable end to
end. Its ranking is intentionally obvious — count things in a window, scale to
1..100. It is the baseline to beat, not an attempt to win, and a real deployment
should implement the same provider signatures against its own search engine.

## What NOT to do

- Do not add a web UI framework, ORM, or build tooling beyond tsc/tsx unless
  explicitly asked. Scope creep kills SDKs.
- Do not make `refindex.ts` clever. If it starts growing a scoring model, that
  belongs in a separate package or the user's own provider.
- Do not add a database dependency. Storage is deliberately dependency-free
  behind `FaspStore`; a shared-database adapter is the user's to write.
- Do not commit `data/` (contains private keys) or `.env`.
- Do not implement capabilities by guessing endpoint shapes. If it's not in
  `docs/SPEC_NOTES.md` or the pinned spec, ask.

## Current state

Phases 0, 1 and 3 of `docs/IMPLEMENTATION_PLAN.md` are complete.

Working and verified: the signature layer (arbitrary labels, multi-signature
headers, any parameter order, `alg` checking, extra covered components, nonces,
replay rejection), base URLs with path prefixes, correct `@target-uri`
reconstruction including query strings, mandatory response signing, outbound
retry with `Retry-After` and timeouts, the registration handshake, nodeinfo
discovery, the `debug/callback` capability, the JSON store, CI, and the full
`data_sharing` capability — announcements, subscription and backfill clients,
the consent gate, deduplication, and signed object retrieval with
double-knocking behind an ActivityPub server actor.

Also working: the `FaspStore` interface with a cached JSON adapter, AES-256-GCM
encryption of private keys at rest, key rotation with an overlap window, the
periodic revalidation the spec requires, and all three discovery capabilities —
`account_search`, `trends`, `follow_recommendation`.

**Every capability in the v0.1 spec is implemented.** `FASPKIT_RUN=1` starts a
complete FASP that registers, ingests, and answers queries.

Storage is intentionally dependency-free: no Postgres, no ORM. The JSON adapter
caches in memory and writes through atomically, which assumes a single process
owns the data directory. Multi-instance deployments want a shared database
behind the same async `FaspStore` interface.

Not built yet: `link_preview` (no spec exists — drafting one is the upstream
contribution opportunity), npm publication, and validation against a real
Mastodon. See `docs/IMPLEMENTATION_PLAN.md` phases 4 and 5.
