# CLAUDE.md — faspkit

Context for Claude Code. Read this before making changes. It is loaded
automatically at the start of every session.

## What this project is

`faspkit` is a TypeScript toolkit for building **Fediverse Auxiliary Service
Providers (FASPs)** — third-party services that fediverse servers (Mastodon and
compatible) connect to for tasks a single instance can't do well alone: search,
trends, follow recommendations, spam scoring, link previews.

It is a **library / SDK**, not an application. The product is the developer
experience of writing a capability. Everything else is scaffolding.

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
src/crypto.ts   RFC 9421 signatures (Ed25519) + RFC 9530 content-digest. Pure, no I/O.
src/store.ts    Persistence for server records + keys. JSON today, Postgres later.
src/server.ts   createFasp(), registration handshake, signature middleware, debug capability.
src/index.ts    Public exports + linkPreviewCapability sketch + optional runnable entry.
scripts/e2e.ts  Mock fediverse server + full handshake test. No network required.
```

Dependency direction is strictly `crypto.ts` <- `store.ts` <- `server.ts` <- `index.ts`.
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

6. **Consent is not optional.** Any capability touching user content must honour:
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
- License AGPL-3.0, matching fediverse tooling norms.

## Testing

`npm test` runs `scripts/e2e.ts`: spins up a mock fediverse server and a FASP on
localhost, runs the full handshake, and asserts both happy path and rejections
(unsigned, tampered body, stale timestamp). Currently 14 assertions, all passing.

**Every new capability must add both positive and negative assertions to the e2e
script.** A capability with only happy-path tests is not done.

Run `npx tsc --noEmit` before declaring any task complete. Typecheck-clean is a
hard gate.

## What NOT to do

- Do not build a Fediscovery competitor. Search/discovery is run by Mastodon
  gGmbH and grant-funded. We build *toolkit* + capabilities they've said they
  want third parties to provide (link previews, anti-spam).
- Do not add a web UI framework, ORM, or build tooling beyond tsc/tsx unless
  explicitly asked. Scope creep kills SDKs.
- Do not commit `data/` (contains private keys) or `.env`.
- Do not implement capabilities by guessing endpoint shapes. If it's not in
  `docs/SPEC_NOTES.md` or the pinned spec, ask.

## Current state

Working and verified: crypto, registration handshake, nodeinfo discovery,
signature middleware, `debug/callback` capability, JSON store.

Not built yet: data_sharing, trends, account_search, follow_recommendation,
Postgres store, admin UI, key rotation, CI. See `docs/IMPLEMENTATION_PLAN.md`.
