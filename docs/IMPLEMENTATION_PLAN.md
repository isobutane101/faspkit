# faspkit — implementation plan

Task list for Claude Code. Read `CLAUDE.md` and `docs/SPEC_NOTES.md` first.

**How to use this:** work one phase at a time. Do not start a phase until the
previous one is typecheck-clean and `npm test` passes. Each task lists its
acceptance criteria — treat those as the definition of done, and check the box
in this file when complete.

**Hard gates for every task:**
- `npx tsc --noEmit` clean
- `npm test` passes with both positive *and* negative assertions for new code
- No new runtime dependencies without asking

---

## Phase 0 — Repo hygiene (do first, ~30 min)

- [x] **0.1 Verify baseline.** Run `npm install`, `npx tsc --noEmit`, `npm test`.
      Confirm 14/14 assertions pass before changing anything. If they don't,
      stop and report — do not "fix" by weakening assertions.

- [x] **0.2 Add CI.** Create `.github/workflows/ci.yml`: on push and PR, Node 20
      and 22 matrix, run `npm ci`, `npx tsc --noEmit`, `npm test`.
      *Accept:* workflow is valid YAML and green on first push.

- [x] **0.3 Add `.env.example`** documenting `PORT`, `FASP_BASE_URL`, `FASP_NAME`,
      `FASPKIT_DATA`, `FASPKIT_RUN`. Confirm `.env` and `data/` are gitignored.
      *Accept:* `git status` shows no key material or env files staged.

- [x] **0.4 Split crypto tests out.** Move signature/digest unit tests into
      `scripts/crypto.test.ts` (keep `e2e.ts` for the integration path). Add
      known-answer tests: fixed keypair + fixed `created` => stable signature base.
      *Accept:* signature base string is asserted literally, so a refactor that
      changes component order fails loudly.

---

## Phase 1 — Harden the core (the actual product)

This is what makes the library worth using. Prioritize it over new capabilities.

- [x] **1.1 Signature edge cases.** Currently `verifyRequest` assumes label `sig1`
      and a single signature. Handle: arbitrary labels, multiple signatures in one
      header (pick the one whose covered components satisfy us), and `Signature-Input`
      params in any order. Reject unknown `alg` if present.
      *Accept:* tests for label `mysig`, two-signature header, and reordered params.

- [x] **1.2 Base URL path prefixes.** Spec: if a base URL contains path segments,
      all API paths MUST be prefixed. `createFasp` currently mounts at root.
      Add a `basePath` option; ensure `@target-uri` reconstruction in
      `requireSignature` uses the full external URL including prefix.
      *Accept:* e2e test with FASP mounted at `https://host/fasp/v1` passes.

- [x] **1.3 Fix `@target-uri` reconstruction.** It currently concatenates
      `opts.baseUrl + req.originalUrl`, which double-counts if `baseUrl` has a
      path, and ignores query strings on GET capabilities (needed for
      `account_search`). Derive the target URI correctly and test with a query string.
      *Accept:* signed `GET /account_search/v0/search?term=x&limit=5` verifies.

- [x] **1.4 Response signing correctness.** `sendSigned` silently skips signing
      when `req.faspServer` is absent. Make that an explicit error rather than a
      silent unsigned response.
      *Accept:* unit test asserts unsigned responses are impossible on guarded routes.

- [x] **1.5 Replay protection.** Timestamp skew alone doesn't prevent replay within
      the window. Add an in-memory LRU of seen (keyid, signature) pairs with TTL
      equal to the skew window; reject duplicates with `401`.
      *Accept:* replaying a valid signed request twice yields `201` then `401`.

- [x] **1.6 Outbound retry + rate-limit handling.** `callServer` must honour `429`
      + `Retry-After` with bounded exponential backoff, and time out. Servers may
      be slow or down; a FASP must not hang.
      *Accept:* mock server returning `429` then `201` succeeds; permanent `429` gives up.

---

**Phases 0 and 1 are complete.** `npm test` runs 102 assertions across
`scripts/crypto.test.ts` (63) and `scripts/e2e.ts` (39); `npx tsc --noEmit` is
clean. Two notes for whoever picks up Phase 2:

- Repeating a byte-identical request within one second is now rejected as a
  replay, because deterministic Ed25519 plus second-granularity `created` makes
  it indistinguishable from one. `signRequest`/`signResponse` accept an RFC 9421
  `nonce` for callers that legitimately need to repeat a request.
- The replay guard is per-process and in-memory. A FASP running more than one
  instance behind a load balancer will not catch a replay that lands on a
  different instance; that wants a shared store, which is Phase 2 work.

---

## Phase 2 — Storage and multi-tenancy

- [x] **2.1 Storage interface.** Extract a `FaspStore` interface
      (`createServer`, `getServer`, `updateServer`, `allServers`, `lookupKeyByFaspId`).
      Make the JSON implementation one adapter behind it; inject into `createFasp`.
      *Accept:* `server.ts` imports the interface, not the JSON module.

- [x] ~~**2.2 Postgres adapter.**~~ **Dropped by decision: faspkit stays
      dependency-free.** The JSON adapter now caches in memory and writes
      through atomically, which is enough for a single-process FASP. Anyone
      needing multi-instance deployment implements the async `FaspStore`
      interface against their own database — that is why it is async. Implement `PostgresStore` against the same
      interface using `pg`. Schema: `servers` table with the `ServerRecord` fields,
      unique index on `server_id` and `fasp_id`.
      *Ask before adding `pg` as a dependency.*
      *Accept:* the full e2e suite runs green against Postgres via an env switch.

- [x] **2.3 Private key encryption at rest.** Keys currently sit in plaintext JSON.
      Encrypt `ourPrivateKey` with AES-256-GCM using a key from `FASPKIT_SECRET`.
      Fail loudly at startup if the env var is missing in production mode.
      *Accept:* stored records contain no readable key material; round-trip test passes.

- [x] **2.4 Key rotation.** Support a second active keypair per server so keys can
      be rolled without breaking in-flight requests: verify against current and
      previous, sign with current.
      *Accept:* rotation test — requests signed with the old key still verify during
      the overlap window, then stop.

---

**2.1, 2.3 and 2.4 are done.** `FaspStore` is async throughout precisely so the
Postgres adapter can drop in without touching a call site — which required
resolving signature keys before verification rather than from inside it, hence
`signatureKeyids()` in `crypto.ts` and `lookupKey` now accepting several keys.

**2.2 was dropped:** no Postgres, no runtime dependency beyond Express. The
tradeoff is stated plainly in the store — a single process must own the data
directory, because each process caches records in memory.

One honest caveat on 2.4: the FASP spec defines no key-rotation handshake, so
`rotateTheirKey` (accept a new key from an instance, keeping the old one for an
overlap) is the useful half. `rotateOurKeypair` exists but cannot be used safely
on its own — an instance keeps verifying against the public key it got at
registration, so rolling our key breaks outbound requests until re-registration.
That gap is worth raising upstream.

---

## Phase 3 — `data_sharing` capability

This is the gateway to trends / account_search / follow_recommendation. See
`docs/SPEC_NOTES.md` for exact shapes. **Consent enforcement is the hard part and
the whole point — do not defer it.**

- [x] **3.1 Announcement receiver.** Implement `POST /data_sharing/v0/announcements`
      as a guarded route. Parse `source` (subscription vs backfillRequest),
      `category`, `eventType`, `objectUris`. Dispatch to a user-supplied handler.
      *Accept:* e2e test posts both an event announcement and a backfill fulfilment.

- [x] **3.2 Subscription + backfill client.** Helpers to `POST`/`DELETE`
      `/data_sharing/v0/event_subscriptions` and `POST` `/data_sharing/v0/backfill_requests`,
      plus `.../{id}/continuation`. Handle `422`, `201`, `204`, `404` per spec.
      *Accept:* mock server exercises every documented status code.

- [x] **3.3 Object fetcher with consent gate.** Announcements carry URIs only. Build
      a fetcher that retrieves each object and **rejects** it unless:
      `to:` indicates genuine public scope; FEP-5feb opt-in is present; for accounts,
      `discoverable === true`. Log rejections with a reason.
      *Accept:* fixtures for public, unlisted, and non-opted-in objects — only the
      first is accepted. **This test is mandatory.**

- [x] **3.4 Deduplication.** The same object arrives from many servers. Dedupe by
      URI with a persistent seen-set.
      *Accept:* the same URI announced by two mock servers is fetched once.

---

**Phase 3 is complete**, and reading the full spec rather than the condensed
notes turned up more than the task list implied. Three things were built that
the plan did not name, because the spec requires them before a single object can
be fetched: an ActivityPub server actor at `/actor` with its own RSA keypair,
WebFinger, and double-knocking between RFC 9421 and draft-cavage signatures.
`docs/SPEC_NOTES.md` has been corrected accordingly — the announcement endpoint
answers `204` not `201`, `eventType` includes `trending`, and backfill responses
carry `moreObjectsAvailable`.

**Still outstanding from this phase:** the spec requires re-checking indexed
content and accounts at least weekly to confirm they are still public and still
opted in, and that loop is not built. It needs a persistent record of what was
indexed and when, which is really Phase 2 storage work — so it is listed here
rather than silently dropped:

- [x] **3.5 Weekly revalidation.** Re-fetch indexed objects and accounts at
      least once a week, re-run the consent gate, apply updates, and remove
      anything that is no longer public or no longer opted in. Objects covered
      by a live subscription MAY skip the week's check.
      *Accept:* a fixture whose author flips `indexable` to `false` is dropped
      on the next pass.

---

## Phase 4 — Contribution and positioning

The strategic payoff. Cheap relative to its value.

- [ ] **4.1 Draft a `link_preview` capability spec.** No spec exists; Mastodon has
      publicly named link preview generation as a desirable third-party FASP.
      Write it in the upstream spec repo's format and style: overview, capability
      identifier, provider endpoints, instance endpoints, status codes, privacy
      considerations. Put it in `docs/proposals/link_preview_v0.1.md`.
      *Accept:* reads like the existing `debug/v0.1` spec; no unresolved TODOs.

- [ ] **4.2 Implement it** against the draft, replacing the sketch in `src/index.ts`.
      *Accept:* signed round-trip test with a mocked preview fetcher.

- [ ] **4.3 Publish to npm** as `faspkit` (or a scoped name if taken). Add
      `files`, `exports`, `types` to `package.json`; ship `dist/` via `npm run build`.
      *Accept:* `npm pack` contains `dist/` and no `data/`, `.env`, or tests.

- [ ] **4.4 Open a Discussion upstream** in the spec repo introducing faspkit as a
      TypeScript implementation, and offer the `link_preview` draft as a PR.
      Draft the text; **do not post — hand it to the human.**

---

## Phase 5 — Real-world validation (human-in-the-loop)

- [ ] **5.1 Mastodon integration guide.** Document setting up Mastodon 4.4+ with
      `EXPERIMENTAL_FEATURES=fasp`, registering faspkit, comparing the fingerprint,
      accepting, enabling capabilities. Include a troubleshooting section for
      `@target-uri` mismatches behind proxies (recommend a tunnel over localhost).
      *Accept:* a stranger can follow it without reading the spec.

- [ ] **5.2 Interop notes.** After a real Mastodon test, record every divergence
      between the spec text and Mastodon's actual behaviour in `docs/INTEROP.md`.
      **This file is the most valuable artifact in the repo** — it's knowledge that
      exists nowhere else and is the reason people will use this library.

---

## Phase 6 — the discovery capabilities (done)

Added after the goal was restated as *build the FASP layer*. All three remaining
v0.1 capabilities are implemented, so faspkit now covers the entire spec.

- [x] **6.1 `account_search`.** GET with `term` (required, else 422) and
      `limit` (default 20). Answers a bare JSON array of actor URIs sorted by
      relevance — not an object; wrapping it would break conforming clients.
      RFC 5988 `Link: rel="next"` pagination.
- [x] **6.2 `trends`.** GET `/trends/v0/{content,hashtags,links}` with
      `withinLastHours` (default 24, at least 168 supported), `maxCount`
      (default 20) and `language` (RFC 4647 basic filtering). Ranks are clamped
      to 1..100 and re-sorted descending, because a server merging results from
      several FASPs depends on both.
- [x] **6.3 `follow_recommendation`.** GET with `accountUri` (required, else
      422) and optional `language`. Filtering out already-followed, blocked and
      domain-blocked accounts is explicitly the fediverse server's job.
- [x] **6.4 Reference index.** `createReferenceIndex()` ingests consent-gated
      objects and answers all three, so the layer runs and is testable end to
      end rather than being a set of interfaces.

## Explicitly out of scope

Do not build these without an explicit new instruction:

- Admin web UI, dashboards, billing, or user accounts.
- Any ORM, bundler, database driver, or framework beyond `tsc`/`tsx`.
- ActivityPub server functionality beyond the server actor the spec requires.
  faspkit is a FASP, not a fediverse server.
- A sophisticated ranking model in `refindex.ts`. It is a documented baseline;
  competing on the algorithm belongs in a provider, which is what the seam is
  for.
