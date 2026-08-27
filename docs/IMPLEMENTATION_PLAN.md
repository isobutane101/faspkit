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

- [ ] **2.1 Storage interface.** Extract a `FaspStore` interface
      (`createServer`, `getServer`, `updateServer`, `allServers`, `lookupKeyByFaspId`).
      Make the JSON implementation one adapter behind it; inject into `createFasp`.
      *Accept:* `server.ts` imports the interface, not the JSON module.

- [ ] **2.2 Postgres adapter.** Implement `PostgresStore` against the same
      interface using `pg`. Schema: `servers` table with the `ServerRecord` fields,
      unique index on `server_id` and `fasp_id`.
      *Ask before adding `pg` as a dependency.*
      *Accept:* the full e2e suite runs green against Postgres via an env switch.

- [ ] **2.3 Private key encryption at rest.** Keys currently sit in plaintext JSON.
      Encrypt `ourPrivateKey` with AES-256-GCM using a key from `FASPKIT_SECRET`.
      Fail loudly at startup if the env var is missing in production mode.
      *Accept:* stored records contain no readable key material; round-trip test passes.

- [ ] **2.4 Key rotation.** Support a second active keypair per server so keys can
      be rolled without breaking in-flight requests: verify against current and
      previous, sign with current.
      *Accept:* rotation test — requests signed with the old key still verify during
      the overlap window, then stop.

---

## Phase 3 — `data_sharing` capability

This is the gateway to trends / account_search / follow_recommendation. See
`docs/SPEC_NOTES.md` for exact shapes. **Consent enforcement is the hard part and
the whole point — do not defer it.**

- [ ] **3.1 Announcement receiver.** Implement `POST /data_sharing/v0/announcements`
      as a guarded route. Parse `source` (subscription vs backfillRequest),
      `category`, `eventType`, `objectUris`. Dispatch to a user-supplied handler.
      *Accept:* e2e test posts both an event announcement and a backfill fulfilment.

- [ ] **3.2 Subscription + backfill client.** Helpers to `POST`/`DELETE`
      `/data_sharing/v0/event_subscriptions` and `POST` `/data_sharing/v0/backfill_requests`,
      plus `.../{id}/continuation`. Handle `422`, `201`, `204`, `404` per spec.
      *Accept:* mock server exercises every documented status code.

- [ ] **3.3 Object fetcher with consent gate.** Announcements carry URIs only. Build
      a fetcher that retrieves each object and **rejects** it unless:
      `to:` indicates genuine public scope; FEP-5feb opt-in is present; for accounts,
      `discoverable === true`. Log rejections with a reason.
      *Accept:* fixtures for public, unlisted, and non-opted-in objects — only the
      first is accepted. **This test is mandatory.**

- [ ] **3.4 Deduplication.** The same object arrives from many servers. Dedupe by
      URI with a persistent seen-set.
      *Accept:* the same URI announced by two mock servers is fetched once.

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

## Explicitly out of scope

Do not build these without an explicit new instruction:

- A Fediscovery competitor (search/discovery FASP). Mastodon gGmbH runs that,
  grant-funded. We build the toolkit and the capabilities they've asked third
  parties to provide.
- Admin web UI, dashboards, billing, or user accounts.
- Any ORM, bundler, or framework beyond `tsc`/`tsx`.
- ActivityPub server functionality. faspkit is a FASP, not a fediverse server.
