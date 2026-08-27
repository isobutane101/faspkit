# FASP spec notes (condensed)

Distilled from `mastodon/fediverse_auxiliary_service_provider_specifications`
at commit **`f6322174618c3344aca97bc3b871030a137497e0` (2026-07-15)**.

This is a working reference so implementation work doesn't require re-reading
the full spec. It is **not authoritative** — when in doubt, read the pinned spec.
Direction is written as `A => B` meaning A calls B.

---

## General (`general/v0.1/`)

### Discovery
Fediverse servers advertise their FASP base URL in nodeinfo metadata:

```
GET /.well-known/nodeinfo  ->  links[] -> href
GET <href>                 ->  { metadata: { faspBaseUrl: "https://fedi.example.com/fasp" } }
```

Absence of `faspBaseUrl` means the server does not support FASP.

Both sides implement their endpoints relative to a base URL of their own
choosing. **If a base URL contains path segments, all API paths must be
prefixed accordingly.**

### Transport
- HTTPS required in production; MAY be relaxed in development.
- JSON bodies, `Content-Type: application/json`.
- Every request MUST carry `Content-Digest` (RFC 9530), SHA-256 only.
- Auth via HTTP Message Signatures (RFC 9421), algorithm **EdDSA / edwards25519**.
- Request signature covers: `@method`, `@target-uri`, `content-digest`.
- Response signature covers: `@status`, `content-digest`.
- Required signature params: `created`, `keyid`.
- `keyid` = the identifier exchanged at registration.
- Verification failure => `401`.
- `created` timestamp SHOULD be range-checked for drift (we allow ±300s).

Example headers:
```
Content-Digest: sha-256=:RK/0qy18...=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=1728467285;keyid="b2ks6vm8p23w"
Signature: sig1=:+CcncFjyE...==:
```

### Rate limiting
FASPs MAY rate limit. If so: return `429` with a `Retry-After` header (seconds).
Fediverse servers SHOULD respect it.

### Registration handshake

1. Admin registers on the FASP's own signup flow (FASP decides requirements:
   email, password, ToS acceptance). Admin supplies their **server URL**.
2. FASP discovers `faspBaseUrl` via nodeinfo.
3. FASP generates an Ed25519 keypair + a unique `serverId` for that server.
4. **FASP => server**: `POST /registration`
   ```json
   { "name": "Example FASP",
     "baseUrl": "https://fasp.example.com",
     "serverId": "b2ks6vm8p23w",
     "publicKey": "<base64 raw 32-byte>" }
   ```
5. Server persists it, generates its own `faspId` + keypair, replies `201`:
   ```json
   { "faspId": "dfkl3msw6ps3",
     "publicKey": "<base64 raw 32-byte>",
     "registrationCompletionUri": "https://fedi.example.com/admin/fasps" }
   ```
6. FASP MUST display its **public key fingerprint** = base64(SHA-256(raw public key))
   and SHOULD link to `registrationCompletionUri`.
7. Admin compares name + fingerprint in their admin UI and accepts or declines.
   **The FASP is not told the outcome** (declines are silent — anti-spam).
8. Admin selects which capabilities to enable. Server calls `GET /provider_info`
   to list them. Capability selection is likewise not currently pushed to the FASP.

### `GET /provider_info` (FASP endpoint, unsigned)

Required: `name`, `privacyPolicy`, `capabilities`.
`signInUrl` required if the FASP offers admin sign-in. Optional: `contactEmail`,
`fediverseAccount`.

```json
{
  "name": "Example FASP",
  "privacyPolicy": [{ "url": "https://fasp.example.com/privacy.html", "language": "en" }],
  "capabilities": [{ "id": "trends", "version": "1.0" }],
  "signInUrl": "https://fasp.example.com/sign_in",
  "contactEmail": "support@fasp.example.com",
  "fediverseAccount": "@fasp@fedi.example.com"
}
```

`privacyPolicy` MAY be empty only if the FASP receives no PII or sensitive data.

---

## `debug/v0.1` — capability id `callback`

- **Server => FASP**: `POST /debug/v0/callback/logs`, body empty or one JSON object.
  FASP MUST log: that it happened, when, caller IP, and the body. MUST return `201`.
- FASP MUST then call back **FASP => server**: `POST /debug/v0/callback/responses`
  with the same JSON object unchanged.

Implemented in `debugCapability()`.

---

## `discovery/data_sharing/v0.1` — capability id `data_sharing`

The prerequisite for trends / account_search / follow_recommendation.

### Consent rules (MUST — enforce these in code)

FEP-5feb, read in full, is more specific than "check opt-in":
- `indexable` is an **actor-level** attribute (`http://joinmastodon.org/ns#indexable`,
  usually compacted to `toot:indexable`). It is not on the object.
- **A missing `indexable` attribute must be treated as `false`.** Consent is
  deny-by-default.
- An object qualifies when its author is `indexable: true` *and* it is addressed
  `to` the public collection. Public in `cc` only is Mastodon's unlisted / quiet
  public, which MUST NOT be indexed — so checking `to` and `cc` together, or
  merely checking that a URL is fetchable, silently indexes forbidden content.
- Account data additionally requires `discoverable: true`.

- Servers share **local and remote** content (so a FASP sees beyond one instance).
- FASPs **MUST deduplicate** — the same object arrives from many servers.
- Only **URIs** are exchanged. The FASP fetches the actual content itself.
- Never share non-public content. Mastodon's "unlisted"/"quiet public" is
  publicly fetchable but **MUST NOT** be shared.
- FASP MUST check the `to:` property on retrieved content for genuine public scope.
- Creator opt-in via **FEP-5feb** MUST be checked by *both* parties.
- Accounts: `discoverable` flag MUST be `true`.

### Subscriptions — **FASP => server**
`POST /data_sharing/v0/event_subscriptions`
```json
{ "category": "content",          // "content" | "account"
  "subscriptionType": "trends",   // "lifecycle" | "trends"  (trends only for content)
  "maxBatchSize": 10,
  "threshold": { "timeframe": 15, "shares": 3, "likes": 3, "replies": 3 } }
```
- `lifecycle` = notify on create / update / delete.
- `trends` = notify on recent interaction volume. Threshold defaults: timeframe 15 min, shares/likes/replies 3.
- Invalid => `422`. Valid => `201` with `{ "subscription": { "id": "3446" } }`.
- Unsubscribe: `DELETE /data_sharing/v0/event_subscriptions/:id` => `204`.

### Backfill — **FASP => server**
`POST /data_sharing/v0/backfill_requests`
```json
{ "category": "content", "maxCount": 100 }
```
=> `201` with `{ "backfillRequest": { "id": "672" } }`.

Fulfilled **asynchronously** via the same announcement mechanism as subscriptions.

Continuation: `POST /data_sharing/v0/backfill_requests/{id}/continuation`, empty body.
=> `204` if more available, `404` if exhausted or unknown id.
FASP SHOULD NOT call this until an announcement indicated more is available.

### Announcements — **server => FASP**
`POST /data_sharing/v0/announcements` (this is an endpoint *we* must implement)
```json
{ "source": { "subscription": { "id": "3446" } },   // or { "backfillRequest": { "id": "672" } }
  "category": "content",
  "eventType": "new",                                 // "new" | "update" | "delete" (events only)
  "objectUris": ["https://fedi.example.com/objects/1"] }
```
`eventType` is present for events, absent for backfill fulfilment.

---

## `discovery/account_search/v0.1` — capability id `account_search`

**Server => FASP**: `GET /account_search/v0/search?term=teapot&limit=10`
- `term` required; missing => `422`.
- `limit` optional, positive integer, default `20`.
- `200` with a JSON array of **ActivityPub actor URIs**, sorted by relevance desc.
- Pagination via RFC 5988 `Link` header with `rel="next"`.

```json
["https://fedi.example.com/actor/23", "https://other.example.com/user/245/actor"]
```

---

## `discovery/trends/v0.1` — capability id `trends`

**Server => FASP** queries for trending content, hashtags, and links.
The spec deliberately does **not** define the ranking algorithm — implementations
MAY compete on it, and FASPs SHOULD document how trends are computed so admins
can choose. Content is identified by URI.

Read the pinned spec for exact endpoint paths and response shapes before
implementing; they are not reproduced here.

---

## `discovery/follow_recommendation/v0.1` — capability id `follow_recommendation`

Not summarized. Read the pinned spec before implementing.

---

## Known spec gaps (open issues upstream)

Useful context, and candidate contribution opportunities:

- FASPs are **not** told whether a registration was accepted or declined.
- Capability selection by the admin is **not** communicated to the FASP.
- There is no defined way to cleanly **terminate** a FASP/server relationship.
- A FASP has one canonical base URL; hosting capabilities on separate domains
  (for scaling a resource-heavy capability) is not yet supported.
- No spec exists for `link_preview` or spam scoring — both named by Mastodon as
  desirable third-party FASPs. **Writing one is an open contribution opportunity.**
