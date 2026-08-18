# HTTP API

Base path `/v1`. JSON in, JSON out. All byte-slice fields are base64.

Two facts shape everything below:

- **Secret values are never plain JSON.** They arrive inside `sealed` blobs,
  encrypted under the session keys with
  `AAD = "ai-auth-payload-v1|" ‖ session_id ‖ item ‖ purpose`.
- **There is no endpoint that returns a second-factor seed.** Not documented
  here because it does not exist.

## Authentication

### `POST /v1/handshake/init`

```json
{ "fingerprint": "SHA256:…", "client_ephemeral": "<32 bytes>", "client_nonce": "<32 bytes>" }
```

```json
{ "session_id": "hs_…", "server_id": "ai-auth-prod",
  "server_ephemeral": "<32 bytes>", "server_nonce": "<32 bytes>",
  "expires_at": "2026-01-01T00:00:30Z" }
```

An unknown fingerprint still receives a well-formed challenge. Refusing here
would turn the endpoint into an oracle for "is this key enrolled"; the request
fails at signature verification instead.

### `POST /v1/handshake/complete`

Sign the transcript (see [design.md](design.md#the-handshake)) and send:

```json
{ "session_id": "hs_…", "signature_format": "ssh-ed25519", "signature_blob": "…" }
```

```json
{ "token": "…", "agent": "deploy-bot", "role": "agent",
  "expires_at": "2026-01-01T00:05:00Z" }
```

Pass the token as `Authorization: Bearer <token>` on everything below. A
challenge is answerable exactly once, whatever the outcome.

Repeated signature failures for one fingerprint are rate-limited (10 per 5
minutes by default), and every failure returns the same opaque message.

## Agent endpoints

### `GET /v1/whoami`

Returns the caller's identity and a redacted view of its grants, including uses
remaining. An agent should call this to discover what it can do rather than
guessing and collecting denials.

### `GET /v1/items`

Lists visible items with their releasable field names, whether a second factor
exists, and the permitted actions. `totp_seed` never appears.

### `POST /v1/read`

```json
{ "item": "prod/console", "fields": ["username", "password"],
  "reason": "nightly deploy", "target": "console.example.com",
  "ttl_seconds": 120, "approval_id": "apr_…" }
```

`fields` omitted means "every field this grant allows". `reason` is mandatory
when the grant sets `require_reason`.

```json
{ "item": "prod/console", "lease_id": "lse_…",
  "expires_at": "…", "fields": ["username", "password"],
  "sealed": "<opens to {\"fields\":{\"username\":\"…\",\"password\":\"…\"}}>" }
```

For end-to-end items the server returns what it cannot read instead:

```json
{ "end_to_end": true, "server_id": "ai-auth-prod",
  "ciphertexts": { "password": "…" },
  "wrapped_key": { "fingerprint": "SHA256:…", "scheme": "x25519-hkdf-sha256+xchacha20poly1305",
                   "ephemeral_pub": "…", "ciphertext": "…" } }
```

The client unwraps the data key with its SSH private key and decrypts each field
with `AAD = "ai-auth-field-v1|" ‖ server_id ‖ item ‖ field`.

### `POST /v1/code`

```json
{ "item": "prod/console", "reason": "nightly deploy", "target": "console.example.com" }
```

```json
{ "item": "prod/console", "lease_id": "lse_…", "digits": 6,
  "sealed": "<opens to {\"code\":\"484921\"}>",
  "expires_at": "…", "valid_for_seconds": 23, "reused": false,
  "issuer": "ACME", "account": "svc@acme.io" }
```

`reused: true` means the request landed in a time step already served and
received the same code without consuming quota.

### `POST /v1/login`

Credentials and, with `"with_code": true`, a fresh code in one round trip. The
`totp` action is evaluated separately, so a read-only grant cannot obtain a code
by asking for a login. Not available for end-to-end items.

### `POST /v1/leases/release`

```json
{ "lease_id": "lse_…" }
```

Declares the credential no longer needed. Not required — leases expire — but it
keeps "who is holding what" accurate.

## Operator endpoints

All require the `operator` role.

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/agents` | List identities |
| `POST /v1/admin/agents` | Enrol or update an identity |
| `POST /v1/admin/agents/disable` | Revoke; drops live sessions immediately |
| `GET /v1/admin/items` | List items and their non-secret configuration |
| `POST /v1/admin/items` | Create or update; secrets arrive in `sealed` |
| `POST /v1/admin/items/delete` | Delete an item |
| `GET /v1/admin/grants` | List grants with usage |
| `POST /v1/admin/grants` | Create or replace a grant |
| `POST /v1/admin/grants/revoke` | Revoke a grant |
| `GET /v1/admin/approvals` | Pending requests (`?status=pending`) |
| `POST /v1/admin/approvals/decide` | Approve or deny, once |
| `GET /v1/admin/leases` | Outstanding credential leases |
| `GET /v1/admin/audit` | Recent records plus chain verification |
| `GET /v1/admin/recipients` | Public keys, for building end-to-end items |

Writing an item seals `ItemSecrets` under the session's client-to-server key:

```json
{ "fields": { "username": "svc-deploy", "password": "…" },
  "otp_uri": "otpauth://totp/ACME:svc@acme.io?secret=…" }
```

Reusing a grant id replaces the grant and resets its budget — that is how you
say "give it five more uses" without inventing a new id.

## The approval flow

When a grant sets `require_approval`, a request returns **202** rather than an
error:

```json
{ "approval_id": "apr_…", "status": "pending",
  "expires_at": "…", "message": "a human must approve this request; retry with this approval_id" }
```

Retry with `"approval_id"`. Still pending → another 202. Approved → the request
proceeds and the approval is spent. Approvals are **single-use** and bound to
the exact `(agent, item, action, fields)` tuple, so one for reading a staging
password cannot be spent on minting a production code.

Duplicate requests for the same thing reuse the open approval rather than
flooding the operator.

## Errors

```json
{ "code": "rate_limited", "message": "grant gr_… allows 5 uses per 1m0s; retry in 42s",
  "retry_after_seconds": 43 }
```

| Code | Status | Meaning |
|---|---|---|
| `unauthenticated` | 401 | Missing, expired or invalid session |
| `forbidden` | 403 | Endpoint needs the operator role |
| `no_grant` | 403 | No grant permits this — also returned for items you may not know exist |
| `grant_expired` | 403 | Outside the grant's validity window |
| `field_denied` | 403 | Field not granted, or never releasable |
| `target_denied` | 403 | Target outside the grant's allow-list |
| `reason_required` | 403 | The grant requires a stated reason |
| `grant_exhausted` | 403 | Use budget spent; does not refill |
| `approval_*` | 403 | Approval invalid, expired, denied, replayed or mismatched |
| `rate_limited` | 429 | Retry after `retry_after_seconds` |
| `mint_too_soon` | 429 | Inside the item's mint throttle |
| `not_found` | 404 | No such item, when you were entitled to know |
| `audit_unavailable` | 503 | The log is not writable, so nothing is released |
| `sealed` | 503 | The vault has not been unsealed |

`GET /v1/health` needs no authentication and reports `{status, sealed, protocol}`.
