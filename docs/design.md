# Design

## The problem

An AI agent needs to log into things. The obvious approach — put the password in
an environment variable, or in the prompt — fails in a specific way that is
worse than it looks:

1. **Secrets are permanent once seen.** A password in an agent's context is in
   the transcript, the trace, the eval dataset, and possibly a support ticket.
2. **There is no blast radius.** An agent with a `.env` file has everything in
   the `.env` file, forever, for every task.
3. **2FA is not actually a second factor.** Giving an agent the TOTP seed so it
   can "handle 2FA" hands over a permanent credential. Anyone who later reads
   the seed can mint codes indefinitely. The second factor stops being a second
   factor the moment it lives beside the first.
4. **Agents can be talked into things.** A prompt-injected agent will ask for
   credentials with complete sincerity. Any control that relies on the agent
   deciding correctly is not a control.

The starting idea — reuse SSH keys, since an agent can already hold one — is the
right one. This document is what falls out of taking it seriously.

## Identity: SSH keys, and only signing

Every identity is an SSH public key in the vault, exactly like `authorized_keys`.
Enrolment is `ai-auth admin agent add --key bot.pub`.

Authentication needs only the ability to **sign**. That matters more than it
sounds: `ssh-agent` will sign for you but will never surrender the key, so an
agent process — the thing most likely to be compromised, or to print its own
memory into a log — can authenticate without ever holding key material.

This constrains the design. `ssh-agent` cannot do key agreement, so anything
requiring the agent to *decrypt* rules out the safest key storage. That is why
transport confidentiality is built from an ephemeral exchange the SSH key merely
*signs over*, rather than from encrypting to the SSH key directly.

## The handshake

```
client                                                    server
  │
  │  1. fingerprint, client_epk, client_nonce
  │ ─────────────────────────────────────────────────────►│
  │                                                        │  generate server_epk,
  │  2. session_id, server_epk, server_nonce               │  server_nonce
  │ ◄─────────────────────────────────────────────────────│
  │
  │  both sides build the transcript T:
  │     T = len-prefix("ai-auth-handshake-v1", server_id, session_id,
  │                    fingerprint, client_epk, client_nonce,
  │                    server_epk, server_nonce)
  │
  │  3. Sign(T)     ← ssh-agent does this; the key never moves
  │ ─────────────────────────────────────────────────────►│
  │                                                        │  verify against the
  │  4. bearer token (5 min)                               │  enrolled public key
  │ ◄─────────────────────────────────────────────────────│
```

Then both sides derive:

```
shared = X25519(own_ephemeral_sk, peer_ephemeral_pk)
prk    = HKDF-Extract(salt = client_nonce ‖ server_nonce, ikm = shared)
c2s    = HKDF-Expand(prk, "ai-auth-handshake-v1 c2s", 32)
s2c    = HKDF-Expand(prk, "ai-auth-handshake-v1 s2c", 32)
```

Four properties come out of this:

- **The signature binds the channel.** Because `T` commits to *both* ephemeral
  public keys, an attacker who substitutes their own changes `T`, and the
  signature stops verifying. There is no window in which a party in the middle
  holds a valid session.
- **Forward secrecy.** The ephemeral keys are used once and dropped. Stealing
  the agent's SSH key tomorrow does not decrypt traffic captured today.
- **No replay.** Each challenge is answerable exactly once — the server deletes
  it on the first attempt, success or failure — and expires in 30 seconds. The
  transcript includes `server_id`, so a signature is useless at another vault,
  and the version label, so it is useless under a future protocol.
- **Confidentiality underneath TLS, not because of it.** Every secret value
  travels inside a `sealed` blob under `s2c`. A TLS-terminating load balancer, a
  request log, an APM trace, or a heap dump of the HTTP layer contains
  ciphertext. TLS is still required in production — it protects metadata and
  prevents traffic analysis — but it is not the only thing standing between a
  proxy and your passwords.

Every field is length-prefixed in `T`, so no two distinct inputs produce the
same transcript. (`Transcript("ab","c") ≠ Transcript("a","bc")` — there is a
test for exactly this.)

## Storage: envelope encryption with bound ciphertext

```
root key (32 bytes, from env / file / Argon2id passphrase)
  └─ wraps ─► per-item data key (DEK)
                └─ encrypts ─► each field, with AAD binding it in place
```

Each field is sealed with XChaCha20-Poly1305 under the item's DEK, with

```
AAD = "ai-auth-field-v1|" ‖ server_id ‖ item_name ‖ field_name
```

The AAD is what stops an attacker with write access to the vault file from
copying the production password blob into a staging item's password field and
reading it back through a staging grant. The ciphertext only opens in the exact
slot it was written to.

Metadata — item names, grants, timestamps — is deliberately **not** encrypted.
Policy you cannot read without unsealing is policy you cannot review, and policy
nobody reviews is decoration.

## The second factor

This is the part the whole design is arranged around.

A TOTP seed is stored as a field named `totp_seed`, marked non-releasable. Three
independent things keep it inside:

1. **No endpoint returns it.** `/v1/code` returns a code. There is no request
   shape that asks for a seed. The `CodeResponse` type has no field that could
   carry one.
2. **The field is non-releasable.** `Item.Releasable()` returns false for
   `totp_seed` *by name*, before consulting the flag — so even a corrupted vault
   record with `releasable: true` cannot release it.
3. **Policy cannot override it.** A grant that explicitly names `totp_seed`
   still fails; the check lives below the policy layer, not inside it. There is
   a test named exactly that.

What the agent gets instead:

```
POST /v1/code {"item": "prod/console", "reason": "nightly deploy"}
→ {"sealed": "…", "valid_for_seconds": 23}      // opens to {"code":"484921"}
```

Anti-abuse on top:

- **One code per time step.** Asking twice inside the same 30-second window
  returns the *same* code and does not consume quota. An agent cannot harvest a
  stream of distinct codes by looping.
- **A mint throttle.** `--otp-min-interval` set longer than the period
  deliberately slows a harvesting agent. (Below the period it is redundant: the
  step rule already caps minting at one code per window.)
- **Server-side HOTP counters.** For counter-based OTP the counter lives in the
  vault, so an agent cannot rewind or race it.
- **The code is never logged.** The audit record carries a 16-hex-character
  digest over `(item, step, code)` — enough to tie an entry to a specific code
  after the fact, useless for producing one.

The seed can be exported, but only through an explicit operator path, never over
the agent API, and the export is loudly audited. Migrating vaults has to be
possible; doing it by accident should not be.

## Authorisation

Deny-by-default. A grant binds one agent to a set of items and actions, plus
constraints:

```go
type Grant struct {
    Agent   string     // exactly one identity
    Items   []string   // globs: "prod/*"
    Fields  []string   // globs; empty = every releasable field
    Actions []Action   // read | totp | list -- separate capabilities

    NotBefore, NotAfter *time.Time
    MaxUses  int         // absolute; never refills
    Rate     *RateLimit  // N per window; rolls

    RequireApproval bool     // a human must say yes, once, per request
    RequireReason   bool     // a stated purpose, recorded next to the release
    AllowedTargets  []string // which system this may be spent against
}
```

`read` and `totp` are deliberately distinct. Reading a password and minting a
second factor are different privileges, and a grant for one must not silently
confer the other — including through the `/v1/login` convenience endpoint, which
re-evaluates `totp` separately before including a code.

Two details worth calling out:

**Grant selection prefers the unconstrained match.** If an agent has both a
narrow automatic grant and a broad break-glass grant needing approval, the
automatic one wins. Adding a safety net must not slow down routine work, or
people will not add it.

**Denials are informative about policy, silent about contents.** If no grant
could match the requested name, a missing item and a forbidden item return the
*same* error — otherwise the API becomes a way to enumerate the vault one guess
at a time. Once a grant does match the name pattern, a genuine 404 is fine: the
agent was already entitled to know.

Usage counters are persisted, so bouncing the server does not refill a budget.
Grants are charged *before* the secret is released: if something fails in
between, we have over-counted, which is the safe direction.

## Leases

Every release creates a lease: who took what, when, why, and for how long. It
cannot claw the value back — nothing can — but it makes *"which agents are
holding production credentials right now"* an answerable question, and it gives
an agent a way to say it is finished (`ai-auth release`, which `ai-auth run`
does automatically when the child exits).

Items marked `--rotate-after-use` are flagged for rotation the moment they are
released, which turns a long-lived password into an effectively single-use one
as long as something acts on the flag.

## Audit

Append-only JSON Lines, each record committing to the hash of the previous one:

```
hash(r) = SHA-256(json(r without its own hash))
r.prev_hash = hash(r-1)
```

Removing, editing or reordering any record breaks verification from that point
forward. `ai-auth audit verify` reads the file directly rather than asking the
server, because verifying through the component you are checking up on proves
nothing.

**A release that cannot be recorded does not happen.** If the audit append
fails, the handler returns 503 instead of the credential. An unrecorded release
is worse than a failed request.

## End-to-end items

Opt-in per item. The data key is wrapped to agent SSH public keys instead of the
root key, so the server stores ciphertext it has no key for.

For Ed25519 recipients the key is mapped to X25519 via the standard birational
map (`u = (1+y)/(1-y) mod p`) — the same construction `age` uses for its
`ssh-ed25519` recipients — then an ephemeral ECDH wraps the data key. RSA
recipients use RSA-OAEP-SHA256. The wrapping key derivation binds both the
ephemeral and recipient public keys, so a wrapped key cannot be replayed at a
different recipient.

The trade-off is real and is the reason this is per-item rather than global: the
server cannot mint second-factor codes for an item it cannot read. Reading one
also requires `--identity`, because `ssh-agent` signs but does not do key
agreement.

## Choices worth defending

**Why not OAuth / OIDC?** Those answer "which user is this" for interactive
humans, and assume a browser and a consent screen. An agent has neither. SSH
keys are already how machine identity works, already in every agent's
environment, and already have a key-holding daemon that refuses to hand the key
over.

**Why not just hand out short-lived tokens from the target system?** Do, where
the target supports it — that is strictly better, and ai-auth is then the thing
holding the credential that mints them. This exists for the large set of systems
that only offer a password and a TOTP prompt.

**Why a bearer token after signature auth?** Signing every request would be
cleaner but costs an `ssh-agent` round trip per call, which for a per-request
tool is enough latency to change behaviour. The compromise: five-minute tokens,
bound to a session whose keys are needed to *open* any response, dropped
instantly when an agent is disabled. A stolen token alone yields ciphertext.

**Why is metadata in plaintext?** See above — reviewable policy beats
theoretically-tighter policy. The values are what need protecting.

**Why is the seed a special-cased field name?** Because defence in depth beats
elegance for the one property everything else is arranged around. Three
independent mechanisms enforce it, and the name check is the one that survives
data corruption and future refactoring.
