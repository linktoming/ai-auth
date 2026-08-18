# Threat model

The honest version. A credential system that oversells itself is worse than one
that is clear about its edges, because people put things in it they should not.

## Assets

| Asset | Where it lives | If it leaks |
|---|---|---|
| Second-factor seeds | Vault only, non-releasable | Permanent 2FA bypass — the worst outcome |
| Passwords, API keys | Vault; released under lease | Compromise until rotated |
| Root key | Operator secret manager | Every server-side item is readable |
| Agent SSH private keys | `ssh-agent`, ideally | Impersonation, bounded by that agent's grants |
| Audit log | Vault directory | Discloses activity; tampering is detectable |

## What an attacker can be

### A network attacker between agent and server

**Stopped.** They see ciphertext. Secret values are sealed under per-session
keys derived from an ephemeral X25519 exchange, so the payload is unreadable
even without TLS, and unreadable later even if the SSH key is stolen (forward
secrecy). They cannot hijack a session: the SSH signature covers a transcript
containing both ephemeral public keys, so substituting one invalidates it. They
cannot replay: challenges are single-use, expire in 30 seconds, and are bound to
the server's identity and the protocol version.

They *can* see metadata — which agent talks to the vault, how often, and which
endpoints. Run TLS in production; that is what it is for here.

### A compromised or prompt-injected agent

**Bounded, not stopped.** This is the realistic case and deserves precision.

It can do anything its grants allow, and it will ask sincerely. What limits it:

- It can only reach items in its grants — not the vault's contents at large. A
  grant for `staging/*` is not a stepping stone to `prod/*`.
- Rate limits and use budgets bound how much it can extract before someone
  notices. Budgets never refill.
- `--require-approval` puts a human in the path for anything that matters. This
  is the only control that actually stops a convincingly-injected agent, and
  it is the one to reach for on your worst credentials.
- `--allowed-target` prevents a staging grant being spent against production.
- Every attempt lands in the audit log with its stated reason, so the incident
  has a timeline.

**Most importantly:** it cannot obtain a second-factor seed. Not through a
crafted request, not through a mistaken grant, not through any API path. The
worst it extracts is one short-lived code per time step per item.

**What target binding does and does not do.** The agent supplies the target
string, so a lying agent can claim any target the grant permits. What it buys
you is that the grant's allow-list is enforced server-side — a staging-scoped
grant cannot be spent on a production target regardless of what the agent
claims — plus an audit record of the claim. It is scope enforcement and
accountability, not attestation.

### Someone who reads the agent's conversation transcript

**Stopped for seeds; mitigated for passwords.** Seeds are never in a transcript
because they never leave the vault. Passwords appear only if the agent printed
them — which is why `ai-auth run` exists. When a secret is injected into a child
process's environment, it never enters the model's context, the transcript, or
the shell history. Prefer it to `get` whenever the tool can be driven that way.

### Someone who steals an agent's SSH private key

**Bounded and revocable.** They become that agent, with exactly its grants, and
everything above applies. Revocation is one command and takes effect
immediately — `admin agent disable` drops live sessions, it does not wait for
tokens to expire.

Keep the key in `ssh-agent` so the agent process cannot read it; use
`--expires-in` so identities age out on their own; use one key per agent so
revoking one does not disrupt the others.

### Someone who reads the vault file (backup, snapshot, stolen disk)

**Stopped, without the root key.** Field values are encrypted; metadata is
readable by design. With the root key, every server-side item is readable —
which is exactly why the root key belongs in a KMS or secret manager and not
next to the vault file.

End-to-end items resist even this: the server holds no key for them, so a
compromised vault file plus the root key still yields nothing.

**Tampering is detectable, not prevented.** The AAD binding stops ciphertext
being moved between fields or items, and the audit chain makes edits visible.
Someone with write access can still delete the whole file. Back it up somewhere
they cannot reach.

### A malicious or compromised server operator

**Only mitigated, and you should know exactly how much.** For server-side items
they can read everything — the root key is theirs — and mint codes at will. The
audit log records their actions, but they could delete the file (the chain makes
edits visible, not disk writes impossible). Ship audit records off-box if this
is in your model.

For end-to-end items they cannot read the values at all. That is the mitigation.
It costs server-side 2FA minting, which is why it is a per-item choice.

### Someone who obtains a live bearer token

**Bounded.** Tokens last five minutes and are useless alone: responses are
sealed under session keys the token does not carry, so a stolen token yields
ciphertext. Combined with the ability to also complete a handshake — i.e. with
the SSH key — see above.

## What this does not attempt

- **Preventing a released credential from being misused.** Once a value leaves,
  it is out. Leases and rotation flags bound the window; nothing closes it. This
  is why `--rotate-after-use` and short lease TTLs exist, and why `run` is the
  preferred pattern.
- **Attesting *which* agent is really running.** The SSH key proves possession
  of a key, not that the process holding it is the code you deployed. Runtime
  attestation is a different problem.
- **Guaranteeing the agent's intent.** A prompt-injected agent making an
  authorised request is indistinguishable from a well-behaved one making the
  same request. That is what approval gates are for.
- **Availability.** No HA, no clustering. A single file-backed vault with atomic
  writes. Run it where you can restore it.
- **Protecting against a compromised operator workstation.** An operator key
  administers the vault. Treat it like a production SSH key.

## Deployment expectations

The design assumes:

1. **TLS in production.** The server refuses to bind a non-loopback address
   without a certificate. Payload sealing is defence in depth, not a substitute.
2. **The root key is not next to the vault.** Environment variable from a secret
   manager, a KMS, or an Argon2id passphrase supplied at start.
3. **The vault directory is `0700` and backed up.** The server writes `0600`
   files, but the directory is yours.
4. **Agent keys live in `ssh-agent`.** File-based identities work and are needed
   for end-to-end items, but they are a step down.
5. **Someone reads the audit log.** Every control here produces evidence.
   Evidence nobody looks at is not a control. Ship it to your SIEM.

## Residual risks, ranked

1. **A compromised server operator reads server-side items.** Mitigate with
   end-to-end items for the worst secrets, off-box audit shipping, and few
   operators.
2. **A prompt-injected agent makes authorised requests.** Mitigate with narrow
   grants, `--require-approval` on anything serious, tight rate limits, and
   alerting on the audit stream.
3. **A released credential is used after the task.** Mitigate with
   `--rotate-after-use`, short leases, and rotation automation.
4. **The code has not been audited.** The primitives are standard and
   conservatively used; the assembly is tested but has not been reviewed by
   anyone but its author. Weigh that before storing credentials whose loss you
   could not absorb.
