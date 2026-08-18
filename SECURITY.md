# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
["Report a vulnerability"](https://github.com/linktoming/ai-auth/security/advisories/new)
form on this repository, rather than opening a public issue.

Useful in a report: what an attacker can do, the conditions needed, and a
reproduction if you have one. A rough report of something real beats a polished
report of something theoretical.

## Scope

This project stores credentials. Findings that are especially interesting:

- Anything that extracts a **second-factor seed** through an agent-facing path.
  This is the property the whole design is arranged around; a break here is the
  most serious result possible.
- Authentication bypass: accepting a signature from an unenrolled key, replaying
  a handshake, hijacking a session, or forging a bearer token.
- Policy bypass: reaching an item or field outside a grant, evading a rate limit
  or use budget, or spending an approval more than once or outside its scope.
- Cryptographic errors: nonce reuse, missing or wrong AAD binding, key
  separation failures, anything letting a ciphertext be moved between slots.
- Audit forgery: modifying the log in a way that still verifies.

Known and documented in [`docs/threat-model.md`](docs/threat-model.md), so not
vulnerabilities in themselves:

- A malicious server operator can read server-side items. Use end-to-end items
  where that matters.
- A released credential cannot be recalled.
- An authorised request from a prompt-injected agent is indistinguishable from a
  legitimate one. That is what approval gates are for.

## Status

This code has **not** been independently audited. The primitives are standard
(X25519, XChaCha20-Poly1305, HKDF-SHA256, Ed25519, Argon2id) and used
conservatively, but standard primitives and a correct assembly of them are
different claims. Weigh that before storing credentials whose loss you could not
absorb.
