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

## Automated checks

Every commit and pull request runs, and must pass:

| Check | What it catches |
|---|---|
| `go test` + `-race` | Behavioural regressions, and data races in the shared vault state |
| `examples/demo.sh` | The real binary end to end, including that the denials still deny |
| [govulncheck](https://go.dev/blog/govulncheck) | Known vulnerabilities whose affected symbols this code actually reaches |
| gosec | Weak primitives, unchecked conversions, permissive file modes |
| CodeQL (`security-extended`) | Dataflow-level issues, re-scanned weekly against new queries |
| Dependency review | Vulnerable or non-permissively-licensed dependencies entering via a PR |
| Private-key grep | A key or seed accidentally committed to the tree |

These are gates, not reports: a red check blocks the merge. They are a floor,
not a substitute for review — none of them would notice if a policy check were
quietly removed, which is why [CONTRIBUTING.md](CONTRIBUTING.md) lists the areas
that need a human to think about them.

## Status

This code has **not** been independently audited. The primitives are standard
(X25519, XChaCha20-Poly1305, HKDF-SHA256, Ed25519, Argon2id) and used
conservatively, but standard primitives and a correct assembly of them are
different claims. Weigh that before storing credentials whose loss you could not
absorb.
