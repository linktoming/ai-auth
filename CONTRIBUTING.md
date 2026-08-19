# Contributing

Contributions are welcome. This is a credential vault, so the bar for changes
is a little higher than usual — not because contributors are distrusted, but
because a subtle mistake here loses somebody's production passwords.

## Reporting a vulnerability

**Do not open a public issue.** Use the private route in
[SECURITY.md](SECURITY.md). That applies to anything that looks like it might
be a weakness, even if you are not sure.

## Proposing a change

Fork, branch, open a pull request. Every PR runs the same gates the
maintainer's own commits run — there is no path onto `main` that skips them.

Before pushing:

```bash
make lint    # gofmt + go vet
make test    # unit and integration tests
make race    # the race detector
make demo    # the end-to-end tour against a throwaway vault
```

CI additionally runs [govulncheck](https://go.dev/blog/govulncheck), gosec,
CodeQL, and a dependency review on the diff.

## What gets scrutinised hardest

Changes touching these need a clear explanation in the PR description of *why*
the new behaviour is safe, not just what it does:

- **Anything near `totp_seed`.** The seed never leaves the server. Three
  independent mechanisms enforce that (no endpoint returns it, the field is
  non-releasable by name, and policy cannot override it). A change that removes
  or weakens any one of them needs a very good reason.
- **The handshake and key schedule** (`internal/seal`). The transcript is
  length-prefixed and domain-separated on purpose. If you change what is signed,
  change `TranscriptLabel` too, so old signatures cannot be replayed under the
  new meaning.
- **AAD construction** (`internal/store`). Every ciphertext is bound to its item
  and field. Loosening that would let stored blobs be moved between slots.
- **The policy engine** (`internal/policy`). Deny-by-default. New constraints
  must fail closed when unset or misconfigured.
- **The audit log** (`internal/audit`). Append-only and hash-chained. A release
  that cannot be recorded must not happen.

New security-relevant behaviour needs a test that fails without the change.
Several existing tests are named after the property they defend, e.g.
`TestGrantNamingTheSeedStillCannotReleaseIt` — that style is encouraged.

## Suppressing a scanner finding

gosec runs as a hard gate. If a finding is a false positive, annotate the line
with the rule and the reason:

```go
cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //#nosec G204 -- the command to run is the user's explicit argument
```

A bare `//#nosec` with no rule and no justification will be asked to change in
review. The reason is the point: it is what a future reader checks against when
the surrounding code has moved on.

Prefer fixing over suppressing. Two of the findings that shipped with the
initial scan turned out to be genuine hardening opportunities — a 32-bit length
prefix in the signed transcript, and a time-based counter that wrapped on a
pre-epoch clock.

## Style

Match the surrounding code. A few conventions worth knowing:

- Comments explain **why**, not what. If a line needs a comment to say what it
  does, the line usually wants rewriting instead.
- Errors are lowercase, wrapped with `%w`, and say what was being attempted.
- Error messages that a user will read should say what to do next, not just what
  failed.
- No new dependencies without a reason. The module deliberately depends on
  `golang.org/x/crypto` and nothing else; every addition is supply chain that
  the vault's users inherit.

## Licence

Contributions are accepted under the [MIT licence](LICENSE), the same terms the
project is distributed under.
