# ai-auth

A credential vault for AI agents. Think 1Password, but the "user" is an
autonomous program that may be running attacker-controlled text.

An agent authenticates with an ordinary **SSH key** — ideally one held by
`ssh-agent`, so the agent process never touches key material — and gets back
**scoped, short-lived, audited** credentials. Second-factor seeds never leave
the server: agents ask for a *code*, never a *seed*.

```
      ┌───────────┐   1. signed challenge (ssh-agent signs)   ┌────────────┐
      │ AI agent  │ ────────────────────────────────────────► │            │
      │           │                                           │  ai-auth   │
      │ holds an  │ ◄──────────────────────────────────────── │   server   │
      │ SSH key   │   2. session sealed to an ephemeral key   │            │
      └───────────┘                                           │  holds the │
            │        3. "read prod/console, reason: deploy"   │  seeds and │
            └──────────────────────────────────────────────►  │  passwords │
                        4. username + password + 484921       └────────────┘
                           (the TOTP seed stays inside)              │
                                                                     ▼
                                                             append-only,
                                                          hash-chained audit
```

## The two problems this solves

**Storing credentials.** An agent that holds a password holds it forever, in
its context, its logs, and whatever it pasted into a tool call. Here it holds
only an SSH private key. Everything else is fetched on demand, scoped to the
task, expiring in minutes, and revocable in one place.

**Not leaking 2FA.** This is the interesting half. A TOTP seed is a *permanent*
credential disguised as a temporary one: give an agent the seed and it can mint
codes forever, and so can anyone who reads the transcript. ai-auth stores the
seed as a **non-releasable field** and exposes only a mint endpoint. There is no
flag, no grant, and no API path that returns a seed to an agent. The worst a
fully compromised agent can extract is one six-digit code that dies in seconds
— and the attempt is in the audit log.

## Quick start

```bash
make build

# One key for you, one for the agent.
./ai-auth keygen --out ~/.ssh/ai-auth-ops   --comment ops
./ai-auth keygen --out ~/.ssh/ai-auth-bot   --comment deploy-bot

# Create the vault; save the printed root key in a secret manager.
./ai-auth init --dir ./ai-auth-data --operator-key ~/.ssh/ai-auth-ops.pub

export AI_AUTH_ROOT_KEY=...     # from the line init printed
./ai-auth serve --dir ./ai-auth-data &

export AI_AUTH_SERVER=http://127.0.0.1:8711
export AI_AUTH_IDENTITY=~/.ssh/ai-auth-ops

# Enrol the agent by its public key -- exactly like authorized_keys.
./ai-auth admin agent add --name deploy-bot --key ~/.ssh/ai-auth-bot.pub

# Store a login and its second factor. The seed is sealed on the way in.
./ai-auth admin item put --name prod/console \
  --target console.example.com \
  --field username=svc-deploy --field password=@/path/to/secret \
  --otp-uri 'otpauth://totp/ACME:svc@acme.io?secret=JBSWY3DPEHPK3PXP'

# Grant narrow, constrained access.
./ai-auth admin grant add --agent deploy-bot \
  --item 'prod/*' --action read --action totp \
  --rate-count 5 --rate-window 1m \
  --require-reason --allowed-target console.example.com
```

Now the agent, using its own key:

```bash
export AI_AUTH_IDENTITY=~/.ssh/ai-auth-bot

ai-auth list
ai-auth get  prod/console --reason "nightly deploy" --target console.example.com
ai-auth code prod/console --reason "nightly deploy" --target console.example.com
```

`examples/demo.sh` runs this whole tour — including the denials — against a
throwaway vault in a temp directory. It is the fastest way to see the shape of
the thing.

## The best way for an agent to use a secret: never see it

```bash
ai-auth run --reason "schema migration" --target db.internal \
  --env PGPASSWORD=prod/db/password --code-env OTP=prod/db \
  -- psql -h db.internal -U app -f migrate.sql
```

The values go straight into the child process's environment. They never reach
stdout, the model's context window, the conversation transcript, or the shell
history — and the lease is released the moment the child exits. When a tool can
be driven this way, prefer it to `get`.

## What a grant can say

Grants are deny-by-default: an identity with no matching grant cannot tell that
an item exists.

| Constraint | Flag | What it buys you |
|---|---|---|
| Which items | `--item 'prod/*'` | Blast radius |
| Which fields | `--field username` | A grant that reads usernames but not passwords |
| Which actions | `--action read\|totp\|list` | Reading a password ≠ minting a code |
| Expiry | `--expires-in 24h` | Access that ends on its own |
| Budget | `--max-uses 3` | An absolute ceiling that never refills |
| Rate | `--rate-count 5 --rate-window 1m` | Bounds a runaway or compromised loop |
| Stated purpose | `--require-reason` | Every release carries a why, in the log |
| Destination | `--allowed-target console.example.com` | A staging grant cannot be spent on prod |
| A human | `--require-approval` | Break-glass access that someone must say yes to |

The approval flow is single-use and bound to the exact request: an approval for
reading a staging password cannot be spent on minting a production code.

## Two storage modes

**Server-side (default).** The server holds a root key, unwraps each item's data
key, and can compute with the values. This is what makes server-side 2FA minting
possible.

**End-to-end** (`--end-to-end --recipient <agent>`). The data key is wrapped
only to agent SSH public keys; the server stores ciphertext it cannot read.
Strictly stronger against a compromised server — and strictly less capable: no
second-factor minting, since minting requires reading the seed. Choose per item.
Reading one needs `--identity` rather than `ssh-agent`, because an agent can
sign but cannot perform key agreement.

## Documentation

- [`docs/design.md`](docs/design.md) — how the protocol and crypto work, and why
- [`docs/threat-model.md`](docs/threat-model.md) — what this stops, and what it honestly does not
- [`docs/api.md`](docs/api.md) — the HTTP API
- [`docs/operations.md`](docs/operations.md) — deployment, unsealing, rotation, backup
- [`SECURITY.md`](SECURITY.md) — reporting vulnerabilities

## Status

Working, tested, and not yet audited. The cryptography is standard and
conservative (X25519, XChaCha20-Poly1305, HKDF-SHA256, Ed25519, Argon2id), but
"standard primitives" and "correctly assembled" are different claims, and only
the first one has been checked by anyone other than its author. Read
[`docs/threat-model.md`](docs/threat-model.md) before putting real production
credentials in it.

## Licence

MIT — see [LICENSE](LICENSE).

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This project handles credentials and second-factor secrets. It has not been
independently security audited. You are solely responsible for evaluating its
suitability, for how you deploy and operate it, and for any loss, damage,
credential compromise, service disruption or other harm arising from its use.
Use it at your own risk.
