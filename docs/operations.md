# Operations

## Creating a vault

```bash
ai-auth init --dir /var/lib/ai-auth --operator-key ~/.ssh/ai-auth-ops.pub
```

This prints a base64 root key **once**. Without it the vault cannot be opened;
with it, every server-side item can be decrypted. Put it in a secret manager
before you close the terminal.

For an interactively-unsealed vault instead:

```bash
AI_AUTH_PASSPHRASE='…' ai-auth init --dir /var/lib/ai-auth \
  --operator-key ~/.ssh/ai-auth-ops.pub --passphrase
```

The key is then derived with Argon2id (t=3, 256 MiB, p=4) from the passphrase
plus a stored salt, and the same passphrase must be present at start.

## Unsealing

The server reads, in order:

| Source | Use |
|---|---|
| `AI_AUTH_ROOT_KEY` | base64 key, from a secret manager |
| `AI_AUTH_ROOT_KEY_FILE` | path to a file containing it |
| `AI_AUTH_PASSPHRASE` | Argon2id-derived, for `--passphrase` vaults |

A wrong key is detected at unseal, not at the first read.

## Running

```bash
ai-auth serve --dir /var/lib/ai-auth \
  --addr 0.0.0.0:8711 --tls-cert /etc/ssl/ai-auth.pem --tls-key /etc/ssl/ai-auth.key
```

The server **refuses to bind a non-loopback address without TLS**. For local
development, bind loopback; for a sidecar, use a unix socket, which keeps the
vault off the network entirely and makes file permissions the first gate:

```bash
ai-auth serve --unix /run/ai-auth.sock     # created 0600
```

Tunables: `--session-ttl` (5m), `--lease-ttl` (2m), `--approval-ttl` (10m).

### systemd

```ini
[Unit]
Description=ai-auth credential vault
After=network.target

[Service]
Type=simple
User=ai-auth
ExecStart=/usr/local/bin/ai-auth serve --dir /var/lib/ai-auth \
  --addr 127.0.0.1:8711
Environment=AI_AUTH_ROOT_KEY_FILE=/run/credentials/ai-auth/root.key
Restart=on-failure

# The vault holds every credential you own; give it nothing else.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ai-auth
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

## Enrolling an agent

On the agent's machine, with the key never leaving it:

```bash
ai-auth keygen --out ~/.ssh/ai-auth_ed25519 --comment deploy-bot
ssh-add ~/.ssh/ai-auth_ed25519       # so the process itself cannot read it
```

Send the operator only `~/.ssh/ai-auth_ed25519.pub`, then:

```bash
ai-auth admin agent add --name deploy-bot --key ./deploy-bot.pub --expires-in 720h
```

`--expires-in` makes identities age out on their own. Re-enrolment is cheap;
prefer short lifetimes.

## Writing secrets without leaking them

Never put a secret in a command line — it is visible in `ps` and lands in shell
history. Both of these read from elsewhere:

```bash
ai-auth admin item put --name prod/db --field password=@/run/secrets/db
printf '%s' "$SECRET" | ai-auth admin item put --name prod/db --field password=@-
```

Values are sealed to the session before they leave the process, so they are
ciphertext on the wire even to a TLS-terminating proxy.

## Adding a second factor

Paste what the target's enrolment page shows behind its QR code:

```bash
ai-auth admin item put --name prod/console \
  --otp-uri 'otpauth://totp/ACME:svc@acme.io?secret=JBSWY3DPEHPK3PXP&issuer=ACME'
```

Or the bare seed, with `--otp-seed` (`-` reads stdin). Non-default parameters
are supported: `--otp-digits`, `--otp-period`, `--otp-algorithm`.

To slow down a compromised agent, set a throttle longer than the code period:

```bash
ai-auth admin item put --name prod/console --otp-min-interval 300
```

Below the period this is redundant — one code per time step is already enforced.

## Rotation

```bash
ai-auth admin item put --name prod/db --rotate-after-use     # flag on release
ai-auth admin item list                                      # shows NEEDS ROTATION
# ... rotate at the target system, then store the new value ...
ai-auth admin item put --name prod/db --field password=@-
ai-auth admin item rotated prod/db                           # clear the flag
```

Rotating the **root key** is not yet a single command. Today: stand up a new
vault, re-enter items through it, and decommission the old one. Treat the root
key as long-lived and protect it accordingly.

## Revocation

```bash
ai-auth admin agent disable deploy-bot   # drops live sessions immediately
ai-auth admin grant revoke gr_…          # narrow the reach, keep the identity
```

Disabling takes effect at once — it does not wait for tokens to expire.

## Audit

```bash
ai-auth audit tail -n 50            # through the server
ai-auth audit verify --dir /var/lib/ai-auth   # reads the file directly
```

Verify from the file, not the API, when the question is whether the server
itself is honest. Ship records off-box if a malicious operator is in your threat
model — the chain makes edits *detectable*, it does not make deletion impossible.

Worth alerting on:

- `decision: deny` bursts — an agent probing beyond its grants
- `action: totp` frequency above what the workload should need
- any `admin.*` action outside a change window
- `chain_valid: false` — investigate immediately

## Backup

Back up the whole data directory (`vault.json` and `audit.log`) and store the
root key separately. Writes are atomic (temp file plus rename, with the
directory fsynced), so a copy taken at any moment is consistent.

Restoring the vault without the root key recovers nothing. Restoring the root
key without the vault recovers nothing. Keep both, apart.

## Health

```bash
curl -s http://127.0.0.1:8711/v1/health
{"protocol":"v1","sealed":false,"status":"ok"}
```

`sealed: true` means the process is up but has no root key — every secret
operation will fail until it is unsealed.
