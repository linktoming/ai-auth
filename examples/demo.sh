#!/usr/bin/env bash
#
# End-to-end tour of ai-auth. Creates a throwaway vault in a temp directory,
# runs a server, and walks through everything an AI agent and its operator do.
#
#   ./examples/demo.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
BIN="$WORK/ai-auth"
PORT="${AI_AUTH_DEMO_PORT:-8712}"
export AI_AUTH_DIR="$WORK/data"
export AI_AUTH_SERVER="http://127.0.0.1:$PORT"

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
run() { printf '\033[0;90m$ %s\033[0m\n' "$*"; eval "$@"; }

say "Building"
go build -o "$BIN" ./cmd/ai-auth

say "Generating identities"
# In production the operator key lives on a laptop and the agent key lives in
# ssh-agent. Here both are files so the demo is self-contained.
run "$BIN keygen --out $WORK/ops --comment ops >/dev/null"
run "$BIN keygen --out $WORK/bot --comment deploy-bot >/dev/null"

OPS="$BIN --identity $WORK/ops"
BOT="$BIN --identity $WORK/bot"

say "Creating the vault"
"$BIN" init --operator-key "$WORK/ops.pub" --operator-name ops | tee "$WORK/init.txt"
export "$(grep -o 'AI_AUTH_ROOT_KEY=.*' "$WORK/init.txt")"

say "Starting the server"
"$BIN" serve --addr "127.0.0.1:$PORT" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -sf "$AI_AUTH_SERVER/v1/health" >/dev/null && break
  sleep 0.1
done
curl -s "$AI_AUTH_SERVER/v1/health"; echo

say "Enrolling the agent (the operator adds its public key)"
run "$OPS admin agent add --name deploy-bot --key $WORK/bot.pub"

say "Storing a login, including its 2FA seed"
# The seed goes in encrypted to the session and is stored non-releasable. From
# this moment on, no API can hand it back out.
run "$OPS admin item put --name prod/console \
  --title 'Production console' --target console.example.com \
  --field username=svc-deploy \
  --field password='correct horse battery staple' \
  --otp-uri 'otpauth://totp/ACME:svc-deploy@acme.io?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME'"

say "Granting the agent narrow access"
run "$OPS admin grant add --agent deploy-bot \
  --item 'prod/*' --action read --action totp --action list \
  --rate-count 5 --rate-window 1m \
  --require-reason --allowed-target console.example.com \
  --description 'nightly console deploys'"

say "What the agent can see"
run "$BOT whoami"
run "$BOT list"
echo "Note: totp_seed is not listed. It is not something an agent can ask for."

say "Reading credentials"
run "$BOT get prod/console --reason 'nightly deploy' --target console.example.com"

say "Minting a second factor -- a code, never the seed"
run "$BOT code prod/console --reason 'nightly deploy' --target console.example.com"

say "Things the agent cannot do"
run "$BOT get prod/console --field totp_seed --reason x --target console.example.com" || true
run "$BOT get prod/console --target console.example.com" || true
run "$BOT get prod/console --reason x --target evil.example.com" || true

say "The safest pattern: inject into a child process, never print"
# The value never reaches stdout, the agent's context, or the shell history.
run "$BOT run --reason 'schema check' --target console.example.com \
  --env APP_PASSWORD=prod/console/password --code-env APP_OTP=prod/console \
  -- sh -c 'echo \"child received a \${#APP_PASSWORD}-character password and code \$APP_OTP\"'"

say "Break-glass: a credential that needs a human"
run "$OPS admin item put --name prod/root --field password='root-of-all-evil'"
run "$OPS admin grant add --agent deploy-bot --item prod/root \
  --action read --require-approval --require-reason --max-uses 3 >/dev/null"
# shellcheck disable=SC2086  # BOT is a command prefix and must be split
$BOT get prod/root --reason 'incident 4711' 2>&1 | tail -2 || true
run "$OPS admin approval list"
APPROVAL="$($OPS --json admin approval list | grep -o '"id": "apr_[a-f0-9]*"' | head -1 | grep -o 'apr_[a-f0-9]*')"
run "$OPS admin approval approve $APPROVAL --note 'confirmed with on-call'"
run "$BOT get prod/root --reason 'incident 4711' --approval $APPROVAL"
echo "-- and the same approval cannot be spent twice --"
$BOT get prod/root --reason 'incident 4711' --approval "$APPROVAL" || true

say "Zero-knowledge items: the server stores what it cannot read"
run "$OPS admin item put --name prod/e2e --end-to-end --recipient deploy-bot \
  --field password='the-server-never-sees-this'"
run "$OPS admin grant add --agent deploy-bot --item prod/e2e --action read --action list >/dev/null"
run "$BOT get prod/e2e"
printf 'occurrences of that plaintext in the vault file: '
grep -c 'the-server-never-sees-this' "$AI_AUTH_DIR/vault.json" || true

say "Revocation is immediate"
run "$OPS admin agent disable deploy-bot"
$BOT list || true

say "The audit trail"
run "$OPS audit tail -n 15"
run "$BIN audit verify --dir $AI_AUTH_DIR"

say "Done -- everything above lived in $WORK and is about to be deleted"
