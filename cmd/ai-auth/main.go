// Command ai-auth is a credential vault for AI agents.
//
// An agent authenticates with an ordinary SSH key -- ideally one held by
// ssh-agent, so the agent process never touches key material -- and receives
// scoped, short-lived, audited credentials. Second-factor seeds never leave the
// server: agents ask for a code, not a seed.
package main

import (
	"context"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/linktoming/ai-auth/internal/client"
	"github.com/linktoming/ai-auth/internal/sshid"
)

const usage = `ai-auth -- a credential vault for AI agents

Agent commands (what an AI calls):
  whoami                  show this identity and everything it may reach
  list                    list items this identity can see
  get <item>              read fields from an item
  code <item>             mint a second-factor code (the seed never leaves the vault)
  login <item>            fetch credentials and, with --with-code, a fresh code
  run --env N=item/field -- cmd...
                          run a command with secrets injected as environment
                          variables, so they never pass through the agent
  release <lease-id>      declare that a leased credential is no longer needed

Operator commands:
  init                    create a new vault
  serve                   run the vault server
  keygen                  generate an ed25519 identity for an agent
  admin agent  add|list|disable
  admin item   put|list|delete|rotated
  admin grant  add|list|revoke
  admin approval list|approve|deny
  admin lease  list
  audit tail|verify       read and verify the tamper-evident log

Global flags (accepted before or after the subcommand):
  --server URL     vault address           (env AI_AUTH_SERVER)
  --identity PATH  ssh private key         (env AI_AUTH_IDENTITY)
  --fingerprint FP pick one ssh-agent key  (env AI_AUTH_FINGERPRINT)
  --json           machine-readable output

Run 'ai-auth <command> --help' for the flags of a specific command.
`

// globals holds the flags every client command shares.
type globals struct {
	server      string
	identity    string
	fingerprint string
	jsonOut     bool
	timeout     time.Duration
}

// preset holds global flags given before the subcommand. They become the
// defaults the subcommand's own flags start from, so both
// "ai-auth --identity K get x" and "ai-auth get x --identity K" work.
var preset globals

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.server, "server", preset.server, "vault server URL")
	fs.StringVar(&g.identity, "identity", preset.identity, "path to an ssh private key (defaults to ssh-agent)")
	fs.StringVar(&g.fingerprint, "fingerprint", preset.fingerprint, "select one key from ssh-agent by fingerprint")
	fs.BoolVar(&g.jsonOut, "json", preset.jsonOut, "emit JSON")
	fs.DurationVar(&g.timeout, "timeout", preset.timeout, "request timeout")
}

// globalFlags maps each global flag to whether it consumes a following value.
// Knowing this is what makes stripping them unambiguous: without it, "--json
// list" would swallow the subcommand as the flag's argument.
var globalFlags = map[string]bool{
	"server": true, "identity": true, "fingerprint": true, "timeout": true, "json": false,
}

// splitCommand pulls any leading global flags off argv, leaving the subcommand
// and its own arguments.
func splitCommand(argv []string) (cmd string, rest []string, err error) {
	preset = globals{
		server:      envOr("AI_AUTH_SERVER", "http://127.0.0.1:8711"),
		identity:    os.Getenv("AI_AUTH_IDENTITY"),
		fingerprint: os.Getenv("AI_AUTH_FINGERPRINT"),
		timeout:     30 * time.Second,
	}
	i := 0
	for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "-" {
		name := strings.TrimLeft(argv[i], "-")
		value, inline, hasInline := "", "", false
		if n, v, ok := strings.Cut(name, "="); ok {
			name, inline, hasInline = n, v, true
		}
		takesValue, known := globalFlags[name]
		if !known {
			// Not one of ours: hand it to the normal help/error path below.
			break
		}
		switch {
		case !takesValue:
			value = "true"
			if hasInline {
				value = inline
			}
			i++
		case hasInline:
			value = inline
			i++
		default:
			if i+1 >= len(argv) {
				return "", nil, fmt.Errorf("flag --%s needs a value", name)
			}
			value = argv[i+1]
			i += 2
		}
		if err := preset.set(name, value); err != nil {
			return "", nil, err
		}
	}
	if i >= len(argv) {
		return "", nil, nil
	}
	return argv[i], argv[i+1:], nil
}

func (g *globals) set(name, value string) error {
	switch name {
	case "server":
		g.server = value
	case "identity":
		g.identity = value
	case "fingerprint":
		g.fingerprint = value
	case "json":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("flag --json: %w", err)
		}
		g.jsonOut = v
	case "timeout":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("flag --timeout: %w", err)
		}
		g.timeout = d
	}
	return nil
}

// client builds a connected client.
//
// Preference order matters: ssh-agent first, because a key the agent process
// cannot read is a key it cannot leak. An explicit --identity is only needed
// for end-to-end items, where decryption requires the key itself.
func (g *globals) client() (*client.Client, error) {
	signer, raw, err := g.resolveIdentity()
	if err != nil {
		return nil, err
	}
	return client.New(client.Config{
		BaseURL:  g.server,
		Signer:   signer,
		Identity: raw,
	})
}

func (g *globals) resolveIdentity() (ssh.Signer, crypto.PrivateKey, error) {
	if g.identity != "" {
		pass := os.Getenv("AI_AUTH_IDENTITY_PASSPHRASE")
		return sshid.LoadIdentityFile(expandHome(g.identity), []byte(pass))
	}
	signers, agentErr := sshid.AgentSigners()
	if agentErr == nil && len(signers) > 0 {
		signer, err := sshid.SelectSigner(signers, g.fingerprint)
		if err == nil {
			return signer, nil, nil
		}
		if g.fingerprint != "" {
			return nil, nil, err
		}
	}
	// Fall back to the conventional key locations so a first run works without
	// any configuration at all.
	for _, candidate := range []string{"~/.ssh/ai-auth_ed25519", "~/.ssh/id_ed25519"} {
		path := expandHome(candidate)
		if _, err := os.Stat(path); err == nil {
			return sshid.LoadIdentityFile(path, []byte(os.Getenv("AI_AUTH_IDENTITY_PASSPHRASE")))
		}
	}
	if agentErr != nil {
		return nil, nil, fmt.Errorf("no ssh identity found: %w (and no key at ~/.ssh/ai-auth_ed25519); "+
			"generate one with 'ai-auth keygen'", agentErr)
	}
	return nil, nil, errors.New("no ssh identity found; generate one with 'ai-auth keygen'")
}

func main() {
	cmd, args, err := splitCommand(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-auth: "+err.Error())
		os.Exit(2)
	}
	if cmd == "" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// Ctrl-C should cancel in-flight requests rather than leaving leases that
	// nobody will ever release.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "init":
		err = cmdInit(args)
	case "serve":
		err = cmdServe(ctx, args)
	case "keygen":
		err = cmdKeygen(args)
	case "whoami":
		err = cmdWhoAmI(ctx, args)
	case "list":
		err = cmdList(ctx, args)
	case "get":
		err = cmdGet(ctx, args)
	case "code":
		err = cmdCode(ctx, args)
	case "login":
		err = cmdLogin(ctx, args)
	case "run":
		err = cmdRun(ctx, args)
	case "release":
		err = cmdRelease(ctx, args)
	case "admin":
		err = cmdAdmin(ctx, args)
	case "audit":
		err = cmdAudit(ctx, args)
	case "version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "ai-auth: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-auth: "+err.Error())
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
