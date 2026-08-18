package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linktoming/ai-auth/internal/audit"
	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/server"
	"github.com/linktoming/ai-auth/internal/sshid"
	"github.com/linktoming/ai-auth/internal/store"
	"github.com/linktoming/ai-auth/internal/version"
)

func versionString() string {
	return fmt.Sprintf("ai-auth %s (%s)", version.Version, version.Commit)
}

// dataPaths resolves the vault and audit log locations.
func dataPaths(dir string) (vaultPath, auditPath string) {
	return filepath.Join(dir, "vault.json"), filepath.Join(dir, "audit.log")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", envOr("AI_AUTH_DIR", "./ai-auth-data"), "directory to hold the vault and audit log")
	serverID := fs.String("server-id", "", "stable server identifier (default: derived from the directory name)")
	operatorKey := fs.String("operator-key", "", "authorized_keys line, or a path to a .pub file, for the first operator")
	operatorName := fs.String("operator-name", "operator", "name for the first operator identity")
	passphrase := fs.Bool("passphrase", false, "derive the root key from AI_AUTH_PASSPHRASE instead of printing one")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth init --operator-key <path-or-line> [--dir DIR] [--passphrase]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operatorKey == "" {
		return errors.New("--operator-key is required: the first operator is how you administer the vault")
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	vaultPath, auditPath := dataPaths(*dir)

	id := *serverID
	if id == "" {
		abs, err := filepath.Abs(*dir)
		if err != nil {
			return err
		}
		id = "ai-auth-" + filepath.Base(abs)
	}

	var rootKey []byte
	var kdf *store.KDFParams
	var err error
	if *passphrase {
		pass := os.Getenv("AI_AUTH_PASSPHRASE")
		if len(pass) < 12 {
			return errors.New("set AI_AUTH_PASSPHRASE to at least 12 characters when using --passphrase")
		}
		salt, err := seal.RandomBytes(16)
		if err != nil {
			return err
		}
		kdf = store.DefaultKDF(salt)
		if rootKey, err = kdf.Derive([]byte(pass)); err != nil {
			return err
		}
	} else if rootKey, err = seal.RandomKey(); err != nil {
		return err
	}

	v, err := store.Create(vaultPath, id, rootKey, kdf)
	if err != nil {
		return err
	}

	line, err := readKeyArg(*operatorKey)
	if err != nil {
		return err
	}
	pub, comment, err := sshid.ParseAuthorizedKey(line)
	if err != nil {
		return err
	}
	name := *operatorName
	if name == "" {
		name = comment
	}
	v.Lock()
	v.Data().Agents[sshid.Fingerprint(pub)] = &store.Agent{
		Name:        name,
		Fingerprint: sshid.Fingerprint(pub),
		PublicKey:   sshid.MarshalAuthorizedKey(pub),
		Role:        store.RoleOperator,
		Description: "bootstrap operator",
		CreatedAt:   time.Now().UTC(),
	}
	saveErr := v.SaveLocked()
	v.Unlock()
	if saveErr != nil {
		return saveErr
	}

	log, err := audit.Open(auditPath)
	if err != nil {
		return err
	}
	if _, err := log.Append(audit.Record{
		Actor: name, Action: "vault.init", Decision: audit.Allow, Detail: "server_id=" + id,
	}); err != nil {
		return err
	}
	if err := log.Close(); err != nil {
		return err
	}

	fmt.Printf("Vault created at %s\n", vaultPath)
	fmt.Printf("Server ID:       %s\n", id)
	fmt.Printf("Operator:        %s (%s)\n\n", name, sshid.Fingerprint(pub))
	if *passphrase {
		fmt.Println("The root key is derived from AI_AUTH_PASSPHRASE. The server needs that")
		fmt.Println("same passphrase in its environment to unseal.")
	} else {
		fmt.Println("Root key (store this in a secret manager -- without it the vault cannot be opened,")
		fmt.Println("and anyone holding it can decrypt every stored credential):")
		fmt.Printf("\n    AI_AUTH_ROOT_KEY=%s\n\n", store.FormatRootKey(rootKey))
	}
	return nil
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", envOr("AI_AUTH_DIR", "./ai-auth-data"), "directory holding the vault and audit log")
	addr := fs.String("addr", envOr("AI_AUTH_ADDR", "127.0.0.1:8711"), "listen address")
	socket := fs.String("unix", "", "listen on a unix socket instead of TCP")
	certFile := fs.String("tls-cert", os.Getenv("AI_AUTH_TLS_CERT"), "TLS certificate")
	keyFile := fs.String("tls-key", os.Getenv("AI_AUTH_TLS_KEY"), "TLS private key")
	sessionTTL := fs.Duration("session-ttl", 5*time.Minute, "how long a session token stays valid")
	leaseTTL := fs.Duration("lease-ttl", 2*time.Minute, "default credential lease lifetime")
	approvalTTL := fs.Duration("approval-ttl", 10*time.Minute, "how long a human has to answer an approval request")
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	vaultPath, auditPath := dataPaths(*dir)
	v, err := store.Load(vaultPath)
	if err != nil {
		return err
	}
	if err := unseal(v); err != nil {
		return err
	}
	log, err := audit.Open(auditPath)
	if err != nil {
		return err
	}
	defer log.Close()

	srv, err := server.New(server.Config{
		Vault: v, Audit: log, AuditPath: auditPath, Logger: logger,
		SessionTTL: *sessionTTL, LeaseTTL: *leaseTTL, ApprovalTTL: *approvalTTL,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	var ln net.Listener
	if *socket != "" {
		// A unix socket keeps the vault off the network entirely, and file
		// permissions become the first line of defence.
		_ = os.Remove(*socket)
		if ln, err = net.Listen("unix", *socket); err != nil {
			return fmt.Errorf("listen on %s: %w", *socket, err)
		}
		if err := os.Chmod(*socket, 0o600); err != nil {
			return fmt.Errorf("restrict socket permissions: %w", err)
		}
		defer os.Remove(*socket)
	} else if ln, err = net.Listen("tcp", *addr); err != nil {
		return fmt.Errorf("listen on %s: %w", *addr, err)
	}

	useTLS := *certFile != "" && *keyFile != ""
	if !useTLS && *socket == "" && !isLoopback(*addr) {
		return fmt.Errorf("refusing to serve %s without TLS: pass --tls-cert and --tls-key, "+
			"or bind to loopback and terminate TLS in front", *addr)
	}
	if useTLS {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	errCh := make(chan error, 1)
	go func() {
		if useTLS {
			errCh <- httpSrv.ServeTLS(ln, *certFile, *keyFile)
			return
		}
		errCh <- httpSrv.Serve(ln)
	}()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	logger.Info("ai-auth listening", "address", ln.Addr().String(), "scheme", scheme,
		"server_id", v.ServerID(), "version", version.Version)
	if !useTLS && *socket == "" {
		logger.Warn("serving without TLS on loopback; every response is still sealed to the session, " +
			"but use TLS for anything beyond local testing")
	}

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := contextWithTimeout(10 * time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// unseal installs the root key from the environment.
func unseal(v *store.Vault) error {
	if raw := os.Getenv("AI_AUTH_ROOT_KEY"); raw != "" {
		key, err := store.ParseRootKey(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		return v.Unseal(key)
	}
	if path := os.Getenv("AI_AUTH_ROOT_KEY_FILE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read root key file: %w", err)
		}
		key, err := store.ParseRootKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		return v.Unseal(key)
	}
	if pass := os.Getenv("AI_AUTH_PASSPHRASE"); pass != "" {
		return v.UnsealWithPassphrase([]byte(pass))
	}
	return errors.New("the vault is sealed: set AI_AUTH_ROOT_KEY, AI_AUTH_ROOT_KEY_FILE or AI_AUTH_PASSPHRASE")
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "write the private key here (default: print both keys to stdout)")
	comment := fs.String("comment", "", "key comment, conventionally the agent's name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, pub, err := sshid.GenerateEd25519(*comment)
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Printf("%s\n%s\n", priv, pub)
		return nil
	}
	path := expandHome(*out)
	// 0600 before any bytes are written: never let a private key exist, even
	// momentarily, with wider permissions.
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(path+".pub", []byte(pub+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	fmt.Printf("Private key: %s\nPublic key:  %s\n\n%s\n", path, path+".pub", pub)
	fmt.Println("Enrol this agent with:")
	fmt.Printf("  ai-auth admin agent add --name <name> --key %s.pub\n", path)
	return nil
}

// readKeyArg accepts either a path to a .pub file or a literal key line.
func readKeyArg(arg string) (string, error) {
	if strings.HasPrefix(arg, "ssh-") || strings.HasPrefix(arg, "ecdsa-") {
		return arg, nil
	}
	raw, err := os.ReadFile(expandHome(arg))
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}
