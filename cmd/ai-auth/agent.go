package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/linktoming/ai-auth/internal/api"
	"github.com/linktoming/ai-auth/internal/client"
)

func cmdWhoAmI(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	me, err := c.WhoAmI(ctx)
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(me)
	}
	fmt.Printf("agent:       %s\nfingerprint: %s\nrole:        %s\nserver:      %s\n",
		me.Agent, me.Fingerprint, me.Role, me.ServerID)
	if len(me.Grants) == 0 {
		fmt.Println("\nNo grants. This identity is enrolled but cannot reach anything yet.")
		return nil
	}
	fmt.Println("\ngrants:")
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tITEMS\tACTIONS\tFIELDS\tCONSTRAINTS")
	for _, gr := range me.Grants {
		var constraints []string
		if gr.RequireApproval {
			constraints = append(constraints, "needs-approval")
		}
		if gr.RequireReason {
			constraints = append(constraints, "needs-reason")
		}
		if gr.NotAfter != nil {
			constraints = append(constraints, "until "+gr.NotAfter.UTC().Format(time.RFC3339))
		}
		if gr.UsesRemaining != nil {
			constraints = append(constraints, fmt.Sprintf("%d uses left", *gr.UsesRemaining))
		}
		if len(gr.AllowedTargets) > 0 {
			constraints = append(constraints, "targets "+strings.Join(gr.AllowedTargets, "|"))
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", gr.ID, strings.Join(gr.Items, ","),
			strings.Join(gr.Actions, ","), orDash(strings.Join(gr.Fields, ",")),
			orDash(strings.Join(constraints, "; ")))
	}
	return tw.Flush()
}

func cmdList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	out, err := c.List(ctx)
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	if len(out.Items) == 0 {
		fmt.Println("No items are visible to this identity.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ITEM\tTARGET\tFIELDS\t2FA\tACTIONS")
	for _, it := range out.Items {
		otp := "-"
		if it.HasOTP {
			otp = "yes"
		}
		name := it.Name
		if it.NeedsRotation {
			name += " (needs rotation)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, orDash(it.Target),
			orDash(strings.Join(it.Fields, ",")), otp, strings.Join(it.Actions, ","))
	}
	return tw.Flush()
}

// secretFlags are the request-shaping flags shared by get/code/login.
type secretFlags struct {
	reason     string
	target     string
	approval   string
	wait       time.Duration
	ttlSeconds int
}

func (s *secretFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.reason, "reason", "", "why this credential is needed (recorded in the audit log; some grants require it)")
	fs.StringVar(&s.target, "target", "", "the system this credential will be used against")
	fs.StringVar(&s.approval, "approval", "", "an approval id obtained from a previous attempt")
	fs.DurationVar(&s.wait, "wait", 0, "wait up to this long for a human to approve")
	fs.IntVar(&s.ttlSeconds, "lease-ttl", 0, "requested lease lifetime in seconds")
}

// withApproval runs an operation, and when the vault answers "a human must
// approve this", optionally waits and retries with the issued approval id.
func withApproval[T any](ctx context.Context, sf *secretFlags, attempt func(approvalID string) (T, error)) (T, error) {
	var zero T
	result, err := attempt(sf.approval)
	if err == nil {
		return result, nil
	}
	var pending *client.ErrApprovalPending
	if !errors.As(err, &pending) {
		return zero, err
	}
	if sf.wait <= 0 {
		return zero, fmt.Errorf("%w\nretry with: --approval %s (or add --wait 5m to block until a human answers)",
			err, pending.ApprovalID)
	}

	fmt.Fprintf(os.Stderr, "ai-auth: waiting up to %s for a human to approve %s...\n", sf.wait, pending.ApprovalID)
	deadline := time.Now().Add(sf.wait)
	// Poll rather than hold a connection: an approval may take minutes, and an
	// idle HTTP request open that long is a liability, not a feature.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-ticker.C:
		}
		result, err := attempt(pending.ApprovalID)
		if err == nil {
			return result, nil
		}
		if !errors.As(err, &pending) {
			return zero, err
		}
	}
	return zero, fmt.Errorf("timed out waiting for approval %s", pending.ApprovalID)
}

func cmdGet(ctx context.Context, args []string) error {
	var g globals
	var sf secretFlags
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	g.register(fs)
	sf.register(fs)
	var fields multiFlag
	fs.Var(&fields, "field", "field to read (repeatable; default: every field this grant allows)")
	raw := fs.Bool("raw", false, "print only the value, with no trailing newline (for shell capture)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth get <item> [--field NAME] [--reason WHY] [--target HOST]")
		fs.PrintDefaults()
	}
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		fs.Usage()
		return errors.New("exactly one item name is required")
	}
	item := operands[0]

	c, err := g.client()
	if err != nil {
		return err
	}
	type readResult struct {
		values map[string]string
		meta   *api.ReadResponse
	}
	res, err := withApproval(ctx, &sf, func(approvalID string) (readResult, error) {
		values, meta, err := c.Read(ctx, api.ReadRequest{
			Item: item, Fields: fields, Reason: sf.reason, Target: sf.target,
			TTLSeconds: sf.ttlSeconds, ApprovalID: approvalID,
		})
		return readResult{values, meta}, err
	})
	if err != nil {
		return err
	}

	if g.jsonOut {
		return emitJSON(map[string]any{
			"item": res.meta.Item, "lease_id": res.meta.LeaseID,
			"expires_at": res.meta.ExpiresAt, "fields": res.values,
		})
	}
	if *raw {
		if len(res.values) != 1 {
			return fmt.Errorf("--raw needs exactly one field; got %d (use --field)", len(res.values))
		}
		for _, v := range res.values {
			fmt.Print(v)
		}
		return nil
	}
	names := make([]string, 0, len(res.values))
	for name := range res.values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%s: %s\n", name, res.values[name])
	}
	fmt.Fprintf(os.Stderr, "\nlease %s expires %s\n", res.meta.LeaseID,
		res.meta.ExpiresAt.Format(time.RFC3339))
	return nil
}

func cmdCode(ctx context.Context, args []string) error {
	var g globals
	var sf secretFlags
	fs := flag.NewFlagSet("code", flag.ExitOnError)
	g.register(fs)
	sf.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth code <item> [--reason WHY] [--target HOST]")
		fmt.Fprintln(os.Stderr, "\nMints one second-factor code. The seed stays in the vault; there is no")
		fmt.Fprintln(os.Stderr, "command, flag or API that returns it to an agent.")
		fs.PrintDefaults()
	}
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		fs.Usage()
		return errors.New("exactly one item name is required")
	}
	item := operands[0]

	c, err := g.client()
	if err != nil {
		return err
	}
	type codeResult struct {
		code string
		meta *api.CodeResponse
	}
	res, err := withApproval(ctx, &sf, func(approvalID string) (codeResult, error) {
		code, meta, err := c.Code(ctx, api.CodeRequest{
			Item: item, Reason: sf.reason, Target: sf.target, ApprovalID: approvalID,
		})
		return codeResult{code, meta}, err
	})
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(map[string]any{
			"item": res.meta.Item, "code": res.code,
			"expires_at": res.meta.ExpiresAt, "valid_for_seconds": res.meta.ValidForSeconds,
		})
	}
	fmt.Println(res.code)
	if res.meta.ValidForSeconds > 0 {
		fmt.Fprintf(os.Stderr, "valid for %ds\n", res.meta.ValidForSeconds)
	}
	return nil
}

func cmdLogin(ctx context.Context, args []string) error {
	var g globals
	var sf secretFlags
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	g.register(fs)
	sf.register(fs)
	withCode := fs.Bool("with-code", true, "also mint a second-factor code when the item has one")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth login <item> [--with-code=false] [--reason WHY] [--target HOST]")
		fs.PrintDefaults()
	}
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		fs.Usage()
		return errors.New("exactly one item name is required")
	}
	item := operands[0]

	c, err := g.client()
	if err != nil {
		return err
	}
	type loginResult struct {
		payload *api.LoginPayload
		meta    *api.LoginResponse
	}
	res, err := withApproval(ctx, &sf, func(approvalID string) (loginResult, error) {
		payload, meta, err := c.Login(ctx, api.LoginRequest{
			Item: item, Reason: sf.reason, Target: sf.target, WithCode: *withCode,
			TTLSeconds: sf.ttlSeconds, ApprovalID: approvalID,
		})
		return loginResult{payload, meta}, err
	})
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(map[string]any{
			"item": res.meta.Item, "lease_id": res.meta.LeaseID,
			"fields": res.payload.Fields, "code": res.payload.Code,
			"expires_at": res.meta.ExpiresAt,
		})
	}
	names := make([]string, 0, len(res.payload.Fields))
	for name := range res.payload.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%s: %s\n", name, res.payload.Fields[name])
	}
	if res.payload.Code != "" {
		fmt.Printf("code: %s\n", res.payload.Code)
	}
	fmt.Fprintf(os.Stderr, "\nlease %s expires %s\n", res.meta.LeaseID, res.meta.ExpiresAt.Format(time.RFC3339))
	return nil
}

func cmdRelease(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("release", flag.ExitOnError)
	g.register(fs)
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("usage: ai-auth release <lease-id>")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	if err := c.Release(ctx, operands[0]); err != nil {
		return err
	}
	fmt.Println("released")
	return nil
}

// cmdRun is the safest way for an AI agent to use a credential: the value is
// placed in a child process's environment and never printed, so it never enters
// the model's context, the transcript, or the shell history.
func cmdRun(ctx context.Context, args []string) error {
	var g globals
	var sf secretFlags
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	g.register(fs)
	sf.register(fs)
	var envs multiFlag
	var codeEnvs multiFlag
	fs.Var(&envs, "env", "VAR=item/field to inject as an environment variable (repeatable)")
	fs.Var(&codeEnvs, "code-env", "VAR=item to inject a freshly minted second-factor code (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth run --env VAR=item/field [--code-env VAR=item] -- command [args...]")
		fmt.Fprintln(os.Stderr, "\nRuns a command with credentials in its environment. Nothing is printed, so the")
		fmt.Fprintln(os.Stderr, "secret never reaches the agent's context or the terminal scrollback.")
		fmt.Fprintln(os.Stderr, "\nexample:")
		fmt.Fprintln(os.Stderr, "  ai-auth run --env PGPASSWORD=prod/db/password -- psql -h db.internal -U app")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fs.Usage()
		return errors.New("a command to run is required")
	}
	if len(envs) == 0 && len(codeEnvs) == 0 {
		return errors.New("at least one --env or --code-env is required")
	}

	c, err := g.client()
	if err != nil {
		return err
	}

	// Group by item so one item with three fields costs one request, one lease
	// and one audit entry rather than three.
	wanted := map[string][]string{}
	varToField := map[string][2]string{}
	for _, spec := range envs {
		name, ref, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("--env %q must look like VAR=item/field", spec)
		}
		item, field, ok := cutLast(ref, "/")
		if !ok {
			return fmt.Errorf("--env %q must name a field, as VAR=item/field", spec)
		}
		wanted[item] = append(wanted[item], field)
		varToField[name] = [2]string{item, field}
	}

	env := os.Environ()
	leases := []string{}
	for item, fields := range wanted {
		values, meta, err := c.Read(ctx, api.ReadRequest{
			Item: item, Fields: fields, Reason: sf.reason, Target: sf.target,
			TTLSeconds: sf.ttlSeconds, ApprovalID: sf.approval,
		})
		if err != nil {
			return err
		}
		leases = append(leases, meta.LeaseID)
		for name, ref := range varToField {
			if ref[0] != item {
				continue
			}
			val, ok := values[ref[1]]
			if !ok {
				return fmt.Errorf("item %q returned no field %q", item, ref[1])
			}
			env = append(env, name+"="+val)
		}
	}
	for _, spec := range codeEnvs {
		name, item, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("--code-env %q must look like VAR=item", spec)
		}
		code, meta, err := c.Code(ctx, api.CodeRequest{
			Item: item, Reason: sf.reason, Target: sf.target, ApprovalID: sf.approval,
		})
		if err != nil {
			return err
		}
		leases = append(leases, meta.LeaseID)
		env = append(env, name+"="+code)
	}

	// Release every lease as soon as the child exits, so "who is holding what"
	// stays accurate without waiting for the TTL.
	defer func() {
		for _, id := range leases {
			releaseCtx, cancel := contextWithTimeout(5 * time.Second)
			if err := c.Release(releaseCtx, id); err != nil {
				fmt.Fprintf(os.Stderr, "ai-auth: could not release lease %s: %v\n", id, err)
			}
			cancel()
		}
	}()

	// Running a caller-chosen command is the entire feature: this is how a
	// secret reaches a tool without passing through the agent's context.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //#nosec G204 -- the command to run is the user's explicit argument
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Mirror the child's exit status so callers can branch on it.
			defer os.Exit(exitErr.ExitCode())
			return nil
		}
		return fmt.Errorf("run %s: %w", argv[0], err)
	}
	return nil
}

// parseWithOperands parses a flag set whose flags may appear before or after
// positional arguments. Go's flag package stops at the first non-flag argument,
// so "get item --reason why" would otherwise silently drop the reason -- and a
// dropped --reason is a request that fails, or worse, an audit entry with no
// explanation. Commands taking a "--" terminator (run) must not use this.
func parseWithOperands(fs *flag.FlagSet, args []string) ([]string, error) {
	var operands []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return operands, nil
		}
		operands = append(operands, rest[0])
		args = rest[1:]
	}
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// cutLast splits around the final occurrence of sep, so item names may contain
// the separator: "prod/db/password" is item "prod/db", field "password".
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
