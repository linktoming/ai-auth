package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/linktoming/ai-auth/internal/adminapi"
	"github.com/linktoming/ai-auth/internal/audit"
	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/sshid"
	"github.com/linktoming/ai-auth/internal/store"
)

const adminUsage = `usage: ai-auth admin <group> <command> [flags]

  agent    add | list | disable
  item     put | list | delete | rotated
  grant    add | list | revoke
  approval list | approve | deny
  lease    list
`

func cmdAdmin(ctx context.Context, args []string) error {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, adminUsage)
		return errors.New("an admin group and command are required")
	}
	group, sub, rest := args[0], args[1], args[2:]
	switch group + " " + sub {
	case "agent add":
		return adminAgentAdd(ctx, rest)
	case "agent list":
		return adminAgentList(ctx, rest)
	case "agent disable":
		return adminAgentDisable(ctx, rest)
	case "item put":
		return adminItemPut(ctx, rest)
	case "item list":
		return adminItemList(ctx, rest)
	case "item delete":
		return adminItemDelete(ctx, rest)
	case "item rotated":
		return adminItemRotated(ctx, rest)
	case "grant add":
		return adminGrantAdd(ctx, rest)
	case "grant list":
		return adminGrantList(ctx, rest)
	case "grant revoke":
		return adminGrantRevoke(ctx, rest)
	case "approval list":
		return adminApprovalList(ctx, rest)
	case "approval approve":
		return adminApprovalDecide(ctx, rest, true)
	case "approval deny":
		return adminApprovalDecide(ctx, rest, false)
	case "lease list":
		return adminLeaseList(ctx, rest)
	default:
		fmt.Fprint(os.Stderr, adminUsage)
		return fmt.Errorf("unknown admin command %q", group+" "+sub)
	}
}

func adminAgentAdd(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin agent add", flag.ExitOnError)
	g.register(fs)
	name := fs.String("name", "", "agent name, used by grants")
	key := fs.String("key", "", "path to a .pub file, or a literal authorized_keys line")
	role := fs.String("role", "agent", `"agent" or "operator"`)
	desc := fs.String("description", "", "free-form description")
	expires := fs.Duration("expires-in", 0, "expire this identity after the given duration (0 = never)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *key == "" {
		return errors.New("--name and --key are both required")
	}
	line, err := readKeyArg(*key)
	if err != nil {
		return err
	}
	req := adminapi.PutAgentRequest{Name: *name, PublicKey: line, Role: *role, Description: *desc}
	if *expires > 0 {
		t := time.Now().UTC().Add(*expires)
		req.ExpiresAt = &t
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out store.Agent
	if err := c.Admin(ctx, http.MethodPost, "/v1/admin/agents", req, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	fmt.Printf("enrolled %s as %s\n%s\n", out.Name, out.Role, out.Fingerprint)
	return nil
}

func adminAgentList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin agent list", flag.ExitOnError)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out struct {
		Agents []store.Agent `json:"agents"`
	}
	if err := c.Admin(ctx, http.MethodGet, "/v1/admin/agents", nil, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tROLE\tFINGERPRINT\tSTATUS\tLAST SEEN")
	for _, a := range out.Agents {
		status := "active"
		if ok, why := a.Active(time.Now().UTC()); !ok {
			status = why
		}
		seen := "never"
		if !a.LastSeen.IsZero() {
			seen = a.LastSeen.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.Name, a.Role, a.Fingerprint, status, seen)
	}
	return tw.Flush()
}

func adminAgentDisable(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin agent disable", flag.ExitOnError)
	g.register(fs)
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("usage: ai-auth admin agent disable <name-or-fingerprint>")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out store.Agent
	if err := c.Admin(ctx, http.MethodPost, "/v1/admin/agents/disable",
		adminapi.DisableAgentRequest{Fingerprint: operands[0]}, &out); err != nil {
		return err
	}
	fmt.Printf("disabled %s; its live sessions were dropped\n", out.Name)
	return nil
}

func adminItemPut(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin item put", flag.ExitOnError)
	g.register(fs)
	name := fs.String("name", "", "item name")
	title := fs.String("title", "", "human-readable title")
	target := fs.String("target", "", "the system these credentials belong to")
	desc := fs.String("description", "", "description")
	var fields multiFlag
	fs.Var(&fields, "field", "NAME=VALUE (repeatable). Use NAME=@- to read the value from stdin, or NAME=@path to read a file")
	otpSeed := fs.String("otp-seed", "", "base32 second-factor seed ('-' to read from stdin)")
	otpURI := fs.String("otp-uri", "", "otpauth:// enrolment URI ('-' to read from stdin)")
	otpDigits := fs.Int("otp-digits", 0, "code length (default 6)")
	otpPeriod := fs.Int("otp-period", 0, "code period in seconds (default 30)")
	otpAlgorithm := fs.String("otp-algorithm", "", "SHA1, SHA256 or SHA512")
	otpMinInterval := fs.Int("otp-min-interval", 0, "minimum seconds between mints (default 25; -1 to disable)")
	removeOTP := fs.Bool("remove-otp", false, "remove the second factor from this item")
	var removeFields multiFlag
	fs.Var(&removeFields, "remove-field", "field to delete (repeatable)")
	rotateAfterUse := fs.Bool("rotate-after-use", false, "flag the item for rotation as soon as it is released")
	endToEnd := fs.Bool("end-to-end", false, "encrypt client-side so the server cannot read this item")
	var recipients multiFlag
	fs.Var(&recipients, "recipient", "agent name or fingerprint that may decrypt an --end-to-end item (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth admin item put --name NAME [--field k=v] [--otp-uri URI] [flags]")
		fmt.Fprintln(os.Stderr, "\nSecret values are encrypted to the session before they leave this process.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}

	secrets := &adminapi.ItemSecrets{Fields: map[string]string{}}
	for _, spec := range fields {
		k, v, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("--field %q must look like NAME=VALUE", spec)
		}
		val, err := readValueArg(v)
		if err != nil {
			return fmt.Errorf("--field %s: %w", k, err)
		}
		secrets.Fields[k] = val
	}
	if *otpSeed != "" {
		v, err := readValueArg(*otpSeed)
		if err != nil {
			return fmt.Errorf("--otp-seed: %w", err)
		}
		secrets.OTPSeed = strings.TrimSpace(v)
	}
	if *otpURI != "" {
		v, err := readValueArg(*otpURI)
		if err != nil {
			return fmt.Errorf("--otp-uri: %w", err)
		}
		secrets.OTPURI = strings.TrimSpace(v)
	}

	req := adminapi.PutItemRequest{
		Name: *name, Title: *title, Target: *target, Description: *desc,
		RemoveOTP: *removeOTP, RemoveFields: removeFields,
	}
	if *rotateAfterUse {
		req.RotateAfterUse = rotateAfterUse
	}
	if *otpDigits != 0 || *otpPeriod != 0 || *otpAlgorithm != "" || *otpMinInterval != 0 {
		req.OTP = &adminapi.OTPView{
			Digits: *otpDigits, Period: *otpPeriod, Algorithm: *otpAlgorithm,
			MinInterval: *otpMinInterval,
		}
	}

	c, err := g.client()
	if err != nil {
		return err
	}

	if *endToEnd {
		if len(recipients) == 0 {
			return errors.New("--end-to-end needs at least one --recipient, or nobody could ever read the item")
		}
		if secrets.OTPSeed != "" || secrets.OTPURI != "" {
			return errors.New("an end-to-end item cannot carry a second factor: the server would have to read the seed to mint codes")
		}
		if err := buildEndToEnd(ctx, c, &req, secrets, recipients); err != nil {
			return err
		}
		secrets = nil
	}

	if err := c.PutItem(ctx, req, secrets); err != nil {
		return err
	}
	fmt.Printf("wrote item %s\n", *name)
	return nil
}

// buildEndToEnd encrypts an item on this machine. The server receives
// ciphertext and a set of wrapped keys, and can decrypt none of it.
func buildEndToEnd(ctx context.Context, c interface {
	Admin(context.Context, string, string, any, any) error
}, req *adminapi.PutItemRequest, secrets *adminapi.ItemSecrets, recipients []string) error {
	var known adminapi.RecipientsResponse
	if err := c.Admin(ctx, http.MethodGet, "/v1/admin/recipients", nil, &known); err != nil {
		return err
	}
	var agents struct {
		Agents []store.Agent `json:"agents"`
	}
	if err := c.Admin(ctx, http.MethodGet, "/v1/admin/agents", nil, &agents); err != nil {
		return err
	}
	byName := map[string]string{}
	for _, a := range agents.Agents {
		byName[a.Name] = a.Fingerprint
	}

	dek, err := seal.RandomKey()
	if err != nil {
		return err
	}
	req.EndToEnd = true
	req.Ciphertexts = map[string][]byte{}
	// The AAD must match what the reader recomputes, so the server id has to be
	// the one this vault will store the item under.
	var health struct {
		ServerID string `json:"server_id"`
	}
	if err := c.Admin(ctx, http.MethodGet, "/v1/whoami", nil, &health); err != nil {
		return err
	}
	for name, value := range secrets.Fields {
		ct, err := seal.Encrypt(dek, []byte(value), store.FieldAAD(health.ServerID, req.Name, name))
		if err != nil {
			return err
		}
		req.Ciphertexts[name] = ct
	}
	for _, want := range recipients {
		fp, ok := byName[want]
		if !ok {
			fp = want
		}
		line, ok := known.Recipients[fp]
		if !ok {
			return fmt.Errorf("no enrolled identity matches recipient %q", want)
		}
		pub, _, err := sshid.ParseAuthorizedKey(line)
		if err != nil {
			return err
		}
		wrapped, err := seal.WrapToSSHKey(pub, dek)
		if err != nil {
			return fmt.Errorf("wrap key for %s: %w", want, err)
		}
		req.Recipients = append(req.Recipients, wrapped)
	}
	return nil
}

func adminItemList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin item list", flag.ExitOnError)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out struct {
		Items []adminapi.ItemView `json:"items"`
	}
	if err := c.Admin(ctx, http.MethodGet, "/v1/admin/items", nil, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ITEM\tTARGET\tFIELDS\t2FA\tMODE\tFLAGS")
	for _, it := range out.Items {
		mode := "server-side"
		if it.EndToEnd {
			mode = fmt.Sprintf("end-to-end (%d recipients)", len(it.Recipients))
		}
		otp := "-"
		if it.OTP != nil {
			otp = fmt.Sprintf("%s/%dd/%ds", it.OTP.Algorithm, it.OTP.Digits, it.OTP.Period)
			if it.OTP.HOTP {
				otp = fmt.Sprintf("HOTP %s/%dd", it.OTP.Algorithm, it.OTP.Digits)
			}
		}
		var flags []string
		if it.RotateAfterUse {
			flags = append(flags, "rotate-after-use")
		}
		if it.NeedsRotation {
			flags = append(flags, "NEEDS ROTATION")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", it.Name, orDash(it.Target),
			orDash(strings.Join(it.Fields, ",")), otp, mode, orDash(strings.Join(flags, ",")))
	}
	return tw.Flush()
}

func adminItemDelete(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin item delete", flag.ExitOnError)
	g.register(fs)
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("usage: ai-auth admin item delete <name>")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	if err := c.Admin(ctx, http.MethodPost, "/v1/admin/items/delete",
		adminapi.DeleteItemRequest{Name: operands[0]}, nil); err != nil {
		return err
	}
	fmt.Printf("deleted %s\n", operands[0])
	return nil
}

func adminItemRotated(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin item rotated", flag.ExitOnError)
	g.register(fs)
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("usage: ai-auth admin item rotated <name>")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	if err := c.PutItem(ctx, adminapi.PutItemRequest{Name: operands[0], ClearRotationFlag: true}, nil); err != nil {
		return err
	}
	fmt.Printf("cleared the rotation flag on %s\n", operands[0])
	return nil
}

func adminGrantAdd(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin grant add", flag.ExitOnError)
	g.register(fs)
	id := fs.String("id", "", "grant id (default: generated; reusing an id resets its budget)")
	agent := fs.String("agent", "", "agent name this grant is for")
	var items, fields, actions, targets multiFlag
	fs.Var(&items, "item", "item name or glob (repeatable)")
	fs.Var(&fields, "field", "field name or glob (repeatable; default: every releasable field)")
	fs.Var(&actions, "action", "read, totp or list (repeatable)")
	fs.Var(&targets, "allowed-target", "target this grant may be spent against (repeatable)")
	desc := fs.String("description", "", "why this grant exists")
	expiresIn := fs.Duration("expires-in", 0, "expire the grant after this long")
	maxUses := fs.Int("max-uses", 0, "total uses before the grant is exhausted")
	rateCount := fs.Int("rate-count", 0, "uses allowed per rate window")
	rateWindow := fs.Duration("rate-window", 0, "rate limit window")
	requireApproval := fs.Bool("require-approval", false, "hold every request until a human approves it")
	requireReason := fs.Bool("require-reason", false, "require a --reason on every request")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth admin grant add --agent NAME --item PATTERN --action read [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agent == "" || len(items) == 0 || len(actions) == 0 {
		return errors.New("--agent, at least one --item and at least one --action are required")
	}

	req := adminapi.PutGrantRequest{
		ID: *id, Agent: *agent, Items: items, Fields: fields, Actions: actions,
		Description: *desc, MaxUses: *maxUses, RequireApproval: *requireApproval,
		RequireReason: *requireReason, AllowedTargets: targets,
	}
	if *expiresIn > 0 {
		t := time.Now().UTC().Add(*expiresIn)
		req.NotAfter = &t
	}
	if *rateCount > 0 {
		if *rateWindow <= 0 {
			return errors.New("--rate-count needs --rate-window")
		}
		req.RateCount = *rateCount
		req.RateWindow = int(rateWindow.Seconds())
	}

	c, err := g.client()
	if err != nil {
		return err
	}
	var out store.Grant
	if err := c.Admin(ctx, http.MethodPost, "/v1/admin/grants", req, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	fmt.Printf("created grant %s: %s may %s on %s\n", out.ID, out.Agent,
		joinActions(out.Actions), strings.Join(out.Items, ","))
	return nil
}

func adminGrantList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin grant list", flag.ExitOnError)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out struct {
		Grants []adminapi.GrantView `json:"grants"`
	}
	if err := c.Admin(ctx, http.MethodGet, "/v1/admin/grants", nil, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAGENT\tITEMS\tACTIONS\tUSES\tCONSTRAINTS\tSTATE")
	for _, gv := range out.Grants {
		var constraints []string
		if gv.RequireApproval {
			constraints = append(constraints, "approval")
		}
		if gv.RequireReason {
			constraints = append(constraints, "reason")
		}
		if gv.Rate != nil {
			constraints = append(constraints, fmt.Sprintf("%d/%ds", gv.Rate.Count, gv.Rate.Window))
		}
		if gv.NotAfter != nil {
			constraints = append(constraints, "until "+gv.NotAfter.Format(time.RFC3339))
		}
		if len(gv.AllowedTargets) > 0 {
			constraints = append(constraints, "targets="+strings.Join(gv.AllowedTargets, "|"))
		}
		state := "active"
		if gv.Revoked {
			state = "revoked"
		} else if gv.NotAfter != nil && time.Now().After(*gv.NotAfter) {
			state = "expired"
		}
		uses := fmt.Sprint(gv.TotalUses)
		if gv.MaxUses > 0 {
			uses = fmt.Sprintf("%d/%d", gv.TotalUses, gv.MaxUses)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", gv.ID, gv.Agent,
			strings.Join(gv.Items, ","), joinActions(gv.Actions), uses,
			orDash(strings.Join(constraints, ",")), state)
	}
	return tw.Flush()
}

func adminGrantRevoke(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin grant revoke", flag.ExitOnError)
	g.register(fs)
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return errors.New("usage: ai-auth admin grant revoke <grant-id>")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	if err := c.Admin(ctx, http.MethodPost, "/v1/admin/grants/revoke",
		adminapi.RevokeGrantRequest{ID: operands[0]}, nil); err != nil {
		return err
	}
	fmt.Printf("revoked %s\n", operands[0])
	return nil
}

func adminApprovalList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin approval list", flag.ExitOnError)
	g.register(fs)
	pending := fs.Bool("pending", true, "show only requests still awaiting a decision")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	path := "/v1/admin/approvals"
	if *pending {
		path += "?status=pending"
	}
	var out struct {
		Approvals []store.Approval `json:"approvals"`
	}
	if err := c.Admin(ctx, http.MethodGet, path, nil, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	if len(out.Approvals) == 0 {
		fmt.Println("Nothing is waiting for a decision.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAGENT\tACTION\tITEM\tFIELDS\tTARGET\tREASON\tEXPIRES")
	for _, ap := range out.Approvals {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ap.ID, ap.Agent, ap.Action, ap.Item,
			orDash(strings.Join(ap.Fields, ",")), orDash(ap.Target), orDash(ap.Reason),
			ap.ExpiresAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

func adminApprovalDecide(ctx context.Context, args []string, approve bool) error {
	var g globals
	verb := "deny"
	if approve {
		verb = "approve"
	}
	fs := flag.NewFlagSet("admin approval "+verb, flag.ExitOnError)
	g.register(fs)
	note := fs.String("note", "", "note recorded with the decision")
	extend := fs.Duration("valid-for", 0, "how long the approval stays spendable")
	operands, err := parseWithOperands(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return fmt.Errorf("usage: ai-auth admin approval %s <approval-id>", verb)
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	req := adminapi.DecideApprovalRequest{ID: operands[0], Approve: approve, Note: *note}
	if *extend > 0 {
		req.ExtendSeconds = int(extend.Seconds())
	}
	var out store.Approval
	if err := c.Admin(ctx, http.MethodPost, "/v1/admin/approvals/decide", req, &out); err != nil {
		return err
	}
	fmt.Printf("%s is now %s (spendable once, until %s)\n", out.ID, out.Status, out.ExpiresAt.Format(time.RFC3339))
	return nil
}

func adminLeaseList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("admin lease list", flag.ExitOnError)
	g.register(fs)
	activeOnly := fs.Bool("active", true, "show only leases still outstanding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out struct {
		Leases []store.Lease `json:"leases"`
	}
	if err := c.Admin(ctx, http.MethodGet, "/v1/admin/leases", nil, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LEASE\tAGENT\tITEM\tFIELDS\tSTATUS\tISSUED\tEXPIRES")
	for _, l := range out.Leases {
		if *activeOnly && l.Status != store.LeaseActive {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", l.ID, l.Agent, l.Item,
			orDash(strings.Join(l.Fields, ",")), l.Status,
			l.IssuedAt.Format(time.RFC3339), l.ExpiresAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

func cmdAudit(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ai-auth audit tail|verify")
	}
	switch args[0] {
	case "tail":
		return auditTail(ctx, args[1:])
	case "verify":
		return auditVerify(args[1:])
	default:
		return fmt.Errorf("unknown audit command %q", args[0])
	}
}

func auditTail(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("audit tail", flag.ExitOnError)
	g.register(fs)
	limit := fs.Int("n", 25, "number of records to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	var out struct {
		Records    []audit.Record `json:"records"`
		ChainValid bool           `json:"chain_valid"`
		ChainError string         `json:"chain_error"`
	}
	if err := c.Admin(ctx, http.MethodGet, fmt.Sprintf("/v1/admin/audit?limit=%d", *limit), nil, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(out)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tACTION\tITEM\tDECISION\tDETAIL")
	for _, r := range out.Records {
		detail := r.Detail
		if detail == "" && r.Reason != "" {
			detail = "reason: " + r.Reason
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Seq, r.Time.Format(time.RFC3339),
			r.Actor, r.Action, orDash(r.Item), r.Decision, orDash(detail))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if !out.ChainValid {
		return fmt.Errorf("the audit chain does not verify: %s", out.ChainError)
	}
	fmt.Fprintln(os.Stderr, "\nhash chain verified")
	return nil
}

// auditVerify reads the log file directly. Verifying through the server would
// be pointless if the server is the thing you are checking up on.
func auditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	dir := fs.String("dir", envOr("AI_AUTH_DIR", "./ai-auth-data"), "directory holding the audit log")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ai-auth audit verify [--dir DIR]")
		fmt.Fprintln(os.Stderr, "\nReads the log file directly and checks the hash chain end to end.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, auditPath := dataPaths(*dir)
	records, err := audit.VerifyFile(auditPath)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("The audit log is empty.")
		return nil
	}
	counts := map[string]int{}
	for _, r := range records {
		counts[string(r.Decision)]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("verified %d records, %s to %s\n", len(records),
		records[0].Time.Format(time.RFC3339), records[len(records)-1].Time.Format(time.RFC3339))
	for _, k := range keys {
		fmt.Printf("  %-8s %d\n", k, counts[k])
	}
	fmt.Printf("head hash: %s\n", records[len(records)-1].Hash)
	return nil
}

func joinActions(actions []store.Action) string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = string(a)
	}
	return strings.Join(out, ",")
}

// readValueArg resolves a flag value: "@-" reads stdin, "@path" reads a file,
// anything else is literal. Reading from stdin or a file keeps secrets out of
// the process table and the shell history.
func readValueArg(v string) (string, error) {
	switch {
	case v == "@-" || v == "-":
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return strings.TrimRight(string(raw), "\n"), nil
	case strings.HasPrefix(v, "@"):
		raw, err := os.ReadFile(expandHome(v[1:]))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", v[1:], err)
		}
		return strings.TrimRight(string(raw), "\n"), nil
	default:
		return v, nil
	}
}
