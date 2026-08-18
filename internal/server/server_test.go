package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/linktoming/ai-auth/internal/adminapi"
	"github.com/linktoming/ai-auth/internal/api"
	"github.com/linktoming/ai-auth/internal/audit"
	"github.com/linktoming/ai-auth/internal/client"
	"github.com/linktoming/ai-auth/internal/otp"
	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/server"
	"github.com/linktoming/ai-auth/internal/sshid"
	"github.com/linktoming/ai-auth/internal/store"
)

// testSeed is the RFC 4226 secret, so expected codes can be computed here too.
const testSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32("12345678901234567890")

type harness struct {
	t         *testing.T
	httpSrv   *httptest.Server
	vault     *store.Vault
	auditPath string
	now       time.Time
}

type identity struct {
	signer ssh.Signer
	raw    any
	pubKey string
	fp     string
}

func newIdentity(t *testing.T, name string) identity {
	t.Helper()
	privPEM, pubLine, err := sshid.GenerateEd25519(name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ssh.ParseRawPrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := sshid.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	return identity{signer: signer, raw: raw, pubKey: pubLine, fp: sshid.Fingerprint(pub)}
}

func newHarness(t *testing.T, operator identity) *harness {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.json")
	auditPath := filepath.Join(dir, "audit.log")

	rootKey, err := seal.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := store.Create(vaultPath, "test-server", rootKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := sshid.ParseAuthorizedKey(operator.pubKey)
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	v.Data().Agents[operator.fp] = &store.Agent{
		Name: "ops", Fingerprint: operator.fp, PublicKey: sshid.MarshalAuthorizedKey(pub),
		Role: store.RoleOperator, CreatedAt: time.Now().UTC(),
	}
	if err := v.SaveLocked(); err != nil {
		t.Fatal(err)
	}
	v.Unlock()

	log, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	h := &harness{t: t, vault: v, auditPath: auditPath, now: time.Now().UTC()}
	srv, err := server.New(server.Config{
		Vault: v, Audit: log, AuditPath: auditPath,
		Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.httpSrv = httptest.NewServer(srv)
	t.Cleanup(h.httpSrv.Close)
	return h
}

func (h *harness) client(id identity) *client.Client {
	h.t.Helper()
	c, err := client.New(client.Config{
		BaseURL: h.httpSrv.URL, Signer: id.signer, Identity: id.raw,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

func (h *harness) enrol(ops *client.Client, name string, id identity, role store.Role) {
	h.t.Helper()
	if err := ops.Admin(context.Background(), http.MethodPost, "/v1/admin/agents",
		adminapi.PutAgentRequest{Name: name, PublicKey: id.pubKey, Role: string(role)}, nil); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) grant(ops *client.Client, req adminapi.PutGrantRequest) store.Grant {
	h.t.Helper()
	var out store.Grant
	if err := ops.Admin(context.Background(), http.MethodPost, "/v1/admin/grants", req, &out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// setup builds the common fixture: an operator, a bot, one login item with a
// second factor, and a grant letting the bot read and mint.
func setup(t *testing.T) (*harness, identity, identity, *client.Client, *client.Client) {
	t.Helper()
	ops := newIdentity(t, "ops")
	bot := newIdentity(t, "bot")
	h := newHarness(t, ops)
	opsClient := h.client(ops)
	h.enrol(opsClient, "deploy-bot", bot, store.RoleAgent)

	if err := opsClient.PutItem(context.Background(), adminapi.PutItemRequest{
		Name: "prod/console", Title: "Prod console", Target: "console.example.com",
	}, &adminapi.ItemSecrets{
		Fields:  map[string]string{"username": "svc-deploy", "password": "correct-horse"},
		OTPSeed: testSeed,
	}); err != nil {
		t.Fatal(err)
	}
	h.grant(opsClient, adminapi.PutGrantRequest{
		ID: "gr_main", Agent: "deploy-bot", Items: []string{"prod/*"},
		Actions: []string{"read", "totp", "list"},
	})
	return h, ops, bot, opsClient, h.client(bot)
}

func TestReadAndMintHappyPath(t *testing.T) {
	h, _, _, _, bot := setup(t)
	ctx := context.Background()

	values, meta, err := bot.Read(ctx, api.ReadRequest{Item: "prod/console", Reason: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if values["username"] != "svc-deploy" || values["password"] != "correct-horse" {
		t.Fatalf("unexpected values: %v", values)
	}
	if meta.LeaseID == "" || meta.ExpiresAt.Before(h.now) {
		t.Fatal("expected a live lease")
	}

	code, codeMeta, err := bot.Code(ctx, api.CodeRequest{Item: "prod/console", Reason: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := otp.DecodeSecret(testSeed)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &otp.Config{}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	want, _, err := otp.TOTP(raw, h.now, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if code != want {
		t.Fatalf("code = %s, want %s", code, want)
	}
	if codeMeta.ValidForSeconds <= 0 || codeMeta.ValidForSeconds > 30 {
		t.Fatalf("valid_for = %d", codeMeta.ValidForSeconds)
	}
}

// The headline property: no agent-facing path returns the seed.
func TestSeedIsNeverReleased(t *testing.T) {
	_, _, _, _, bot := setup(t)
	ctx := context.Background()

	if _, _, err := bot.Read(ctx, api.ReadRequest{
		Item: "prod/console", Fields: []string{store.SeedField},
	}); err == nil {
		t.Fatal("reading the seed field must fail")
	}

	// Nor via a wildcard read that asks for everything.
	values, _, err := bot.Read(ctx, api.ReadRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := values[store.SeedField]; leaked {
		t.Fatal("an unqualified read leaked the seed")
	}

	// Nor is it advertised in the listing.
	list, err := bot.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range list.Items {
		for _, f := range item.Fields {
			if f == store.SeedField {
				t.Fatal("the seed is advertised in the item listing")
			}
		}
	}

}

// Even a grant that explicitly names the seed field cannot pry it loose: the
// non-releasable flag is enforced below the policy layer, not by it.
func TestGrantNamingTheSeedStillCannotReleaseIt(t *testing.T) {
	h, _, _, ops, bot := setup(t)
	h.grant(ops, adminapi.PutGrantRequest{
		ID: "gr_seed", Agent: "deploy-bot", Items: []string{"prod/*"},
		Fields: []string{store.SeedField, "*"}, Actions: []string{"read"},
	})
	if _, _, err := bot.Read(context.Background(), api.ReadRequest{
		Item: "prod/console", Fields: []string{store.SeedField},
	}); err == nil {
		t.Fatal("a grant naming the seed field must still not release it")
	}
	values, _, err := bot.Read(context.Background(), api.ReadRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := values[store.SeedField]; leaked {
		t.Fatal("a wildcard field grant leaked the seed")
	}
}

func TestUnenrolledKeyIsRejected(t *testing.T) {
	h, _, _, _, _ := setup(t)
	stranger := newIdentity(t, "stranger")
	c := h.client(stranger)
	if err := c.Connect(context.Background()); err == nil {
		t.Fatal("an unenrolled key must not authenticate")
	}
}

// A signature is bound to one challenge; replaying it must fail.
func TestHandshakeSignatureCannotBeReplayed(t *testing.T) {
	h, _, bot, _, _ := setup(t)
	ctx := context.Background()
	c := h.client(bot)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	// Drive the raw protocol so we can reuse a captured signature.
	eph, err := seal.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	var init api.HandshakeInitResponse
	post(t, h, "/v1/handshake/init", "", api.HandshakeInitRequest{
		Fingerprint: bot.fp, ClientEphemeral: eph.Pub, ClientNonce: eph.Nonce,
	}, &init, http.StatusOK)

	transcript := seal.Transcript(init.ServerID, init.SessionID, bot.fp,
		eph.Pub, eph.Nonce, init.ServerEphemeral, init.ServerNonce)
	sig, err := sshid.Sign(bot.signer, transcript)
	if err != nil {
		t.Fatal(err)
	}
	complete := api.HandshakeCompleteRequest{
		SessionID: init.SessionID, SignatureFormat: sig.Format, SignatureBlob: sig.Blob,
	}
	var done api.HandshakeCompleteResponse
	post(t, h, "/v1/handshake/complete", "", complete, &done, http.StatusOK)

	// The same signature, sent again, must be refused: the challenge is gone.
	post(t, h, "/v1/handshake/complete", "", complete, nil, http.StatusUnauthorized)
}

func TestExpiredHandshakeIsRejected(t *testing.T) {
	h, _, bot, _, _ := setup(t)
	eph, err := seal.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	var init api.HandshakeInitResponse
	post(t, h, "/v1/handshake/init", "", api.HandshakeInitRequest{
		Fingerprint: bot.fp, ClientEphemeral: eph.Pub, ClientNonce: eph.Nonce,
	}, &init, http.StatusOK)

	h.now = h.now.Add(time.Minute)

	transcript := seal.Transcript(init.ServerID, init.SessionID, bot.fp,
		eph.Pub, eph.Nonce, init.ServerEphemeral, init.ServerNonce)
	sig, err := sshid.Sign(bot.signer, transcript)
	if err != nil {
		t.Fatal(err)
	}
	post(t, h, "/v1/handshake/complete", "", api.HandshakeCompleteRequest{
		SessionID: init.SessionID, SignatureFormat: sig.Format, SignatureBlob: sig.Blob,
	}, nil, http.StatusUnauthorized)
}

func TestGrantScoping(t *testing.T) {
	h, _, _, ops, _ := setup(t)
	ctx := context.Background()
	narrow := newIdentity(t, "narrow")
	h.enrol(ops, "reader", narrow, store.RoleAgent)
	h.grant(ops, adminapi.PutGrantRequest{
		ID: "gr_narrow", Agent: "reader", Items: []string{"prod/console"},
		Fields: []string{"username"}, Actions: []string{"read"},
	})
	c := h.client(narrow)

	values, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values["username"] != "svc-deploy" {
		t.Fatalf("an unqualified read should return only the granted field, got %v", values)
	}
	if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console", Fields: []string{"password"}}); err == nil {
		t.Fatal("reading an ungranted field must fail")
	}
	if _, _, err := c.Code(ctx, api.CodeRequest{Item: "prod/console"}); err == nil {
		t.Fatal("a read-only grant must not mint codes")
	}
	// A read grant must not be upgradable to a code by asking for a "login".
	if _, _, err := c.Login(ctx, api.LoginRequest{Item: "prod/console", WithCode: true}); err == nil {
		t.Fatal("login+code must not bypass the totp action")
	}
}

// An agent with no grant must not be able to tell a real item from a fictional
// one, or the API becomes a way to enumerate the vault.
func TestUngrantedItemsAreIndistinguishable(t *testing.T) {
	h, _, _, ops, _ := setup(t)
	ctx := context.Background()
	nobody := newIdentity(t, "nobody")
	h.enrol(ops, "nobody", nobody, store.RoleAgent)
	c := h.client(nobody)

	_, _, realErr := c.Read(ctx, api.ReadRequest{Item: "prod/console"})
	_, _, fakeErr := c.Read(ctx, api.ReadRequest{Item: "prod/does-not-exist"})
	if realErr == nil || fakeErr == nil {
		t.Fatal("both reads must fail")
	}
	var realAPI, fakeAPI *api.Error
	if !errors.As(realErr, &realAPI) || !errors.As(fakeErr, &fakeAPI) {
		t.Fatalf("expected API errors, got %v / %v", realErr, fakeErr)
	}
	if realAPI.Code != fakeAPI.Code {
		t.Fatalf("existing and missing items are distinguishable: %q vs %q", realAPI.Code, fakeAPI.Code)
	}
}

func TestRateLimitAndMaxUses(t *testing.T) {
	h, _, _, ops, _ := setup(t)
	ctx := context.Background()
	limited := newIdentity(t, "limited")
	h.enrol(ops, "limited", limited, store.RoleAgent)
	h.grant(ops, adminapi.PutGrantRequest{
		ID: "gr_limited", Agent: "limited", Items: []string{"prod/console"},
		Actions: []string{"read"}, MaxUses: 2,
	})
	c := h.client(limited)

	for i := range 2 {
		if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console"}); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console"}); err == nil {
		t.Fatal("the third read must exhaust the grant")
	}
}

func TestRequireReason(t *testing.T) {
	h, _, _, ops, _ := setup(t)
	ctx := context.Background()
	id := newIdentity(t, "needsreason")
	h.enrol(ops, "needsreason", id, store.RoleAgent)
	h.grant(ops, adminapi.PutGrantRequest{
		ID: "gr_reason", Agent: "needsreason", Items: []string{"prod/console"},
		Actions: []string{"read"}, RequireReason: true,
	})
	c := h.client(id)

	if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console"}); err == nil {
		t.Fatal("a grant requiring a reason must reject a request without one")
	}
	if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console", Reason: "rotating the deploy key"}); err != nil {
		t.Fatal(err)
	}
}

func TestTargetBinding(t *testing.T) {
	h, _, _, ops, _ := setup(t)
	ctx := context.Background()
	id := newIdentity(t, "staging")
	h.enrol(ops, "staging-bot", id, store.RoleAgent)
	h.grant(ops, adminapi.PutGrantRequest{
		ID: "gr_target", Agent: "staging-bot", Items: []string{"prod/console"},
		Actions: []string{"read"}, AllowedTargets: []string{"staging.example.com"},
	})
	c := h.client(id)

	if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console", Target: "console.example.com"}); err == nil {
		t.Fatal("a target outside the allow list must be refused")
	}
	if _, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console", Target: "staging.example.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalFlow(t *testing.T) {
	h, _, _, ops, _ := setup(t)
	ctx := context.Background()
	id := newIdentity(t, "gated")
	h.enrol(ops, "gated-bot", id, store.RoleAgent)
	h.grant(ops, adminapi.PutGrantRequest{
		ID: "gr_gated", Agent: "gated-bot", Items: []string{"prod/console"},
		Actions: []string{"read"}, RequireApproval: true,
	})
	c := h.client(id)

	_, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console", Reason: "incident 42"})
	var pending *client.ErrApprovalPending
	if !errors.As(err, &pending) {
		t.Fatalf("expected an approval-pending error, got %v", err)
	}

	// While pending, the approval id alone must not unlock the read.
	if _, _, err := c.Read(ctx, api.ReadRequest{
		Item: "prod/console", Reason: "incident 42", ApprovalID: pending.ApprovalID,
	}); !errors.As(err, &pending) {
		t.Fatalf("an undecided approval must not release anything, got %v", err)
	}

	var decided store.Approval
	if err := ops.Admin(ctx, http.MethodPost, "/v1/admin/approvals/decide",
		adminapi.DecideApprovalRequest{ID: pending.ApprovalID, Approve: true}, &decided); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Read(ctx, api.ReadRequest{
		Item: "prod/console", Reason: "incident 42", ApprovalID: pending.ApprovalID,
	}); err != nil {
		t.Fatal(err)
	}
	// Single use: the same approval must not authorise a second release.
	if _, _, err := c.Read(ctx, api.ReadRequest{
		Item: "prod/console", Reason: "incident 42", ApprovalID: pending.ApprovalID,
	}); err == nil {
		t.Fatal("an approval must be spendable only once")
	}
}

func TestDisablingAnAgentKillsLiveSessions(t *testing.T) {
	_, _, _, ops, bot := setup(t)
	ctx := context.Background()
	if _, _, err := bot.Read(ctx, api.ReadRequest{Item: "prod/console"}); err != nil {
		t.Fatal(err)
	}
	if err := ops.Admin(ctx, http.MethodPost, "/v1/admin/agents/disable",
		adminapi.DisableAgentRequest{Fingerprint: "deploy-bot"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bot.Read(ctx, api.ReadRequest{Item: "prod/console"}); err == nil {
		t.Fatal("a disabled agent must lose access immediately, not at token expiry")
	}
}

func TestMintThrottleAndStepReuse(t *testing.T) {
	h, _, _, _, bot := setup(t)
	ctx := context.Background()

	first, _, err := bot.Code(ctx, api.CodeRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	// Inside the same time step, the same code comes back rather than burning
	// quota or handing out a second distinct code.
	second, meta, err := bot.Code(ctx, api.CodeRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !meta.Reused {
		t.Fatalf("expected the same code inside one step, got %s then %s (reused=%v)", first, second, meta.Reused)
	}

	// A new time step yields a genuinely new code. The default 25s throttle is
	// shorter than the 30s step, so it does not interfere here.
	h.now = h.now.Add(31 * time.Second)
	third, _, err := bot.Code(ctx, api.CodeRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("a new time step should produce a new code")
	}
}

// A throttle longer than the time step is how an operator slows down a
// compromised agent that is trying to harvest codes.
func TestMintThrottleBlocksHarvesting(t *testing.T) {
	h, _, _, ops, bot := setup(t)
	ctx := context.Background()

	if err := ops.PutItem(ctx, adminapi.PutItemRequest{
		Name: "prod/slow", OTP: &adminapi.OTPView{MinInterval: 300},
	}, &adminapi.ItemSecrets{OTPSeed: testSeed}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bot.Code(ctx, api.CodeRequest{Item: "prod/slow"}); err != nil {
		t.Fatal(err)
	}

	h.now = h.now.Add(31 * time.Second)
	_, _, err := bot.Code(ctx, api.CodeRequest{Item: "prod/slow"})
	if err == nil {
		t.Fatal("minting again inside the throttle window must be refused")
	}
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "mint_too_soon" {
		t.Fatalf("expected a mint_too_soon error, got %v", err)
	}

	h.now = h.now.Add(5 * time.Minute)
	if _, _, err := bot.Code(ctx, api.CodeRequest{Item: "prod/slow"}); err != nil {
		t.Fatalf("minting after the throttle window should work: %v", err)
	}
}

func TestOperatorRoleIsRequiredForAdmin(t *testing.T) {
	_, _, _, _, bot := setup(t)
	err := bot.Admin(context.Background(), http.MethodGet, "/v1/admin/agents", nil, nil)
	if err == nil {
		t.Fatal("an agent identity must not reach the admin API")
	}
	if !strings.Contains(err.Error(), "operator") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEndToEndItemIsOpaqueToTheServer(t *testing.T) {
	h, _, bot, ops, botClient := setup(t)
	ctx := context.Background()

	dek, err := seal.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := sshid.ParseAuthorizedKey(bot.pubKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := seal.WrapToSSHKey(pub, dek)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := seal.Encrypt(dek, []byte("only-the-bot-knows"),
		store.FieldAAD("test-server", "prod/e2e", "password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.Admin(ctx, http.MethodPost, "/v1/admin/items", adminapi.PutItemRequest{
		Name: "prod/e2e", EndToEnd: true,
		Ciphertexts: map[string][]byte{"password": ct},
		Recipients:  []*seal.WrappedKey{wrapped},
	}, nil); err != nil {
		t.Fatal(err)
	}

	values, meta, err := botClient.Read(ctx, api.ReadRequest{Item: "prod/e2e"})
	if err != nil {
		t.Fatal(err)
	}
	if !meta.EndToEnd || values["password"] != "only-the-bot-knows" {
		t.Fatalf("end-to-end read failed: %+v %v", meta, values)
	}

	// The server holds no key for this item, even with the vault unsealed.
	h.vault.RLock()
	item := h.vault.Data().Items["prod/e2e"]
	h.vault.RUnlock()
	if len(item.WrappedDEK) != 0 {
		t.Fatal("the server retained a data key for an end-to-end item")
	}
	if _, err := h.vault.ReadField(item, "password"); err == nil {
		t.Fatal("the server must not be able to read an end-to-end field")
	}
}

func TestAuditChainRecordsReleasesAndNeverTheCode(t *testing.T) {
	h, _, _, _, bot := setup(t)
	ctx := context.Background()
	code, _, err := bot.Code(ctx, api.CodeRequest{Item: "prod/console", Reason: "sign in"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bot.Read(ctx, api.ReadRequest{Item: "prod/console", Reason: "sign in"}); err != nil {
		t.Fatal(err)
	}

	records, err := audit.VerifyFile(h.auditPath)
	if err != nil {
		t.Fatalf("audit chain does not verify: %v", err)
	}
	var sawCode, sawRead bool
	for _, r := range records {
		for _, v := range append([]string{r.Detail, r.Reason}, mapValues(r.Meta)...) {
			if strings.Contains(v, code) {
				t.Fatal("the one-time code was written to the audit log")
			}
		}
		if r.Action == "totp" && r.Decision == audit.Allow {
			sawCode = true
			if r.Meta["code_digest"] == "" {
				t.Fatal("a mint was recorded without a code digest")
			}
		}
		if r.Action == "read" && r.Decision == audit.Allow && r.Reason == "sign in" {
			sawRead = true
		}
	}
	if !sawCode || !sawRead {
		t.Fatalf("missing audit entries (code=%v read=%v)", sawCode, sawRead)
	}

	// Tampering with any record must break the chain.
	records[0].Actor = "someone-else"
	if err := audit.Verify(records); err == nil {
		t.Fatal("an edited record must fail verification")
	}
}

func TestSealedPayloadIsNotReadableFromTheWire(t *testing.T) {
	h, _, bot, _, _ := setup(t)
	ctx := context.Background()
	c := h.client(bot)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	values, meta, err := c.Read(ctx, api.ReadRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if values["password"] != "correct-horse" {
		t.Fatal("unexpected value")
	}
	// The response body carries ciphertext only; the secret is not recoverable
	// by anything sitting between client and server.
	if strings.Contains(string(meta.Sealed), "correct-horse") {
		t.Fatal("the sealed blob contains plaintext")
	}
	// A different session's keys must not open it.
	other, err := seal.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := other.Derive(other.Pub, other.Nonce, other.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.OpenFromServer(meta.Sealed, api.PayloadAAD("x", "prod/console", "read")); err == nil {
		t.Fatal("a foreign session opened the sealed payload")
	}
}

func TestLeaseLifecycle(t *testing.T) {
	_, _, _, ops, bot := setup(t)
	ctx := context.Background()
	_, meta, err := bot.Read(ctx, api.ReadRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	var before struct {
		Leases []store.Lease `json:"leases"`
	}
	if err := ops.Admin(ctx, http.MethodGet, "/v1/admin/leases", nil, &before); err != nil {
		t.Fatal(err)
	}
	if !hasActiveLease(before.Leases, meta.LeaseID) {
		t.Fatal("expected the lease to show as active")
	}
	if err := bot.Release(ctx, meta.LeaseID); err != nil {
		t.Fatal(err)
	}
	var after struct {
		Leases []store.Lease `json:"leases"`
	}
	if err := ops.Admin(ctx, http.MethodGet, "/v1/admin/leases", nil, &after); err != nil {
		t.Fatal(err)
	}
	if hasActiveLease(after.Leases, meta.LeaseID) {
		t.Fatal("the lease should no longer be active after release")
	}
}

func TestVaultSurvivesRestart(t *testing.T) {
	h, _, bot, _, _ := setup(t)
	ctx := context.Background()

	// Reopen the vault from disk with a fresh server, as a restart would.
	reopened, err := store.Load(filepath.Join(filepath.Dir(h.auditPath), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	h.vault.RLock()
	root := h.vault.RootKey()
	h.vault.RUnlock()
	if err := reopened.Unseal(root); err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	srv, err := server.New(server.Config{Vault: reopened, Audit: log, AuditPath: h.auditPath})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	c, err := client.New(client.Config{BaseURL: ts.URL, Signer: bot.signer})
	if err != nil {
		t.Fatal(err)
	}
	values, _, err := c.Read(ctx, api.ReadRequest{Item: "prod/console"})
	if err != nil {
		t.Fatal(err)
	}
	if values["password"] != "correct-horse" {
		t.Fatalf("value did not survive a restart: %v", values)
	}
}

func hasActiveLease(leases []store.Lease, id string) bool {
	for _, l := range leases {
		if l.ID == id {
			return l.Status == store.LeaseActive
		}
	}
	return false
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
