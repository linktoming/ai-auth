// Package client speaks the ai-auth protocol.
//
// It is what an AI agent links against (or shells out to). The important
// property is that it only ever needs the ability to *sign*: with ssh-agent
// holding the key, the agent process never has key material in its own memory.
package client

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/linktoming/ai-auth/internal/adminapi"
	"github.com/linktoming/ai-auth/internal/api"
	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/sshid"
	"github.com/linktoming/ai-auth/internal/store"
)

// Config configures a Client.
type Config struct {
	// BaseURL is the vault address, e.g. https://ai-auth.internal:8443
	BaseURL string
	// Signer proves the agent's identity. It is typically backed by ssh-agent.
	Signer ssh.Signer
	// Identity is the raw private key, needed only to open end-to-end items.
	// Leave it nil when using ssh-agent and no end-to-end items.
	Identity   crypto.PrivateKey
	HTTPClient *http.Client
	// UnixSocket, when set, makes the client dial a local socket instead of TCP.
	UnixSocket string
}

// Client is a connected ai-auth client. It is safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client

	mu        sync.Mutex
	token     string
	sessionID string
	keys      *seal.Session
	expiresAt time.Time
	agent     string
	role      string
	serverID  string
}

// New builds a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("client: a base URL is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("client: an ssh signer is required")
	}
	if _, err := url.Parse(cfg.BaseURL); err != nil {
		return nil, fmt.Errorf("client: bad base URL: %w", err)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{cfg: cfg, http: hc}, nil
}

// Fingerprint returns the identity this client authenticates as.
func (c *Client) Fingerprint() string { return sshid.Fingerprint(c.cfg.Signer.PublicKey()) }

// AgentName returns the enrolled name, available after the first call.
func (c *Client) AgentName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agent
}

// Connect performs the handshake, replacing any existing session.
func (c *Client) Connect(ctx context.Context) error {
	eph, err := seal.NewEphemeral()
	if err != nil {
		return err
	}
	fp := c.Fingerprint()

	var init api.HandshakeInitResponse
	if err := c.call(ctx, http.MethodPost, "/v1/handshake/init", "", api.HandshakeInitRequest{
		Fingerprint:     fp,
		ClientEphemeral: eph.Pub,
		ClientNonce:     eph.Nonce,
	}, &init); err != nil {
		return err
	}

	// Sign the full transcript. Because it commits to both ephemeral keys, a
	// party in the middle cannot swap in its own and ride the session.
	transcript := seal.Transcript(init.ServerID, init.SessionID, fp,
		eph.Pub, eph.Nonce, init.ServerEphemeral, init.ServerNonce)
	sig, err := sshid.Sign(c.cfg.Signer, transcript)
	if err != nil {
		return fmt.Errorf("client: sign challenge: %w", err)
	}

	var done api.HandshakeCompleteResponse
	if err := c.call(ctx, http.MethodPost, "/v1/handshake/complete", "", api.HandshakeCompleteRequest{
		SessionID:       init.SessionID,
		SignatureFormat: sig.Format,
		SignatureBlob:   sig.Blob,
	}, &done); err != nil {
		return err
	}
	keys, err := eph.Derive(init.ServerEphemeral, eph.Nonce, init.ServerNonce)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.sessionID, c.keys = done.Token, init.SessionID, keys
	c.expiresAt, c.agent, c.role, c.serverID = done.ExpiresAt, done.Agent, done.Role, init.ServerID
	return nil
}

// ensure returns a live session, handshaking if needed. Sessions are short by
// design, so this is the common path rather than an error case.
func (c *Client) ensure(ctx context.Context) (string, *seal.Session, string, error) {
	c.mu.Lock()
	token, keys, sid := c.token, c.keys, c.sessionID
	fresh := token != "" && time.Now().UTC().Before(c.expiresAt.Add(-5*time.Second))
	c.mu.Unlock()
	if fresh {
		return token, keys, sid, nil
	}
	if err := c.Connect(ctx); err != nil {
		return "", nil, "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token, c.keys, c.sessionID, nil
}

// do performs an authenticated request, re-handshaking once if the server
// rejects the session. Our local idea of when a token expires can be wrong --
// clock skew, a server restart, a session dropped by an operator -- so the
// server's answer is the authority, not our timer.
//
// It returns the session that was in force for the successful attempt, which is
// what the caller needs in order to open a sealed payload.
func (c *Client) do(ctx context.Context, method, path string, body, out any) (*seal.Session, string, error) {
	token, keys, sid, err := c.ensure(ctx)
	if err != nil {
		return nil, "", err
	}
	err = c.call(ctx, method, path, token, body, out)
	if err == nil || !isUnauthenticated(err) {
		return keys, sid, err
	}
	if reconnectErr := c.Connect(ctx); reconnectErr != nil {
		// Report the original rejection: it explains what actually went wrong.
		return nil, "", err
	}
	c.mu.Lock()
	token, keys, sid = c.token, c.keys, c.sessionID
	c.mu.Unlock()
	return keys, sid, c.call(ctx, method, path, token, body, out)
}

func isUnauthenticated(err error) bool {
	var apiErr *api.Error
	return errors.As(err, &apiErr) && apiErr.Code == "unauthenticated"
}

// WhoAmI reports the caller's identity and what it may reach.
func (c *Client) WhoAmI(ctx context.Context) (*api.WhoAmIResponse, error) {
	var out api.WhoAmIResponse
	_, _, err := c.do(ctx, http.MethodGet, "/v1/whoami", nil, &out)
	return &out, err
}

// List enumerates the items the agent may see.
func (c *Client) List(ctx context.Context) (*api.ListResponse, error) {
	var out api.ListResponse
	_, _, err := c.do(ctx, http.MethodGet, "/v1/items", nil, &out)
	return &out, err
}

// ErrApprovalPending is returned when a human still has to say yes. The
// approval id is carried on the error so the caller can retry with it.
type ErrApprovalPending struct {
	ApprovalID string
	Status     string
	ExpiresAt  time.Time
	Message    string
}

func (e *ErrApprovalPending) Error() string {
	return fmt.Sprintf("awaiting human approval (%s, id %s): %s", e.Status, e.ApprovalID, e.Message)
}

// Read fetches field values, decrypting them locally.
func (c *Client) Read(ctx context.Context, req api.ReadRequest) (map[string]string, *api.ReadResponse, error) {
	var out api.ReadResponse
	keys, sid, err := c.do(ctx, http.MethodPost, "/v1/read", req, &out)
	if err != nil {
		return nil, nil, err
	}
	if out.EndToEnd {
		values, err := c.openEndToEnd(&out)
		return values, &out, err
	}
	raw, err := keys.OpenFromServer(out.Sealed, api.PayloadAAD(sid, out.Item, "read"))
	if err != nil {
		return nil, nil, fmt.Errorf("client: could not open the sealed response: %w", err)
	}
	var payload api.SecretPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil, fmt.Errorf("client: malformed payload: %w", err)
	}
	return payload.Fields, &out, nil
}

// openEndToEnd decrypts an item the server itself cannot read.
func (c *Client) openEndToEnd(out *api.ReadResponse) (map[string]string, error) {
	if c.cfg.Identity == nil {
		return nil, errors.New("client: this item is end-to-end encrypted, which needs the private key itself; " +
			"pass --identity (ssh-agent can sign but cannot decrypt)")
	}
	dek, err := seal.UnwrapWithSSHKey(c.cfg.Identity, out.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("client: could not unwrap the item key: %w", err)
	}
	values := make(map[string]string, len(out.Ciphertexts))
	for name, ct := range out.Ciphertexts {
		pt, err := seal.Decrypt(dek, ct, store.FieldAAD(out.ServerID, out.Item, name))
		if err != nil {
			return nil, fmt.Errorf("client: could not decrypt %s: %w", name, err)
		}
		values[name] = string(pt)
	}
	return values, nil
}

// Code mints a second-factor code. Only the code comes back; the seed stays in
// the vault, which is the entire point.
func (c *Client) Code(ctx context.Context, req api.CodeRequest) (string, *api.CodeResponse, error) {
	var out api.CodeResponse
	keys, sid, err := c.do(ctx, http.MethodPost, "/v1/code", req, &out)
	if err != nil {
		return "", nil, err
	}
	raw, err := keys.OpenFromServer(out.Sealed, api.PayloadAAD(sid, out.Item, "code"))
	if err != nil {
		return "", nil, fmt.Errorf("client: could not open the sealed response: %w", err)
	}
	var payload api.CodePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", nil, fmt.Errorf("client: malformed payload: %w", err)
	}
	return payload.Code, &out, nil
}

// Login fetches credentials and, optionally, a fresh code in one round trip.
func (c *Client) Login(ctx context.Context, req api.LoginRequest) (*api.LoginPayload, *api.LoginResponse, error) {
	var out api.LoginResponse
	keys, sid, err := c.do(ctx, http.MethodPost, "/v1/login", req, &out)
	if err != nil {
		return nil, nil, err
	}
	raw, err := keys.OpenFromServer(out.Sealed, api.PayloadAAD(sid, out.Item, "login"))
	if err != nil {
		return nil, nil, fmt.Errorf("client: could not open the sealed response: %w", err)
	}
	var payload api.LoginPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil, fmt.Errorf("client: malformed payload: %w", err)
	}
	return &payload, &out, nil
}

// Release ends a lease early, recording that the agent is done with a secret.
func (c *Client) Release(ctx context.Context, leaseID string) error {
	_, _, err := c.do(ctx, http.MethodPost, "/v1/leases/release", api.ReleaseRequest{LeaseID: leaseID}, nil)
	return err
}

// SealForServer encrypts an operator payload under the session keys.
func (c *Client) SealForServer(ctx context.Context, item, purpose string, payload any) ([]byte, error) {
	_, keys, sid, err := c.ensure(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return keys.SealToServer(raw, api.PayloadAAD(sid, item, purpose))
}

// Admin issues an operator request against an arbitrary admin path.
func (c *Client) Admin(ctx context.Context, method, path string, body, out any) error {
	_, _, err := c.do(ctx, method, path, body, out)
	return err
}

// adminOnce is Admin without the automatic re-handshake. It exists for requests
// carrying a sealed payload: those are bound to the session that sealed them,
// so a silent reconnect would send a blob the server can no longer open.
func (c *Client) adminOnce(ctx context.Context, method, path string, body, out any) error {
	token, _, _, err := c.ensure(ctx)
	if err != nil {
		return err
	}
	return c.call(ctx, method, path, token, body, out)
}

// PutItem writes an item, sealing its secret material to the server first.
//
// The sealed blob is bound to the session that produced it, so if the session
// turns out to be stale we re-handshake and seal again rather than retrying
// with a blob the new session cannot open.
func (c *Client) PutItem(ctx context.Context, req adminapi.PutItemRequest, secrets *adminapi.ItemSecrets) error {
	hasSecrets := secrets != nil && (len(secrets.Fields) > 0 || secrets.OTPSeed != "" || secrets.OTPURI != "")
	for attempt := range 2 {
		if hasSecrets {
			sealed, err := c.SealForServer(ctx, req.Name, "put-item", secrets)
			if err != nil {
				return err
			}
			req.Sealed = sealed
		}
		err := c.adminOnce(ctx, http.MethodPost, "/v1/admin/items", req, nil)
		if err == nil {
			return nil
		}
		if attempt == 1 || !isUnauthenticated(err) {
			return err
		}
		if reconnectErr := c.Connect(ctx); reconnectErr != nil {
			return err
		}
	}
	return nil
}

// --- transport ---

func (c *Client) call(ctx context.Context, method, path, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("client: encode request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.BaseURL, "/")+path, reader)
	if err != nil {
		return fmt.Errorf("client: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-AI-Auth-Protocol", api.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("client: read response: %w", err)
	}

	if resp.StatusCode == http.StatusAccepted {
		var pending api.ApprovalPendingResponse
		if err := json.Unmarshal(raw, &pending); err == nil && pending.ApprovalID != "" {
			return &ErrApprovalPending{
				ApprovalID: pending.ApprovalID, Status: pending.Status,
				ExpiresAt: pending.ExpiresAt, Message: pending.Message,
			}
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr api.Error
		if err := json.Unmarshal(raw, &apiErr); err == nil && apiErr.Message != "" {
			return &apiErr
		}
		return fmt.Errorf("client: %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("client: decode response: %w", err)
	}
	return nil
}
