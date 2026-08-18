// Package server implements the ai-auth HTTP API.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/linktoming/ai-auth/internal/api"
	"github.com/linktoming/ai-auth/internal/audit"
	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/sshid"
	"github.com/linktoming/ai-auth/internal/store"
)

// Config configures a Server.
type Config struct {
	Vault  *store.Vault
	Audit  *audit.Log
	Logger *slog.Logger
	// AuditPath is where the audit log lives, so the admin API can re-read and
	// re-verify the chain rather than trusting its own in-memory view.
	AuditPath string

	// HandshakeTTL bounds how long a challenge stays answerable. Short, because
	// its only job is to survive one network round trip.
	HandshakeTTL time.Duration
	// SessionTTL bounds a bearer token's life. Agents re-handshake cheaply, so
	// this is deliberately short.
	SessionTTL time.Duration
	// LeaseTTL is the default lifetime of a credential lease.
	LeaseTTL time.Duration
	// MaxLeaseTTL caps what a client may request.
	MaxLeaseTTL time.Duration
	// ApprovalTTL bounds how long a human has to answer, and how long an
	// approval remains spendable.
	ApprovalTTL time.Duration
	// MaxFailedHandshakes is the number of bad signatures tolerated per
	// fingerprint per FailureWindow before that identity is refused.
	MaxFailedHandshakes int
	FailureWindow       time.Duration

	// Now is injectable so tests can control time.
	Now func() time.Time
}

func (c *Config) applyDefaults() {
	if c.HandshakeTTL == 0 {
		c.HandshakeTTL = 30 * time.Second
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 5 * time.Minute
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = 2 * time.Minute
	}
	if c.MaxLeaseTTL == 0 {
		c.MaxLeaseTTL = 15 * time.Minute
	}
	if c.ApprovalTTL == 0 {
		c.ApprovalTTL = 10 * time.Minute
	}
	if c.MaxFailedHandshakes == 0 {
		c.MaxFailedHandshakes = 10
	}
	if c.FailureWindow == 0 {
		c.FailureWindow = 5 * time.Minute
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// pendingHandshake is a challenge awaiting its signature.
type pendingHandshake struct {
	id          string
	fingerprint string
	agent       string
	eph         *seal.Ephemeral
	clientPub   []byte
	clientNonce []byte
	expiresAt   time.Time
}

// session is an authenticated connection.
type session struct {
	id          string
	agent       string
	fingerprint string
	role        store.Role
	keys        *seal.Session
	expiresAt   time.Time
	remote      string
}

type failureRecord struct {
	count int
	since time.Time
}

// Server serves the ai-auth API.
type Server struct {
	cfg Config
	mux *http.ServeMux

	mu       sync.Mutex
	pending  map[string]*pendingHandshake
	sessions map[string]*session // keyed by token digest
	failures map[string]*failureRecord
}

// New builds a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Vault == nil {
		return nil, errors.New("server: a vault is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("server: an audit log is required")
	}
	cfg.applyDefaults()
	s := &Server{
		cfg:      cfg,
		mux:      http.NewServeMux(),
		pending:  map[string]*pendingHandshake{},
		sessions: map[string]*session{},
		failures: map[string]*failureRecord{},
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /v1/handshake/init", s.handleHandshakeInit)
	s.mux.HandleFunc("POST /v1/handshake/complete", s.handleHandshakeComplete)

	s.mux.HandleFunc("GET /v1/whoami", s.agentOnly(s.handleWhoAmI))
	s.mux.HandleFunc("GET /v1/items", s.agentOnly(s.handleList))
	s.mux.HandleFunc("POST /v1/read", s.agentOnly(s.handleRead))
	s.mux.HandleFunc("POST /v1/code", s.agentOnly(s.handleCode))
	s.mux.HandleFunc("POST /v1/login", s.agentOnly(s.handleLogin))
	s.mux.HandleFunc("POST /v1/leases/release", s.agentOnly(s.handleRelease))

	s.mux.HandleFunc("GET /v1/admin/agents", s.operatorOnly(s.handleAdminListAgents))
	s.mux.HandleFunc("POST /v1/admin/agents", s.operatorOnly(s.handleAdminPutAgent))
	s.mux.HandleFunc("POST /v1/admin/agents/disable", s.operatorOnly(s.handleAdminDisableAgent))
	s.mux.HandleFunc("GET /v1/admin/items", s.operatorOnly(s.handleAdminListItems))
	s.mux.HandleFunc("POST /v1/admin/items", s.operatorOnly(s.handleAdminPutItem))
	s.mux.HandleFunc("POST /v1/admin/items/delete", s.operatorOnly(s.handleAdminDeleteItem))
	s.mux.HandleFunc("GET /v1/admin/grants", s.operatorOnly(s.handleAdminListGrants))
	s.mux.HandleFunc("POST /v1/admin/grants", s.operatorOnly(s.handleAdminPutGrant))
	s.mux.HandleFunc("POST /v1/admin/grants/revoke", s.operatorOnly(s.handleAdminRevokeGrant))
	s.mux.HandleFunc("GET /v1/admin/approvals", s.operatorOnly(s.handleAdminListApprovals))
	s.mux.HandleFunc("POST /v1/admin/approvals/decide", s.operatorOnly(s.handleAdminDecideApproval))
	s.mux.HandleFunc("GET /v1/admin/leases", s.operatorOnly(s.handleAdminListLeases))
	s.mux.HandleFunc("GET /v1/admin/audit", s.operatorOnly(s.handleAdminAudit))
	s.mux.HandleFunc("GET /v1/admin/recipients", s.operatorOnly(s.handleAdminRecipients))

	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Nothing this API returns should ever be cached or embedded in a page.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) now() time.Time { return s.cfg.Now().UTC() }

// --- handshake ---

func (s *Server) handleHandshakeInit(w http.ResponseWriter, r *http.Request) {
	var req api.HandshakeInitRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.ClientEphemeral) != 32 || len(req.ClientNonce) != seal.NonceSize {
		writeError(w, http.StatusBadRequest, "bad_request", "client ephemeral key and nonce are malformed")
		return
	}

	v := s.cfg.Vault
	v.RLock()
	agent := v.Data().Agents[req.Fingerprint]
	v.RUnlock()

	now := s.now()
	if s.lockedOut(req.Fingerprint, now) {
		writeError(w, http.StatusTooManyRequests, "too_many_failures",
			"too many failed handshakes for this identity; wait for the window to pass")
		return
	}

	// An unknown fingerprint still receives a well-formed challenge. Refusing
	// here would turn the endpoint into an oracle for "is this key enrolled".
	// The request fails at signature verification instead.
	eph, err := seal.NewEphemeral()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not start handshake")
		return
	}
	id, err := randomID("hs")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not start handshake")
		return
	}
	p := &pendingHandshake{
		id:          id,
		fingerprint: req.Fingerprint,
		eph:         eph,
		clientPub:   req.ClientEphemeral,
		clientNonce: req.ClientNonce,
		expiresAt:   now.Add(s.cfg.HandshakeTTL),
	}
	if agent != nil {
		p.agent = agent.Name
	}

	s.mu.Lock()
	s.sweepLocked(now)
	s.pending[id] = p
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, api.HandshakeInitResponse{
		SessionID:       id,
		ServerID:        v.ServerID(),
		ServerEphemeral: eph.Pub,
		ServerNonce:     eph.Nonce,
		ExpiresAt:       p.expiresAt,
	})
}

func (s *Server) handleHandshakeComplete(w http.ResponseWriter, r *http.Request) {
	var req api.HandshakeCompleteRequest
	if !decode(w, r, &req) {
		return
	}
	now := s.now()

	s.mu.Lock()
	p := s.pending[req.SessionID]
	// A challenge is answerable exactly once, whatever the outcome.
	delete(s.pending, req.SessionID)
	s.mu.Unlock()

	if p == nil || now.After(p.expiresAt) {
		writeError(w, http.StatusUnauthorized, "handshake_expired", "no such handshake, or it has already been used or expired")
		return
	}

	v := s.cfg.Vault
	v.RLock()
	agent := v.Data().Agents[p.fingerprint]
	serverID := v.Data().ServerID
	v.RUnlock()

	fail := func(detail string) {
		s.recordFailure(p.fingerprint, now)
		s.auditRecord(audit.Record{
			Actor: nameOr(agent, "unknown"), KeyID: p.fingerprint, Action: "handshake",
			Decision: audit.Deny, Detail: detail, Remote: remoteAddr(r),
		})
		// One message for every failure mode: an attacker probing fingerprints
		// learns nothing from the response.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication failed")
	}

	if agent == nil {
		fail("unknown fingerprint " + p.fingerprint)
		return
	}
	if ok, why := agent.Active(now); !ok {
		fail(why)
		return
	}

	pub, _, err := sshid.ParseAuthorizedKey(agent.PublicKey)
	if err != nil {
		fail("stored public key is unparseable: " + err.Error())
		return
	}
	transcript := seal.Transcript(serverID, p.id, p.fingerprint, p.clientPub, p.clientNonce, p.eph.Pub, p.eph.Nonce)
	sig := &ssh.Signature{Format: req.SignatureFormat, Blob: req.SignatureBlob}
	if err := sshid.Verify(pub, transcript, sig); err != nil {
		fail("signature verification failed: " + err.Error())
		return
	}

	keys, err := p.eph.Derive(p.clientPub, p.clientNonce, p.eph.Nonce)
	if err != nil {
		fail("key agreement failed: " + err.Error())
		return
	}

	token, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not issue a session")
		return
	}
	sess := &session{
		id:          p.id,
		agent:       agent.Name,
		fingerprint: agent.Fingerprint,
		role:        agent.Role,
		keys:        keys,
		expiresAt:   now.Add(s.cfg.SessionTTL),
		remote:      remoteAddr(r),
	}

	s.mu.Lock()
	s.sessions[tokenDigest(token)] = sess
	delete(s.failures, p.fingerprint)
	s.mu.Unlock()

	v.Lock()
	if a := v.Data().Agents[p.fingerprint]; a != nil {
		a.LastSeen = now
	}
	saveErr := v.SaveLocked()
	v.Unlock()
	if saveErr != nil {
		s.cfg.Logger.Warn("could not persist last-seen timestamp", "error", saveErr)
	}

	s.auditRecord(audit.Record{
		Actor: agent.Name, KeyID: agent.Fingerprint, Action: "handshake",
		Decision: audit.Allow, Remote: remoteAddr(r),
	})
	writeJSON(w, http.StatusOK, api.HandshakeCompleteResponse{
		Token:     token,
		Agent:     agent.Name,
		Role:      string(agent.Role),
		ExpiresAt: sess.expiresAt,
	})
}

// --- authentication middleware ---

type handlerFunc func(http.ResponseWriter, *http.Request, *session)

func (s *Server) authenticate(r *http.Request) (*session, bool) {
	h := r.Header.Get("Authorization")
	raw, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || raw == "" {
		return nil, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	sess := s.sessions[tokenDigest(strings.TrimSpace(raw))]
	if sess == nil || now.After(sess.expiresAt) {
		return nil, false
	}
	return sess, true
}

func (s *Server) agentOnly(h handlerFunc) http.HandlerFunc {
	return s.authed(h, store.RoleAgent, store.RoleOperator)
}

func (s *Server) operatorOnly(h handlerFunc) http.HandlerFunc {
	return s.authed(h, store.RoleOperator)
}

func (s *Server) authed(h handlerFunc, roles ...store.Role) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ai-auth"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "missing, expired or invalid session token")
			return
		}
		permitted := false
		for _, role := range roles {
			if sess.role == role {
				permitted = true
				break
			}
		}
		if !permitted {
			s.auditRecord(audit.Record{
				Actor: sess.agent, KeyID: sess.fingerprint, Action: r.URL.Path,
				Decision: audit.Deny, Detail: "role " + string(sess.role) + " may not use this endpoint",
				Remote: remoteAddr(r),
			})
			writeError(w, http.StatusForbidden, "forbidden", "this endpoint requires the operator role")
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"sealed":   s.cfg.Vault.Sealed(),
		"protocol": api.Version,
	})
}

// --- housekeeping ---

// sweepLocked drops expired handshakes, sessions and failure records. Callers
// must hold s.mu.
func (s *Server) sweepLocked(now time.Time) {
	for id, p := range s.pending {
		if now.After(p.expiresAt) {
			delete(s.pending, id)
		}
	}
	for tok, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			delete(s.sessions, tok)
		}
	}
	for fp, f := range s.failures {
		if now.Sub(f.since) > s.cfg.FailureWindow {
			delete(s.failures, fp)
		}
	}
}

func (s *Server) lockedOut(fingerprint string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[fingerprint]
	if f == nil {
		return false
	}
	if now.Sub(f.since) > s.cfg.FailureWindow {
		delete(s.failures, fingerprint)
		return false
	}
	return f.count >= s.cfg.MaxFailedHandshakes
}

func (s *Server) recordFailure(fingerprint string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[fingerprint]
	if f == nil || now.Sub(f.since) > s.cfg.FailureWindow {
		f = &failureRecord{since: now}
		s.failures[fingerprint] = f
	}
	f.count++
}

func (s *Server) auditRecord(r audit.Record) {
	if r.Time.IsZero() {
		r.Time = s.now()
	}
	if _, err := s.cfg.Audit.Append(r); err != nil {
		// A release we cannot account for is worse than a failed request, so
		// this is logged loudly; handlers treat audit failure as fatal.
		s.cfg.Logger.Error("audit append failed", "error", err, "action", r.Action)
	}
}

// mustAudit appends a record and reports whether it succeeded. Handlers call
// this before releasing a secret: if the release cannot be recorded, it does
// not happen.
func (s *Server) mustAudit(w http.ResponseWriter, r audit.Record) bool {
	if r.Time.IsZero() {
		r.Time = s.now()
	}
	if _, err := s.cfg.Audit.Append(r); err != nil {
		s.cfg.Logger.Error("audit append failed; refusing to release", "error", err)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable",
			"the audit log is not writable, so no credential can be released")
		return false
	}
	return true
}

// --- helpers ---

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	// Bound the body: nothing this API accepts is large, and an unbounded
	// reader is a free memory-exhaustion primitive.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "malformed request body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Default().Debug("write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, api.Error{Code: code, Message: msg})
}

func writeRetryableError(w http.ResponseWriter, status int, code, msg string, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
	}
	writeJSON(w, status, api.Error{Code: code, Message: msg, RetryAfter: int(retryAfter.Seconds()) + 1})
}

func randomID(prefix string) (string, error) {
	b, err := seal.RandomBytes(12)
	if err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func randomToken() (string, error) {
	b, err := seal.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tokenDigest is what we keep in memory. Comparing digests through a map lookup
// avoids holding the bearer token itself in the session table.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte("ai-auth-token-v1|" + token))
	return hex.EncodeToString(sum[:])
}

// constantTimeEqual is used where a value is compared outside a map lookup.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func nameOr(a *store.Agent, fallback string) string {
	if a == nil {
		return fallback
	}
	return a.Name
}
