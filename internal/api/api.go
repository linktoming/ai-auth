// Package api defines the ai-auth wire protocol, shared by client and server.
//
// Secret values never appear as plain JSON fields. They travel inside `sealed`
// blobs encrypted under the per-session handshake keys, so a TLS-terminating
// proxy, a request log or a crash dump of the HTTP layer contains ciphertext
// rather than passwords.
package api

import (
	"time"

	"github.com/linktoming/ai-auth/internal/seal"
)

// Version is the protocol version, sent as a header and checked by the server
// so a mismatched client fails clearly instead of subtly.
const Version = "v1"

// PayloadAAD binds a sealed payload to the session and purpose it was made for,
// so a response cannot be replayed into a different context.
func PayloadAAD(sessionID, item, purpose string) []byte {
	return []byte("ai-auth-payload-v1|" + sessionID + "|" + item + "|" + purpose)
}

// HandshakeInitRequest opens a session.
type HandshakeInitRequest struct {
	Fingerprint     string `json:"fingerprint"`
	ClientEphemeral []byte `json:"client_ephemeral"`
	ClientNonce     []byte `json:"client_nonce"`
}

// HandshakeInitResponse carries the server's half of the exchange.
type HandshakeInitResponse struct {
	SessionID       string    `json:"session_id"`
	ServerID        string    `json:"server_id"`
	ServerEphemeral []byte    `json:"server_ephemeral"`
	ServerNonce     []byte    `json:"server_nonce"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// HandshakeCompleteRequest proves possession of the SSH private key.
type HandshakeCompleteRequest struct {
	SessionID       string `json:"session_id"`
	SignatureFormat string `json:"signature_format"`
	SignatureBlob   []byte `json:"signature_blob"`
}

// HandshakeCompleteResponse issues the session token.
type HandshakeCompleteResponse struct {
	Token     string    `json:"token"`
	Agent     string    `json:"agent"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ReadRequest asks for stored field values.
type ReadRequest struct {
	Item       string   `json:"item"`
	Fields     []string `json:"fields,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Target     string   `json:"target,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	ApprovalID string   `json:"approval_id,omitempty"`
}

// SecretPayload is the plaintext inside a sealed read response.
type SecretPayload struct {
	Fields map[string]string `json:"fields"`
}

// ReadResponse returns sealed values, or the raw material an end-to-end client
// needs to decrypt them itself.
type ReadResponse struct {
	Item      string    `json:"item"`
	LeaseID   string    `json:"lease_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Fields    []string  `json:"fields"`

	// Sealed is set for server-side items: a SecretPayload encrypted to the
	// session.
	Sealed []byte `json:"sealed,omitempty"`

	// The following are set only for end-to-end items, where the server is
	// forwarding ciphertext it cannot read.
	EndToEnd    bool              `json:"end_to_end,omitempty"`
	ServerID    string            `json:"server_id,omitempty"`
	Ciphertexts map[string][]byte `json:"ciphertexts,omitempty"`
	WrappedKey  *seal.WrappedKey  `json:"wrapped_key,omitempty"`
}

// CodeRequest asks for a second-factor code.
type CodeRequest struct {
	Item       string `json:"item"`
	Reason     string `json:"reason,omitempty"`
	Target     string `json:"target,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
}

// CodePayload is the plaintext inside a sealed code response.
type CodePayload struct {
	Code string `json:"code"`
}

// CodeResponse returns a sealed one-time code. The seed is never part of any
// response body -- there is no field here that could carry it.
type CodeResponse struct {
	Item            string    `json:"item"`
	LeaseID         string    `json:"lease_id"`
	Sealed          []byte    `json:"sealed"`
	Digits          int       `json:"digits"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
	ValidForSeconds int       `json:"valid_for_seconds"`
	Reused          bool      `json:"reused,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
	Account         string    `json:"account,omitempty"`
}

// LoginRequest asks for everything needed to sign in, in one round trip.
type LoginRequest struct {
	Item       string `json:"item"`
	Reason     string `json:"reason,omitempty"`
	Target     string `json:"target,omitempty"`
	WithCode   bool   `json:"with_code"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
}

// LoginPayload is the plaintext inside a sealed login response.
type LoginPayload struct {
	Fields map[string]string `json:"fields"`
	Code   string            `json:"code,omitempty"`
}

// LoginResponse bundles a credential read and a code mint.
type LoginResponse struct {
	Item            string    `json:"item"`
	LeaseID         string    `json:"lease_id"`
	Sealed          []byte    `json:"sealed"`
	Fields          []string  `json:"fields"`
	ExpiresAt       time.Time `json:"expires_at"`
	CodeExpiresAt   time.Time `json:"code_expires_at,omitzero"`
	ValidForSeconds int       `json:"valid_for_seconds,omitempty"`
}

// ItemSummary is the non-secret view of an item.
type ItemSummary struct {
	Name          string   `json:"name"`
	Title         string   `json:"title,omitempty"`
	Target        string   `json:"target,omitempty"`
	Description   string   `json:"description,omitempty"`
	Fields        []string `json:"fields"`
	HasOTP        bool     `json:"has_otp"`
	EndToEnd      bool     `json:"end_to_end,omitempty"`
	Actions       []string `json:"actions"`
	NeedsRotation bool     `json:"needs_rotation,omitempty"`
}

// ListResponse enumerates what an agent may see.
type ListResponse struct {
	Items []ItemSummary `json:"items"`
}

// WhoAmIResponse describes the caller's own identity and reach. An agent should
// call this to discover what it can do rather than guessing.
type WhoAmIResponse struct {
	Agent       string         `json:"agent"`
	Fingerprint string         `json:"fingerprint"`
	Role        string         `json:"role"`
	ServerID    string         `json:"server_id"`
	ExpiresAt   time.Time      `json:"session_expires_at"`
	Grants      []GrantSummary `json:"grants"`
}

// GrantSummary is a redacted view of a grant, safe to show to its holder.
type GrantSummary struct {
	ID              string     `json:"id"`
	Items           []string   `json:"items"`
	Fields          []string   `json:"fields,omitempty"`
	Actions         []string   `json:"actions"`
	Description     string     `json:"description,omitempty"`
	NotAfter        *time.Time `json:"not_after,omitempty"`
	RequireApproval bool       `json:"require_approval,omitempty"`
	RequireReason   bool       `json:"require_reason,omitempty"`
	AllowedTargets  []string   `json:"allowed_targets,omitempty"`
	UsesRemaining   *int       `json:"uses_remaining,omitempty"`
}

// ApprovalPendingResponse is returned with HTTP 202 when a human must decide.
type ApprovalPendingResponse struct {
	ApprovalID string    `json:"approval_id"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expires_at"`
	Message    string    `json:"message"`
}

// ReleaseRequest ends a lease early.
type ReleaseRequest struct {
	LeaseID string `json:"lease_id"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after_seconds,omitempty"`
}

func (e *Error) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}
