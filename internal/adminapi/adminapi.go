// Package adminapi defines the operator-facing half of the wire protocol.
//
// It is kept separate from package api so it is obvious at a glance which
// messages an agent identity can send and which require an operator.
package adminapi

import (
	"time"

	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/store"
)

// PutAgentRequest enrols or updates an identity.
type PutAgentRequest struct {
	Name        string     `json:"name"`
	PublicKey   string     `json:"public_key"`
	Role        string     `json:"role"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// DisableAgentRequest revokes an identity by name or fingerprint.
type DisableAgentRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// ItemSecrets is the plaintext an operator seals to the server when writing an
// item. It exists only inside a sealed blob, never as a JSON field on the wire.
type ItemSecrets struct {
	Fields map[string]string `json:"fields,omitempty"`
	// OTPSeed is a bare base32 seed; OTPURI is a full otpauth:// enrolment URI.
	// Either one configures the second factor, which is then stored where no
	// agent-facing endpoint can reach it.
	OTPSeed string `json:"otp_seed,omitempty"`
	OTPURI  string `json:"otp_uri,omitempty"`
}

// OTPView is the non-secret half of a second-factor configuration.
type OTPView struct {
	Algorithm string `json:"algorithm,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	Account   string `json:"account,omitempty"`
	HOTP      bool   `json:"hotp,omitempty"`
	// MinInterval throttles minting. A negative value clears the throttle.
	MinInterval int    `json:"min_interval,omitempty"`
	MintCount   uint64 `json:"mint_count,omitempty"`
}

// PutItemRequest creates or updates an item.
type PutItemRequest struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Target      string `json:"target,omitempty"`
	Description string `json:"description,omitempty"`

	// Sealed carries an ItemSecrets encrypted under the session's
	// client-to-server key.
	Sealed []byte `json:"sealed,omitempty"`

	// EndToEnd switches the item to client-side encryption. The server then
	// stores only what the operator sends below and can never read the values.
	EndToEnd    bool               `json:"end_to_end,omitempty"`
	Ciphertexts map[string][]byte  `json:"ciphertexts,omitempty"`
	Recipients  []*seal.WrappedKey `json:"recipients,omitempty"`

	OTP               *OTPView `json:"otp,omitempty"`
	RemoveOTP         bool     `json:"remove_otp,omitempty"`
	RemoveFields      []string `json:"remove_fields,omitempty"`
	RotateAfterUse    *bool    `json:"rotate_after_use,omitempty"`
	ClearRotationFlag bool     `json:"clear_rotation_flag,omitempty"`
}

// DeleteItemRequest removes an item.
type DeleteItemRequest struct {
	Name string `json:"name"`
}

// ItemView is the operator's non-secret view of an item.
type ItemView struct {
	Name           string    `json:"name"`
	Title          string    `json:"title,omitempty"`
	Target         string    `json:"target,omitempty"`
	Description    string    `json:"description,omitempty"`
	Fields         []string  `json:"fields"`
	Sealed         []string  `json:"sealed_fields,omitempty"`
	OTP            *OTPView  `json:"otp,omitempty"`
	HasOTP         bool      `json:"has_otp"`
	EndToEnd       bool      `json:"end_to_end,omitempty"`
	Recipients     []string  `json:"recipients,omitempty"`
	RotateAfterUse bool      `json:"rotate_after_use,omitempty"`
	NeedsRotation  bool      `json:"needs_rotation,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PutGrantRequest creates or replaces a grant.
type PutGrantRequest struct {
	ID          string     `json:"id,omitempty"`
	Agent       string     `json:"agent"`
	Items       []string   `json:"items"`
	Fields      []string   `json:"fields,omitempty"`
	Actions     []string   `json:"actions"`
	Description string     `json:"description,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	MaxUses     int        `json:"max_uses,omitempty"`
	RateCount   int        `json:"rate_count,omitempty"`
	RateWindow  int        `json:"rate_window_seconds,omitempty"`

	RequireApproval bool     `json:"require_approval,omitempty"`
	RequireReason   bool     `json:"require_reason,omitempty"`
	AllowedTargets  []string `json:"allowed_targets,omitempty"`
}

// GrantView is a grant plus its usage.
type GrantView struct {
	*store.Grant
	TotalUses int `json:"total_uses"`
}

// RevokeGrantRequest revokes a grant by id.
type RevokeGrantRequest struct {
	ID string `json:"id"`
}

// DecideApprovalRequest is a human's answer to a pending request.
type DecideApprovalRequest struct {
	ID      string `json:"id"`
	Approve bool   `json:"approve"`
	Note    string `json:"note,omitempty"`
	// ExtendSeconds widens the window in which the approval may be spent.
	ExtendSeconds int `json:"extend_seconds,omitempty"`
}

// RecipientsResponse lists the public keys an operator can encrypt to when
// building an end-to-end item.
type RecipientsResponse struct {
	Recipients map[string]string `json:"recipients"`
}
