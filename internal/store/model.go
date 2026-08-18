// Package store holds ai-auth's data model and its on-disk representation.
//
// Only secret material is encrypted. Names, policy and timestamps stay in
// plaintext on purpose: an operator must be able to read and review who may
// reach what without unsealing the vault, and policy that you cannot inspect is
// policy you cannot trust.
package store

import (
	"strings"
	"time"

	"github.com/linktoming/ai-auth/internal/otp"
	"github.com/linktoming/ai-auth/internal/seal"
)

// FormatVersion is the on-disk schema version.
const FormatVersion = 1

// Role determines which API surface an identity may reach.
type Role string

// Roles.
const (
	// RoleAgent is an AI agent: it may consume credentials it has been granted.
	RoleAgent Role = "agent"
	// RoleOperator is a human administrator: it manages items, grants and
	// approvals but is not itself a credential consumer.
	RoleOperator Role = "operator"
)

// Action is a capability that a grant can confer.
type Action string

// Actions.
const (
	// ActionRead releases stored field values to the agent.
	ActionRead Action = "read"
	// ActionTOTP mints a one-time code without ever releasing the seed.
	ActionTOTP Action = "totp"
	// ActionList reveals that an item exists, and its metadata, but no secrets.
	ActionList Action = "list"
)

// SeedField is the reserved field name holding a second-factor seed. It is
// permanently non-releasable: no grant, and no combination of flags, can cause
// the server to hand it out over the agent API.
const SeedField = "totp_seed"

// Agent is a registered identity, addressed by its SSH public key.
type Agent struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	PublicKey   string    `json:"public_key"`
	Role        Role      `json:"role"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Disabled    bool      `json:"disabled,omitempty"`
	// ExpiresAt bounds the lifetime of the identity itself. Agents are cheap to
	// re-enrol, so short-lived identities are the default posture.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Active reports whether the agent may authenticate right now.
func (a *Agent) Active(now time.Time) (bool, string) {
	switch {
	case a.Disabled:
		return false, "identity is disabled"
	case a.ExpiresAt != nil && now.After(*a.ExpiresAt):
		return false, "identity expired on " + a.ExpiresAt.UTC().Format(time.RFC3339)
	default:
		return true, ""
	}
}

// Field is one encrypted value inside an item.
type Field struct {
	// Ciphertext is sealed under the item's data key. In end-to-end mode the
	// server cannot open it at all.
	Ciphertext []byte `json:"ciphertext"`
	// Releasable is false for values that exist only so the server can compute
	// something from them. It is enforced in addition to the SeedField rule.
	Releasable bool      `json:"releasable"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Item is a credential record.
type Item struct {
	Name        string            `json:"name"`
	Title       string            `json:"title,omitempty"`
	Target      string            `json:"target,omitempty"`
	Description string            `json:"description,omitempty"`
	Fields      map[string]*Field `json:"fields"`
	OTP         *OTPSpec          `json:"otp,omitempty"`

	// EndToEnd means the data key is wrapped only to agent public keys, so the
	// server stores ciphertext it has no way to read. Server-side second-factor
	// minting is unavailable for such items -- that trade-off is the reason it
	// is opt-in per item rather than global.
	EndToEnd   bool               `json:"end_to_end"`
	WrappedDEK []byte             `json:"wrapped_dek,omitempty"`
	Recipients []*seal.WrappedKey `json:"recipients,omitempty"`

	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// RotateAfterUse marks the item for rotation as soon as it is released,
	// which turns a long-lived password into an effectively single-use one.
	RotateAfterUse bool       `json:"rotate_after_use,omitempty"`
	NeedsRotation  bool       `json:"needs_rotation,omitempty"`
	RotatedAt      *time.Time `json:"rotated_at,omitempty"`
}

// OTPSpec is the non-secret half of a second-factor configuration. The seed
// itself lives in Fields[SeedField].
type OTPSpec struct {
	Config *otp.Config `json:"config"`
	// MinInterval is the minimum number of seconds between mints. For TOTP the
	// per-step rule below already caps minting at one code per period, so this
	// matters when set *longer* than the period (deliberately slowing a
	// harvesting agent), and for HOTP, which has no time step to lean on.
	MinInterval int `json:"min_interval"`
	// LastStep and LastCode make repeated requests inside one time step
	// idempotent instead of burning quota.
	LastStep  uint64     `json:"last_step,omitempty"`
	LastMint  *time.Time `json:"last_mint,omitempty"`
	MintCount uint64     `json:"mint_count,omitempty"`
}

// FieldNames returns the item's field names, releasable ones first.
func (i *Item) FieldNames() []string {
	var out []string
	for name := range i.Fields {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// Releasable reports whether a field may ever leave the server.
func (i *Item) Releasable(name string) bool {
	if name == SeedField {
		return false
	}
	f, ok := i.Fields[name]
	return ok && f.Releasable
}

// RateLimit caps how often a grant may be exercised.
type RateLimit struct {
	Count  int `json:"count"`
	Window int `json:"window_seconds"`
}

// Grant authorises one agent to perform actions on a set of items.
// Everything is deny-by-default: an agent with no matching grant sees nothing.
type Grant struct {
	ID          string   `json:"id"`
	Agent       string   `json:"agent"`
	Items       []string `json:"items"`
	Fields      []string `json:"fields,omitempty"`
	Actions     []Action `json:"actions"`
	Description string   `json:"description,omitempty"`

	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	MaxUses   int        `json:"max_uses,omitempty"`
	Rate      *RateLimit `json:"rate,omitempty"`

	// RequireApproval holds every request until a human approves it. This is
	// the control that survives a prompt-injected agent.
	RequireApproval bool `json:"require_approval,omitempty"`
	// RequireReason forces the agent to state why it wants the credential; the
	// reason lands in the audit log next to the release.
	RequireReason bool `json:"require_reason,omitempty"`
	// AllowedTargets restricts which system the credential may be requested
	// for, so a staging grant cannot be spent against production.
	AllowedTargets []string `json:"allowed_targets,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// Allows reports whether the grant confers the given action.
func (g *Grant) Allows(a Action) bool {
	for _, have := range g.Actions {
		if have == a {
			return true
		}
	}
	return false
}

// MatchesItem reports whether the grant covers an item name.
func (g *Grant) MatchesItem(name string) bool { return matchAny(g.Items, name) }

// MatchesField reports whether the grant covers a field name. An empty field
// list means "every releasable field".
func (g *Grant) MatchesField(name string) bool {
	if len(g.Fields) == 0 {
		return true
	}
	return matchAny(g.Fields, name)
}

// MatchesTarget reports whether a requested target is permitted.
func (g *Grant) MatchesTarget(target string) bool {
	if len(g.AllowedTargets) == 0 {
		return true
	}
	return matchAny(g.AllowedTargets, target)
}

// Counter tracks grant usage across restarts, so a rate limit is not reset by
// bouncing the server.
type Counter struct {
	GrantID     string    `json:"grant_id"`
	TotalUses   int       `json:"total_uses"`
	WindowStart time.Time `json:"window_start"`
	WindowUses  int       `json:"window_uses"`
}

// LeaseStatus describes where a lease is in its lifecycle.
type LeaseStatus string

// Lease statuses.
const (
	LeaseActive   LeaseStatus = "active"
	LeaseReleased LeaseStatus = "released"
	LeaseExpired  LeaseStatus = "expired"
)

// Lease records that credentials are currently in an agent's hands. It cannot
// claw the value back, but it makes "who is holding what, right now" answerable
// and gives the agent a way to say it is finished.
type Lease struct {
	ID         string      `json:"id"`
	Agent      string      `json:"agent"`
	Item       string      `json:"item"`
	Fields     []string    `json:"fields"`
	Target     string      `json:"target,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	IssuedAt   time.Time   `json:"issued_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	ReleasedAt *time.Time  `json:"released_at,omitempty"`
	Status     LeaseStatus `json:"status"`
}

// ApprovalStatus is the state of a human-in-the-loop request.
type ApprovalStatus string

// Approval states.
const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalUsed     ApprovalStatus = "used"
	ApprovalExpired  ApprovalStatus = "expired"
)

// Approval is a single-use permission slip issued by a human. It is bound to
// the exact request that asked for it, so an approval for reading a staging
// password cannot be spent on minting a production code.
type Approval struct {
	ID          string         `json:"id"`
	Agent       string         `json:"agent"`
	Item        string         `json:"item"`
	Action      Action         `json:"action"`
	Fields      []string       `json:"fields,omitempty"`
	Target      string         `json:"target,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	RequestedAt time.Time      `json:"requested_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Status      ApprovalStatus `json:"status"`
	DecidedBy   string         `json:"decided_by,omitempty"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
	Note        string         `json:"note,omitempty"`
}

// Matches reports whether an approval covers a specific request.
func (a *Approval) Matches(agent, item string, action Action, fields []string) bool {
	if a.Agent != agent || a.Item != item || a.Action != action {
		return false
	}
	for _, want := range fields {
		if !containsString(a.Fields, want) {
			return false
		}
	}
	return true
}

// matchAny reports whether value matches any pattern. Patterns support '*' as a
// wildcard over any run of characters; everything else is literal.
func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if matchGlob(p, value) {
			return true
		}
	}
	return false
}

// matchGlob implements '*'-only glob matching with linear backtracking.
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(value, part)
		if idx < 0 {
			return false
		}
		value = value[idx+len(part):]
	}
	return strings.HasSuffix(value, last) && len(value) >= len(last)
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
