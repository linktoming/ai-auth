package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/linktoming/ai-auth/internal/otp"
	"github.com/linktoming/ai-auth/internal/seal"
)

// FieldAAD binds a ciphertext to the exact slot it was written to. Without it,
// an operator with file access could copy the production password blob into a
// staging item's password field and read it back through a staging grant.
func FieldAAD(serverID, item, field string) []byte {
	return []byte("ai-auth-field-v1|" + serverID + "|" + item + "|" + field)
}

// NewItem builds a server-side (non end-to-end) item with a fresh data key.
// The caller must hold the write lock and the vault must be unsealed.
func (v *Vault) NewItem(name string) (*Item, []byte, error) {
	if v.root == nil {
		return nil, nil, ErrSealed
	}
	dek, err := seal.RandomKey()
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := seal.Encrypt(v.root, dek, []byte("ai-auth-dek-v1|"+v.data.ServerID+"|"+name))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	return &Item{
		Name:       name,
		Fields:     map[string]*Field{},
		WrappedDEK: wrapped,
		Version:    1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, dek, nil
}

// ItemDEK unwraps an item's data key using the root key. It fails for
// end-to-end items by construction: there is nothing the server can unwrap.
func (v *Vault) ItemDEK(item *Item) ([]byte, error) {
	if item.EndToEnd {
		return nil, fmt.Errorf("store: %q is an end-to-end item; the server holds no key for it", item.Name)
	}
	if v.root == nil {
		return nil, ErrSealed
	}
	if len(item.WrappedDEK) == 0 {
		return nil, fmt.Errorf("store: item %q has no data key", item.Name)
	}
	return seal.Decrypt(v.root, item.WrappedDEK, []byte("ai-auth-dek-v1|"+v.data.ServerID+"|"+item.Name))
}

// SetField encrypts and stores a value on an item.
func (v *Vault) SetField(item *Item, dek []byte, name, value string, releasable bool) error {
	if name == SeedField && releasable {
		return fmt.Errorf("store: %s can never be marked releasable", SeedField)
	}
	ct, err := seal.Encrypt(dek, []byte(value), FieldAAD(v.data.ServerID, item.Name, name))
	if err != nil {
		return err
	}
	item.Fields[name] = &Field{Ciphertext: ct, Releasable: releasable, UpdatedAt: time.Now().UTC()}
	item.UpdatedAt = time.Now().UTC()
	return nil
}

// ReadField decrypts a single field. It refuses non-releasable fields here as
// well as at the API layer, so a future handler cannot accidentally leak a seed
// by forgetting to check.
func (v *Vault) ReadField(item *Item, name string) (string, error) {
	if !item.Releasable(name) {
		return "", fmt.Errorf("store: field %q of %q is not releasable", name, item.Name)
	}
	return v.decryptField(item, name)
}

func (v *Vault) decryptField(item *Item, name string) (string, error) {
	f, ok := item.Fields[name]
	if !ok {
		return "", fmt.Errorf("store: item %q has no field %q: %w", item.Name, name, ErrNotFound)
	}
	dek, err := v.ItemDEK(item)
	if err != nil {
		return "", err
	}
	pt, err := seal.Decrypt(dek, f.Ciphertext, FieldAAD(v.data.ServerID, item.Name, name))
	if err != nil {
		return "", fmt.Errorf("store: decrypt %s/%s: %w", item.Name, name, err)
	}
	return string(pt), nil
}

// Mint is the result of a second-factor code request.
type Mint struct {
	Code      string
	Step      uint64
	ExpiresAt time.Time
	ValidFor  time.Duration
	// Reused is true when the caller asked again inside the same time step and
	// received the code already issued for it, rather than consuming new quota.
	Reused bool
}

// ErrMintTooSoon is returned when an item's minimum mint interval has not
// elapsed. It is a distinct error so the API can answer 429 rather than 403.
var ErrMintTooSoon = errors.New("store: second-factor code requested too soon")

// MintOTP computes a one-time code from a seed that never leaves this process.
//
// This is the core of ai-auth's answer to "how do I give an agent 2FA without
// leaking 2FA": the agent has no API that returns the seed, only this one,
// which returns a code that is useless in about half a minute.
func (v *Vault) MintOTP(item *Item, now time.Time) (*Mint, error) {
	if item.OTP == nil || item.OTP.Config == nil {
		return nil, fmt.Errorf("store: item %q has no second factor configured: %w", item.Name, ErrNotFound)
	}
	if item.EndToEnd {
		return nil, fmt.Errorf("store: %q is end-to-end encrypted, so the server cannot compute codes for it", item.Name)
	}
	if _, ok := item.Fields[SeedField]; !ok {
		return nil, fmt.Errorf("store: item %q has no seed stored", item.Name)
	}
	cfg := item.OTP.Config
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if !cfg.HOTP {
		// A wrong clock produces codes the far end will reject, which looks
		// like a credential failure rather than an operational one. Say so.
		if err := otp.CheckClock(now); err != nil {
			return nil, err
		}
	}

	// Repeat requests inside one time step return the same code. Anything else
	// would either hand out a second distinct code or waste the agent's quota
	// on a retry it did not choose to make.
	step := cfg.Step(now)
	if !cfg.HOTP && item.OTP.LastMint != nil && item.OTP.LastStep == step {
		code, err := v.computeCode(item, step)
		if err != nil {
			return nil, err
		}
		exp := cfg.ExpiresAt(step)
		return &Mint{Code: code, Step: step, ExpiresAt: exp, ValidFor: exp.Sub(now), Reused: true}, nil
	}
	if item.OTP.MinInterval > 0 && item.OTP.LastMint != nil {
		earliest := item.OTP.LastMint.Add(time.Duration(item.OTP.MinInterval) * time.Second)
		if now.Before(earliest) {
			return nil, fmt.Errorf("%w: next code available in %s", ErrMintTooSoon, earliest.Sub(now).Round(time.Second))
		}
	}

	counter := step
	if cfg.HOTP {
		// The counter lives here rather than on the agent, so a compromised
		// agent cannot rewind or race it.
		counter = cfg.Counter
	}
	code, err := v.computeCode(item, counter)
	if err != nil {
		return nil, err
	}

	stamp := now.UTC()
	item.OTP.LastMint = &stamp
	item.OTP.LastStep = step
	item.OTP.MintCount++
	m := &Mint{Code: code, Step: counter}
	if cfg.HOTP {
		cfg.Counter++
		// An HOTP code stays valid until it is used, so we report no expiry
		// beyond the lease itself.
		m.ExpiresAt = time.Time{}
	} else {
		m.ExpiresAt = cfg.ExpiresAt(step)
		m.ValidFor = m.ExpiresAt.Sub(now)
	}
	return m, nil
}

func (v *Vault) computeCode(item *Item, counter uint64) (string, error) {
	seed, err := v.decryptField(item, SeedField)
	if err != nil {
		return "", err
	}
	raw, err := otp.DecodeSecret(seed)
	if err != nil {
		return "", err
	}
	return otp.Code(raw, counter, item.OTP.Config)
}

// ExportSeed returns the raw second-factor seed. Nothing on the agent API can
// reach this; it exists only for the deliberate, loudly audited operator escape
// hatch (migrating a vault, or enrolling a human's authenticator app).
func (v *Vault) ExportSeed(item *Item) (string, error) {
	if item.OTP == nil {
		return "", fmt.Errorf("store: item %q has no second factor: %w", item.Name, ErrNotFound)
	}
	return v.decryptField(item, SeedField)
}
