// Package otp implements HOTP (RFC 4226) and TOTP (RFC 6238).
//
// The reason this lives inside the vault instead of in the client is the whole
// point of ai-auth's second-factor handling: the seed never leaves the server,
// so an agent -- or anything that has compromised an agent -- can only ever
// obtain one short-lived code at a time, under policy and with an audit trail.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm identifies the HMAC hash used by an OTP configuration.
type Algorithm string

// Supported OTP algorithms.
const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

func (a Algorithm) new() (func() hash.Hash, error) {
	switch Algorithm(strings.ToUpper(string(a))) {
	case SHA1, "":
		return sha1.New, nil
	case SHA256:
		return sha256.New, nil
	case SHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("otp: unsupported algorithm %q", a)
	}
}

// Config describes how to derive codes for one item.
type Config struct {
	Algorithm Algorithm `json:"algorithm"`
	Digits    int       `json:"digits"`
	Period    int       `json:"period"` // seconds; TOTP only
	Issuer    string    `json:"issuer,omitempty"`
	Account   string    `json:"account,omitempty"`
	// Counter is used by HOTP only and is incremented by the server on each
	// successful mint. Keeping it server-side is a feature: an agent cannot
	// desynchronise or replay it.
	Counter uint64 `json:"counter,omitempty"`
	HOTP    bool   `json:"hotp,omitempty"`
}

// Normalize fills in RFC defaults and validates the configuration.
func (c *Config) Normalize() error {
	if c.Algorithm == "" {
		c.Algorithm = SHA1
	}
	c.Algorithm = Algorithm(strings.ToUpper(string(c.Algorithm)))
	if _, err := c.Algorithm.new(); err != nil {
		return err
	}
	if c.Digits == 0 {
		c.Digits = 6
	}
	if c.Digits < 6 || c.Digits > 10 {
		return fmt.Errorf("otp: digits must be between 6 and 10, got %d", c.Digits)
	}
	if c.Period == 0 {
		c.Period = 30
	}
	if c.Period < 1 {
		return fmt.Errorf("otp: period must be positive, got %d", c.Period)
	}
	return nil
}

// Step returns the TOTP counter value for the given instant.
func (c *Config) Step(at time.Time) uint64 {
	return uint64(at.Unix()) / uint64(c.Period)
}

// ExpiresAt returns the instant the code for the given step stops being valid.
func (c *Config) ExpiresAt(step uint64) time.Time {
	return time.Unix(int64((step+1)*uint64(c.Period)), 0).UTC()
}

// Code computes the OTP for an explicit counter value.
func Code(secret []byte, counter uint64, cfg *Config) (string, error) {
	newHash, err := cfg.Algorithm.new()
	if err != nil {
		return "", err
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("otp: empty secret")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(newHash, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	// RFC 4226 dynamic truncation.
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < cfg.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", cfg.Digits, truncated%mod), nil
}

// TOTP computes the time-based code for the given instant.
func TOTP(secret []byte, at time.Time, cfg *Config) (string, uint64, error) {
	step := cfg.Step(at)
	code, err := Code(secret, step, cfg)
	return code, step, err
}

// DecodeSecret accepts the base32 encoding used by authenticator apps,
// tolerating lowercase, spaces and missing padding.
func DecodeSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(s)))
	if clean == "" {
		return nil, fmt.Errorf("otp: empty secret")
	}
	if pad := len(clean) % 8; pad != 0 {
		clean += strings.Repeat("=", 8-pad)
	}
	raw, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("otp: secret is not valid base32: %w", err)
	}
	if len(raw) < 10 {
		return nil, fmt.Errorf("otp: secret is only %d bytes; expected at least 10 (RFC 4226 §4 R6)", len(raw))
	}
	return raw, nil
}

// EncodeSecret renders a raw secret as unpadded base32, the form shown by
// enrolment pages.
func EncodeSecret(raw []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
}

// ParseURI reads an otpauth:// enrolment URI, the string behind every 2FA setup
// QR code. This lets an operator paste what the target site displays instead of
// hand-transcribing the seed.
func ParseURI(raw string) ([]byte, *Config, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("otp: parse otpauth uri: %w", err)
	}
	if u.Scheme != "otpauth" {
		return nil, nil, fmt.Errorf("otp: expected an otpauth:// uri, got scheme %q", u.Scheme)
	}
	cfg := &Config{}
	switch strings.ToLower(u.Host) {
	case "totp":
	case "hotp":
		cfg.HOTP = true
	default:
		return nil, nil, fmt.Errorf("otp: unsupported otpauth type %q", u.Host)
	}

	q := u.Query()
	secret, err := DecodeSecret(q.Get("secret"))
	if err != nil {
		return nil, nil, err
	}
	cfg.Algorithm = Algorithm(q.Get("algorithm"))
	cfg.Issuer = q.Get("issuer")
	cfg.Account = strings.TrimPrefix(u.Path, "/")
	if issuer, account, ok := strings.Cut(cfg.Account, ":"); ok {
		if cfg.Issuer == "" {
			cfg.Issuer = issuer
		}
		cfg.Account = account
	}
	for _, f := range []struct {
		key string
		dst *int
	}{{"digits", &cfg.Digits}, {"period", &cfg.Period}} {
		if v := q.Get(f.key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, nil, fmt.Errorf("otp: bad %s parameter %q", f.key, v)
			}
			*f.dst = n
		}
	}
	if v := q.Get("counter"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("otp: bad counter parameter %q", v)
		}
		cfg.Counter = n
	}
	if err := cfg.Normalize(); err != nil {
		return nil, nil, err
	}
	return secret, cfg, nil
}
