package otp

import (
	"errors"
	"math"
	"testing"
	"time"
)

// RFC 4226 Appendix D test vectors, secret "12345678901234567890".
func TestHOTPRFC4226Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cfg := &Config{}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	for counter, expect := range want {
		got, err := Code(secret, uint64(counter), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got != expect {
			t.Errorf("counter %d: got %s, want %s", counter, got, expect)
		}
	}
}

// RFC 6238 Appendix B test vectors. The seeds are the ASCII string
// "12345678901234567890" repeated to the length each algorithm requires.
func TestTOTPRFC6238Vectors(t *testing.T) {
	base := "12345678901234567890"
	seed := func(n int) []byte {
		out := make([]byte, 0, n)
		for len(out) < n {
			out = append(out, base...)
		}
		return out[:n]
	}
	cases := []struct {
		unix int64
		alg  Algorithm
		want string
	}{
		{59, SHA1, "94287082"},
		{59, SHA256, "46119246"},
		{59, SHA512, "90693936"},
		{1111111109, SHA1, "07081804"},
		{1111111111, SHA1, "14050471"},
		{1234567890, SHA1, "89005924"},
		{2000000000, SHA1, "69279037"},
		{20000000000, SHA1, "65353130"},
		{1111111109, SHA256, "68084774"},
		{1234567890, SHA512, "93441116"},
		{1111111111, SHA256, "67062674"},
		{2000000000, SHA512, "38618901"},
		{20000000000, SHA256, "77737706"},
		{20000000000, SHA512, "47863826"},
	}
	sizes := map[Algorithm]int{SHA1: 20, SHA256: 32, SHA512: 64}
	for _, tc := range cases {
		cfg := &Config{Algorithm: tc.alg, Digits: 8, Period: 30}
		if err := cfg.Normalize(); err != nil {
			t.Fatal(err)
		}
		got, _, err := TOTP(seed(sizes[tc.alg]), time.Unix(tc.unix, 0).UTC(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("t=%d alg=%s: got %s, want %s", tc.unix, tc.alg, got, tc.want)
		}
	}
}

func TestStepAndExpiry(t *testing.T) {
	cfg := &Config{Period: 30}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_000_000_037, 0).UTC()
	step := cfg.Step(at)
	if step != 33333334 {
		t.Fatalf("step = %d", step)
	}
	exp := cfg.ExpiresAt(step)
	if !exp.After(at) || exp.Sub(at) > 30*time.Second {
		t.Fatalf("expiry %s is not within the step containing %s", exp, at)
	}
}

func TestDecodeSecretTolerance(t *testing.T) {
	// Authenticator enrolment pages show grouped, unpadded, lowercase base32.
	for _, in := range []string{
		"JBSWY3DPEHPK3PXP",
		"jbswy3dp ehpk3pxp",
		"JBSW Y3DP EHPK 3PXP",
		"JBSWY3DP-EHPK3PXP",
	} {
		got, err := DecodeSecret(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if EncodeSecret(got) != "JBSWY3DPEHPK3PXP" {
			t.Fatalf("%q round-tripped to %q", in, EncodeSecret(got))
		}
	}
	if _, err := DecodeSecret("SHORT"); err == nil {
		t.Fatal("expected short secrets to be rejected")
	}
	if _, err := DecodeSecret("not-base32-!!!"); err == nil {
		t.Fatal("expected invalid base32 to be rejected")
	}
}

func TestParseURI(t *testing.T) {
	secret, cfg, err := ParseURI("otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60")
	if err != nil {
		t.Fatal(err)
	}
	if EncodeSecret(secret) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secret = %s", EncodeSecret(secret))
	}
	if cfg.Issuer != "ACME Co" || cfg.Account != "alice@example.com" {
		t.Fatalf("issuer/account = %q/%q", cfg.Issuer, cfg.Account)
	}
	if cfg.Algorithm != SHA256 || cfg.Digits != 8 || cfg.Period != 60 {
		t.Fatalf("cfg = %+v", cfg)
	}

	// The label carries the issuer when there is no explicit issuer parameter.
	_, cfg2, err := ParseURI("otpauth://hotp/GitHub:bob?secret=JBSWY3DPEHPK3PXP&counter=7")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg2.HOTP || cfg2.Counter != 7 || cfg2.Issuer != "GitHub" || cfg2.Account != "bob" {
		t.Fatalf("cfg = %+v", cfg2)
	}

	if _, _, err := ParseURI("https://example.com"); err == nil {
		t.Fatal("expected non-otpauth uri to be rejected")
	}
}

func TestUnusableClockIsRejectedRatherThanWrapped(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	secret := []byte("12345678901234567890")

	// A pre-epoch clock used to wrap into a huge counter and yield a
	// plausible-looking code that no verifier would ever accept.
	for _, at := range []time.Time{
		time.Unix(-1, 0),
		time.Unix(0, 0),
		time.Date(1969, 7, 20, 20, 17, 0, 0, time.UTC),
	} {
		if _, _, err := TOTP(secret, at, cfg); !errors.Is(err, ErrClockUnusable) {
			t.Errorf("TOTP at %s: expected ErrClockUnusable, got %v", at, err)
		}
		if step := cfg.Step(at); step != 0 {
			t.Errorf("Step at %s = %d, want 0", at, step)
		}
	}

	if err := CheckClock(time.Unix(1, 0)); err != nil {
		t.Fatalf("a positive clock must be usable: %v", err)
	}
}

func TestExpiresAtRefusesUnrepresentableSteps(t *testing.T) {
	cfg := &Config{Period: 30}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	// A step this large cannot be turned into a Unix time. Returning the zero
	// time is what the API renders as "no expiry"; wrapping would produce a
	// date in the past and make a live code look expired.
	if got := cfg.ExpiresAt(math.MaxUint64); !got.IsZero() {
		t.Fatalf("ExpiresAt(MaxUint64) = %s, want the zero time", got)
	}
	if got := cfg.ExpiresAt(uint64(math.MaxInt64/30) + 1); !got.IsZero() {
		t.Fatalf("ExpiresAt past the representable range = %s, want the zero time", got)
	}
	// A realistic step still round-trips.
	step := cfg.Step(time.Unix(1_700_000_000, 0))
	if exp := cfg.ExpiresAt(step); exp.Unix() != int64(step+1)*30 {
		t.Fatalf("ExpiresAt(%d) = %s", step, exp)
	}
}
