package sshid

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// Ed25519 and X25519 use the same underlying curve in different coordinate
// systems, so an ed25519 SSH key can be reused as an X25519 key-agreement key
// via the standard birational map. This is the same trick `age` uses for its
// ssh-ed25519 recipients, and it is what lets an operator encrypt a secret to
// an agent's existing SSH public key.
//
// Note the usual caveat: reusing one key for both signing and key agreement is
// only safe because both schemes are domain-separated and neither exposes the
// other's oracle. We keep the two uses distinct (auth = signatures over a
// versioned transcript; wrapping = ECDH with a fresh ephemeral key).

var (
	// p = 2^255 - 19
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	one    = big.NewInt(1)
)

// ErrNotEd25519 is returned when a key cannot be converted to X25519.
var ErrNotEd25519 = errors.New("sshid: only ed25519 keys can be converted to X25519")

// Ed25519PublicToX25519 maps an Edwards y-coordinate to a Montgomery
// u-coordinate: u = (1 + y) / (1 - y) mod p.
func Ed25519PublicToX25519(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrNotEd25519
	}
	// The encoding is little-endian y with the x sign in the top bit.
	le := make([]byte, ed25519.PublicKeySize)
	copy(le, pub)
	le[31] &= 0x7f
	y := new(big.Int).SetBytes(reverse(le))
	if y.Cmp(fieldP) >= 0 {
		return nil, errors.New("sshid: ed25519 public key is not canonical")
	}

	denom := new(big.Int).Sub(one, y)
	denom.Mod(denom, fieldP)
	if denom.Sign() == 0 {
		return nil, errors.New("sshid: ed25519 public key maps to the point at infinity")
	}
	inv := new(big.Int).ModInverse(denom, fieldP)
	if inv == nil {
		return nil, errors.New("sshid: ed25519 public key is not invertible")
	}
	u := new(big.Int).Add(one, y)
	u.Mul(u, inv)
	u.Mod(u, fieldP)

	out := make([]byte, 32)
	b := u.Bytes()
	copy(out[32-len(b):], b)
	return reverse(out), nil
}

// Ed25519PrivateToX25519 derives the X25519 scalar from an ed25519 seed,
// exactly as RFC 8032 key generation does before clamping.
func Ed25519PrivateToX25519(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrNotEd25519
	}
	h := sha512.Sum512(priv.Seed())
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar, nil
}

// SSHPublicKeyToEd25519 extracts the raw ed25519 key from an SSH public key.
func SSHPublicKeyToEd25519(pub ssh.PublicKey) (ed25519.PublicKey, error) {
	ck, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, ErrNotEd25519
	}
	edPub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w (got %s)", ErrNotEd25519, pub.Type())
	}
	return edPub, nil
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}
