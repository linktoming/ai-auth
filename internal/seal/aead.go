// Package seal provides the confidentiality primitives used by ai-auth:
// authenticated encryption at rest, an ephemeral X25519 handshake that gives
// every session its own end-to-end keys, and key wrapping to SSH public keys.
package seal

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the size of every symmetric key in the system.
const KeySize = 32

// ErrDecrypt is returned for any authentication failure. It is deliberately
// opaque: callers must not be able to distinguish "wrong key" from
// "tampered ciphertext".
var ErrDecrypt = errors.New("seal: decryption failed")

// Encrypt seals plaintext with XChaCha20-Poly1305 under key, binding aad.
// The 24-byte random nonce is prepended to the ciphertext.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: read entropy: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt opens a ciphertext produced by Encrypt.
func Decrypt(key, blob, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// RandomKey returns a fresh 32-byte key.
func RandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("seal: read entropy: %w", err)
	}
	return k, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("seal: read entropy: %w", err)
	}
	return b, nil
}

// derive runs HKDF-SHA256 and returns a 32-byte key.
func derive(secret, salt []byte, info string) ([]byte, error) {
	k, err := hkdf.Key(sha256.New, secret, salt, info, KeySize)
	if err != nil {
		return nil, fmt.Errorf("seal: derive %s: %w", info, err)
	}
	return k, nil
}
