package seal

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/linktoming/ai-auth/internal/sshid"
)

// Wrapping schemes.
const (
	SchemeX25519 = "x25519-hkdf-sha256+xchacha20poly1305"
	SchemeRSAOAEP = "rsa-oaep-sha256"
)

// WrappedKey is a data key encrypted to one recipient's SSH public key.
// It is the mechanism behind end-to-end items: the server stores these blobs
// but holds no key that can open them.
type WrappedKey struct {
	Fingerprint  string `json:"fingerprint"`
	Scheme       string `json:"scheme"`
	EphemeralPub []byte `json:"ephemeral_pub,omitempty"`
	Ciphertext   []byte `json:"ciphertext"`
}

const wrapInfo = "ai-auth-key-wrap-v1"

// WrapToSSHKey encrypts dek so that only the holder of pub's private key can
// recover it.
func WrapToSSHKey(pub ssh.PublicKey, dek []byte) (*WrappedKey, error) {
	fp := sshid.Fingerprint(pub)
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		edPub, err := sshid.SSHPublicKeyToEd25519(pub)
		if err != nil {
			return nil, err
		}
		recipient, err := sshid.Ed25519PublicToX25519(edPub)
		if err != nil {
			return nil, err
		}
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("seal: generate wrap key: %w", err)
		}
		rPub, err := ecdh.X25519().NewPublicKey(recipient)
		if err != nil {
			return nil, fmt.Errorf("seal: recipient key: %w", err)
		}
		shared, err := eph.ECDH(rPub)
		if err != nil {
			return nil, fmt.Errorf("seal: wrap ecdh: %w", err)
		}
		ephPub := eph.PublicKey().Bytes()
		kek, err := derive(shared, wrapSalt(ephPub, recipient), wrapInfo)
		if err != nil {
			return nil, err
		}
		ct, err := Encrypt(kek, dek, []byte(fp))
		if err != nil {
			return nil, err
		}
		return &WrappedKey{Fingerprint: fp, Scheme: SchemeX25519, EphemeralPub: ephPub, Ciphertext: ct}, nil

	case ssh.KeyAlgoRSA:
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return nil, errors.New("seal: rsa key does not expose crypto.PublicKey")
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("seal: malformed rsa key")
		}
		ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rk, dek, []byte(fp))
		if err != nil {
			return nil, fmt.Errorf("seal: rsa wrap: %w", err)
		}
		return &WrappedKey{Fingerprint: fp, Scheme: SchemeRSAOAEP, Ciphertext: ct}, nil

	default:
		return nil, fmt.Errorf("seal: key type %s cannot be used for end-to-end items (use ed25519 or rsa)", pub.Type())
	}
}

// UnwrapWithSSHKey recovers a data key using the recipient's private key.
// Note this needs the raw private key: ssh-agent can sign but cannot perform
// key agreement, so end-to-end items require --identity rather than the agent.
func UnwrapWithSSHKey(priv crypto.PrivateKey, w *WrappedKey) ([]byte, error) {
	if w == nil {
		return nil, errors.New("seal: nil wrapped key")
	}
	switch w.Scheme {
	case SchemeX25519:
		edPriv, ok := normalizeEd25519(priv)
		if !ok {
			return nil, errors.New("seal: wrapped key needs an ed25519 identity")
		}
		scalar, err := sshid.Ed25519PrivateToX25519(edPriv)
		if err != nil {
			return nil, err
		}
		x, err := ecdh.X25519().NewPrivateKey(scalar)
		if err != nil {
			return nil, fmt.Errorf("seal: derive x25519 key: %w", err)
		}
		ephPub, err := ecdh.X25519().NewPublicKey(w.EphemeralPub)
		if err != nil {
			return nil, fmt.Errorf("seal: bad ephemeral key: %w", err)
		}
		shared, err := x.ECDH(ephPub)
		if err != nil {
			return nil, fmt.Errorf("seal: unwrap ecdh: %w", err)
		}
		kek, err := derive(shared, wrapSalt(w.EphemeralPub, x.PublicKey().Bytes()), wrapInfo)
		if err != nil {
			return nil, err
		}
		return Decrypt(kek, w.Ciphertext, []byte(w.Fingerprint))

	case SchemeRSAOAEP:
		rk, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("seal: wrapped key needs an rsa identity")
		}
		dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rk, w.Ciphertext, []byte(w.Fingerprint))
		if err != nil {
			return nil, ErrDecrypt
		}
		return dek, nil

	default:
		return nil, fmt.Errorf("seal: unknown wrap scheme %q", w.Scheme)
	}
}

// wrapSalt binds the derived key to both the ephemeral and recipient keys, so a
// wrapped key cannot be replayed against a different recipient.
func wrapSalt(ephPub, recipientPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(wrapInfo))
	h.Write(ephPub)
	h.Write(recipientPub)
	return h.Sum(nil)
}

func normalizeEd25519(priv crypto.PrivateKey) (ed25519.PrivateKey, bool) {
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		return k, true
	case *ed25519.PrivateKey:
		return *k, true
	default:
		return nil, false
	}
}
