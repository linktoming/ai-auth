// Package sshid handles SSH identities: parsing keys, computing fingerprints,
// obtaining signers (from ssh-agent or a key file) and verifying signatures.
//
// The design goal is that an AI agent's only long-lived secret is an ordinary
// SSH private key -- ideally one it never touches directly, held by ssh-agent.
package sshid

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrNoSigner is returned when no usable private key could be located.
var ErrNoSigner = errors.New("sshid: no usable ssh identity found")

// ParseAuthorizedKey parses a single authorized_keys line.
func ParseAuthorizedKey(line string) (ssh.PublicKey, string, error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return nil, "", fmt.Errorf("sshid: parse public key: %w", err)
	}
	if err := checkKeyStrength(pub); err != nil {
		return nil, "", err
	}
	return pub, comment, nil
}

// checkKeyStrength rejects key types and sizes we are not willing to trust.
func checkKeyStrength(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return nil
	case ssh.KeyAlgoRSA:
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("sshid: rsa key does not expose crypto.PublicKey")
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return errors.New("sshid: malformed rsa key")
		}
		if rk.N.BitLen() < 3072 {
			return fmt.Errorf("sshid: rsa key too small (%d bits, need >= 3072); prefer ed25519", rk.N.BitLen())
		}
		return nil
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		// Usable for authentication, but not for key wrapping.
		return nil
	default:
		return fmt.Errorf("sshid: unsupported key type %q (use ed25519)", pub.Type())
	}
}

// Fingerprint returns the standard OpenSSH SHA256 fingerprint ("SHA256:...").
func Fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }

// MarshalAuthorizedKey renders a public key as a single authorized_keys line.
func MarshalAuthorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// Verify checks a signature produced by Sign over msg.
func Verify(pub ssh.PublicKey, msg []byte, sig *ssh.Signature) error {
	if sig == nil {
		return errors.New("sshid: nil signature")
	}
	// Reject the legacy SHA-1 RSA algorithm outright.
	if sig.Format == ssh.KeyAlgoRSA {
		return errors.New("sshid: ssh-rsa (SHA-1) signatures are not accepted; use rsa-sha2-256/512")
	}
	return pub.Verify(msg, sig)
}

// Sign produces a signature over msg, preferring SHA-2 for RSA keys.
func Sign(signer ssh.Signer, msg []byte) (*ssh.Signature, error) {
	if as, ok := signer.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		return as.SignWithAlgorithm(rand.Reader, msg, ssh.KeyAlgoRSASHA512)
	}
	return signer.Sign(rand.Reader, msg)
}

// AgentSigners returns the signers offered by the ssh-agent at $SSH_AUTH_SOCK.
// The private key never leaves the agent; we only ever ask it to sign.
func AgentSigners() ([]ssh.Signer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("sshid: SSH_AUTH_SOCK is not set")
	}
	// The path comes from the caller's own SSH_AUTH_SOCK and is a unix domain
	// socket, not a network address; there is no request to forge.
	conn, err := net.Dial("unix", sock) //#nosec G704 -- unix socket from the caller's own environment
	if err != nil {
		return nil, fmt.Errorf("sshid: dial ssh-agent: %w", err)
	}
	return agent.NewClient(conn).Signers()
}

// LoadIdentityFile reads an OpenSSH private key from disk, decrypting it with
// passphrase if necessary.
func LoadIdentityFile(path string, passphrase []byte) (ssh.Signer, crypto.PrivateKey, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- the operator names their own identity file
	if err != nil {
		return nil, nil, fmt.Errorf("sshid: read identity: %w", err)
	}
	var key any
	if len(passphrase) > 0 {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, passphrase)
	} else {
		key, err = ssh.ParseRawPrivateKey(raw)
	}
	if err != nil {
		var mErr *ssh.PassphraseMissingError
		if errors.As(err, &mErr) {
			return nil, nil, fmt.Errorf("sshid: %s is passphrase protected (set AI_AUTH_IDENTITY_PASSPHRASE or use ssh-agent)", path)
		}
		return nil, nil, fmt.Errorf("sshid: parse identity: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("sshid: build signer: %w", err)
	}
	return signer, key, nil
}

// SelectSigner returns a signer for the requested fingerprint. If fingerprint
// is empty and exactly one identity is available, that one is used.
func SelectSigner(signers []ssh.Signer, fingerprint string) (ssh.Signer, error) {
	if len(signers) == 0 {
		return nil, ErrNoSigner
	}
	if fingerprint == "" {
		if len(signers) == 1 {
			return signers[0], nil
		}
		return nil, fmt.Errorf("sshid: %d identities available; specify one with --fingerprint", len(signers))
	}
	for _, s := range signers {
		if Fingerprint(s.PublicKey()) == fingerprint {
			return s, nil
		}
	}
	return nil, fmt.Errorf("sshid: no identity matching %s", fingerprint)
}

// GenerateEd25519 creates a new OpenSSH-format ed25519 keypair.
func GenerateEd25519(comment string) (privPEM []byte, pubLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	line := MarshalAuthorizedKey(sshPub)
	if comment != "" {
		line += " " + comment
	}
	return pem.EncodeToMemory(block), line, nil
}
