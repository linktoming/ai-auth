package seal

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Handshake overview
//
//	client                                         server
//	  |-- fingerprint, client_epk, client_nonce ---->|
//	  |<-- session_id, server_epk, server_nonce -----|
//	  |                                              |
//	  |  both sides compute the transcript T and     |
//	  |  the ECDH secret; client signs T with its    |
//	  |  SSH key (ssh-agent does this, so the        |
//	  |  private key never leaves the agent)         |
//	  |-- signature(T) ----------------------------->|
//	  |<-- bearer token ------------------------------|
//
// Signing the transcript -- which contains BOTH ephemeral public keys -- is
// what binds the SSH identity to the ephemeral channel. An attacker who
// substitutes their own ephemeral key changes T, so the signature no longer
// verifies. From then on every secret value travels sealed under keys that
// only the two endpoints hold, independently of (and underneath) TLS.

// TranscriptLabel is the domain separator for handshake signatures. Changing
// the protocol means changing this string, so signatures can never be replayed
// across versions.
const TranscriptLabel = "ai-auth-handshake-v1"

// NonceSize is the size of the handshake nonces contributed by each side.
const NonceSize = 32

// Session holds the directional keys derived from a completed handshake.
type Session struct {
	ClientToServer []byte
	ServerToClient []byte
}

// Ephemeral is one side's contribution to the handshake.
type Ephemeral struct {
	priv  *ecdh.PrivateKey
	Pub   []byte
	Nonce []byte
}

// NewEphemeral generates a fresh X25519 keypair and nonce. The keypair is used
// once and discarded, which is what gives the channel forward secrecy: stealing
// the agent's SSH key later does not decrypt recorded traffic.
func NewEphemeral() (*Ephemeral, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("seal: generate ephemeral key: %w", err)
	}
	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	return &Ephemeral{priv: priv, Pub: priv.PublicKey().Bytes(), Nonce: nonce}, nil
}

// Derive completes the handshake against the peer's ephemeral public key.
// clientNonce and clientPub always come first in the key schedule so both sides
// agree regardless of who is calling.
func (e *Ephemeral) Derive(peerPub, clientNonce, serverNonce []byte) (*Session, error) {
	if len(peerPub) != 32 {
		return nil, errors.New("seal: peer ephemeral key must be 32 bytes")
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("seal: bad peer ephemeral key: %w", err)
	}
	shared, err := e.priv.ECDH(pub)
	if err != nil {
		// A low-order peer key lands here; X25519 in crypto/ecdh rejects
		// all-zero outputs for us.
		return nil, fmt.Errorf("seal: ecdh failed: %w", err)
	}
	salt := append(append([]byte{}, clientNonce...), serverNonce...)
	c2s, err := derive(shared, salt, TranscriptLabel+" c2s")
	if err != nil {
		return nil, err
	}
	s2c, err := derive(shared, salt, TranscriptLabel+" s2c")
	if err != nil {
		return nil, err
	}
	return &Session{ClientToServer: c2s, ServerToClient: s2c}, nil
}

// SealToClient encrypts a payload the client will open with OpenFromServer.
func (s *Session) SealToClient(plaintext, aad []byte) ([]byte, error) {
	return Encrypt(s.ServerToClient, plaintext, aad)
}

// OpenFromServer decrypts a payload produced by SealToClient.
func (s *Session) OpenFromServer(blob, aad []byte) ([]byte, error) {
	return Decrypt(s.ServerToClient, blob, aad)
}

// SealToServer encrypts a payload the server will open with OpenFromClient.
// Admins use this to upload secret material without it ever appearing in
// plaintext on the wire or in a proxy log.
func (s *Session) SealToServer(plaintext, aad []byte) ([]byte, error) {
	return Encrypt(s.ClientToServer, plaintext, aad)
}

// OpenFromClient decrypts a payload produced by SealToServer.
func (s *Session) OpenFromClient(blob, aad []byte) ([]byte, error) {
	return Decrypt(s.ClientToServer, blob, aad)
}

// Transcript builds the exact byte string both sides sign over. Every field is
// length-prefixed so no two distinct inputs can produce the same transcript.
func Transcript(serverID, sessionID, fingerprint string, clientPub, clientNonce, serverPub, serverNonce []byte) []byte {
	var out []byte
	write := func(b []byte) {
		// An 8-byte prefix cannot wrap for any Go slice, so this encoding stays
		// injective whatever a caller passes. A 32-bit prefix would in principle
		// let a field of 2^32+n bytes present the same length as one of n, which
		// is exactly the collision the length prefixing exists to prevent.
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b))) //#nosec G115 -- len is never negative
		out = append(out, l[:]...)
		out = append(out, b...)
	}
	write([]byte(TranscriptLabel))
	write([]byte(serverID))
	write([]byte(sessionID))
	write([]byte(fingerprint))
	write(clientPub)
	write(clientNonce)
	write(serverPub)
	write(serverNonce)
	return out
}
