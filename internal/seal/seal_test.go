package seal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/linktoming/ai-auth/internal/sshid"
)

func TestEncryptRoundTripAndAADBinding(t *testing.T) {
	key, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(key, []byte("hunter2"), []byte("item/password"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(key, ct, []byte("item/password"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hunter2" {
		t.Fatalf("got %q", pt)
	}
	// Same ciphertext under a different AAD must not open: this is what stops a
	// stored password blob from being replayed as a different field.
	if _, err := Decrypt(key, ct, []byte("item/username")); err == nil {
		t.Fatal("expected AAD mismatch to fail")
	}
	// Flipping any byte must fail.
	bad := bytes.Clone(ct)
	bad[len(bad)-1] ^= 0x01
	if _, err := Decrypt(key, bad, []byte("item/password")); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestHandshakeDerivesMatchingKeys(t *testing.T) {
	client, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := client.Derive(server.Pub, client.Nonce, server.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := server.Derive(client.Pub, client.Nonce, server.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cs.ServerToClient, ss.ServerToClient) || !bytes.Equal(cs.ClientToServer, ss.ClientToServer) {
		t.Fatal("session keys diverge")
	}
	if bytes.Equal(cs.ClientToServer, cs.ServerToClient) {
		t.Fatal("directional keys must differ")
	}

	blob, err := ss.SealToClient([]byte("s3cret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cs.OpenFromServer(blob, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("got %q", got)
	}
}

func TestTranscriptIsUnambiguous(t *testing.T) {
	// Length prefixing must prevent field-boundary confusion: "ab"+"c" and
	// "a"+"bc" must not hash to the same transcript.
	a := Transcript("srv", "ab", "c", nil, nil, nil, nil)
	b := Transcript("srv", "a", "bc", nil, nil, nil, nil)
	if bytes.Equal(a, b) {
		t.Fatal("transcript is ambiguous across field boundaries")
	}
}

func TestWrapToEd25519SSHKey(t *testing.T) {
	privPEM, pubLine, err := sshid.GenerateEd25519("agent@test")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := sshid.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	w, err := WrapToSSHKey(pub, dek)
	if err != nil {
		t.Fatal(err)
	}
	if w.Fingerprint != sshid.Fingerprint(pub) {
		t.Fatal("fingerprint mismatch")
	}

	raw, err := ssh.ParseRawPrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapWithSSHKey(raw, w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped dek mismatch")
	}

	// A different identity must not be able to unwrap.
	otherPEM, _, err := sshid.GenerateEd25519("other@test")
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, err := ssh.ParseRawPrivateKey(otherPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapWithSSHKey(otherRaw, w); err == nil {
		t.Fatal("wrong identity must not unwrap")
	}
}

func TestWrapToRSASSHKey(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	w, err := WrapToSSHKey(pub, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapWithSSHKey(rk, w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("rsa unwrapped dek mismatch")
	}
}

func TestSignAndVerifyOverTranscript(t *testing.T) {
	privPEM, pubLine, err := sshid.GenerateEd25519("agent@test")
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err := loadSigner(t, privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := sshid.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	msg := Transcript("srv", "sess", sshid.Fingerprint(pub), []byte{1}, []byte{2}, []byte{3}, []byte{4})
	sig, err := sshid.Sign(signer, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshid.Verify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	// A transcript with a substituted ephemeral key must fail: this is the
	// property that stops a man in the middle from hijacking the channel.
	tampered := Transcript("srv", "sess", sshid.Fingerprint(pub), []byte{1}, []byte{2}, []byte{9}, []byte{4})
	if err := sshid.Verify(pub, tampered, sig); err == nil {
		t.Fatal("signature must not verify over a different transcript")
	}
}

func loadSigner(t *testing.T, pem []byte) (ssh.Signer, any, error) {
	t.Helper()
	key, err := ssh.ParseRawPrivateKey(pem)
	if err != nil {
		return nil, nil, err
	}
	s, err := ssh.NewSignerFromKey(key)
	return s, key, err
}
