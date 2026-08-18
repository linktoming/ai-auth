package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainDetectsEveryKindOfTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, action := range []string{"handshake", "read", "totp", "release"} {
		if _, err := log.Append(Record{Actor: "bot", Action: action, Decision: Allow, Item: "prod/db", Seq: uint64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	base, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("a freshly written log must verify: %v", err)
	}
	if len(base) != 4 {
		t.Fatalf("got %d records", len(base))
	}

	t.Run("edit", func(t *testing.T) {
		records := clone(base)
		records[1].Actor = "someone-else"
		mustFail(t, Verify(records), "modified")
	})
	t.Run("delete", func(t *testing.T) {
		records := append(clone(base)[:1], clone(base)[2:]...)
		mustFail(t, Verify(records), "removed or reordered")
	})
	t.Run("reorder", func(t *testing.T) {
		records := clone(base)
		records[1], records[2] = records[2], records[1]
		mustFail(t, Verify(records), "")
	})
	t.Run("truncate-and-reappend", func(t *testing.T) {
		// Dropping the tail and writing a different record in its place still
		// breaks the chain, because the replacement cannot reproduce the hash.
		records := clone(base)[:3]
		forged := base[3]
		forged.Actor = "ghost"
		forged.Hash = base[3].Hash
		mustFail(t, Verify(append(records, forged)), "modified")
	})
}

func TestAppendResumesAnExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := log.Append(Record{Actor: "a", Action: "read", Decision: Allow})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must continue the chain rather than restarting it, or a restart
	// would silently orphan everything written before it.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Append(Record{Actor: "b", Action: "read", Decision: Allow})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if second.Seq != first.Seq+1 {
		t.Fatalf("sequence restarted: %d then %d", first.Seq, second.Seq)
	}
	if second.PrevHash != first.Hash {
		t.Fatal("the chain did not continue across a restart")
	}
	if _, err := VerifyFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesACorruptedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := log.Append(Record{Actor: "a", Action: "read", Decision: Allow}); err != nil {
			t.Fatal(err)
		}
	}
	log.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Truncation alone still verifies -- the surviving prefix is intact -- but
	// an edit must stop the server from starting on top of it.
	if _, err := Open(path); err != nil {
		t.Fatalf("a truncated but self-consistent log should still open: %v", err)
	}
	edited := strings.Replace(lines[0], `"actor":"a"`, `"actor":"z"`, 1)
	if err := os.WriteFile(path, []byte(edited+"\n"+lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("opening a tampered log must fail")
	}
}

func TestCodeDigestHidesTheCode(t *testing.T) {
	d := CodeDigest("prod/db", "123456", 42)
	if strings.Contains(d, "123456") || len(d) != 16 {
		t.Fatalf("digest = %q", d)
	}
	if CodeDigest("prod/db", "123456", 42) != d {
		t.Fatal("the digest must be deterministic")
	}
	for _, other := range []string{
		CodeDigest("prod/db", "123457", 42),
		CodeDigest("prod/db", "123456", 43),
		CodeDigest("other", "123456", 42),
	} {
		if other == d {
			t.Fatal("digests must differ when any input differs")
		}
	}
}

func clone(in []Record) []Record {
	out := make([]Record, len(in))
	copy(out, in)
	return out
}

func mustFail(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected verification to fail")
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not mention %q", err, contains)
	}
}
