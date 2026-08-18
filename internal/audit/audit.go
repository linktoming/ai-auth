// Package audit implements an append-only, hash-chained event log.
//
// Every credential release is recorded. Each record commits to the hash of the
// one before it, so removing or editing any past entry invalidates the chain
// from that point on -- an operator (or an agent that gained file access)
// cannot quietly delete the evidence of a release.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Decision records whether a request was permitted.
type Decision string

// Possible decisions.
const (
	Allow   Decision = "allow"
	Deny    Decision = "deny"
	Pending Decision = "pending"
)

// Record is one entry in the log. Secret values are never stored here; for
// one-time codes we keep only a short digest so a code can be correlated with
// its use without the log itself becoming a credential store.
type Record struct {
	Seq      uint64            `json:"seq"`
	Time     time.Time         `json:"time"`
	Actor    string            `json:"actor"`
	KeyID    string            `json:"key_id,omitempty"`
	Action   string            `json:"action"`
	Item     string            `json:"item,omitempty"`
	Fields   []string          `json:"fields,omitempty"`
	Target   string            `json:"target,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Decision Decision          `json:"decision"`
	Detail   string            `json:"detail,omitempty"`
	LeaseID  string            `json:"lease_id,omitempty"`
	Remote   string            `json:"remote,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Log is a hash-chained log persisted as JSON Lines.
type Log struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	seq      uint64
	lastHash string
}

// GenesisHash anchors the chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Open loads an existing log (verifying it on the way) or creates a new one.
func Open(path string) (*Log, error) {
	l := &Log{path: path, lastHash: GenesisHash}
	if records, err := Read(path); err == nil && len(records) > 0 {
		if err := Verify(records); err != nil {
			return nil, fmt.Errorf("audit: existing log failed verification: %w", err)
		}
		last := records[len(records)-1]
		l.seq, l.lastHash = last.Seq, last.Hash
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log: %w", err)
	}
	l.file = f
	return l, nil
}

// Append chains and writes a record. The record is flushed to disk before the
// call returns so a crash cannot lose the evidence of a release that already
// happened.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	r.Seq = l.seq
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	r.Time = r.Time.UTC().Truncate(time.Millisecond)
	r.PrevHash = l.lastHash
	h, err := hashRecord(r)
	if err != nil {
		l.seq--
		return Record{}, err
	}
	r.Hash = h

	line, err := json.Marshal(r)
	if err != nil {
		l.seq--
		return Record{}, fmt.Errorf("audit: marshal record: %w", err)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		l.seq--
		return Record{}, fmt.Errorf("audit: write record: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return Record{}, fmt.Errorf("audit: sync log: %w", err)
	}
	l.lastHash = r.Hash
	return r, nil
}

// Close releases the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Read loads every record from a log file.
func Read(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("audit: malformed record at line %d: %w", len(out)+1, err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read log: %w", err)
	}
	return out, nil
}

// Verify walks the chain and reports the first inconsistency it finds.
func Verify(records []Record) error {
	prev := GenesisHash
	for i, r := range records {
		if r.Seq != uint64(i+1) {
			return fmt.Errorf("audit: record %d has sequence %d (expected %d): a record was removed or reordered", i+1, r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("audit: record %d does not chain to its predecessor: the log was edited or truncated", r.Seq)
		}
		want, err := hashRecord(r)
		if err != nil {
			return err
		}
		if want != r.Hash {
			return fmt.Errorf("audit: record %d has been modified (hash mismatch)", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// VerifyFile verifies a log on disk and returns the records it contains.
func VerifyFile(path string) ([]Record, error) {
	records, err := Read(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return records, Verify(records)
}

// hashRecord computes the chain hash over every field except Hash itself.
// json.Marshal on a struct emits fields in declaration order, which gives us a
// stable encoding without needing a separate canonicalisation step.
func hashRecord(r Record) (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("audit: hash record: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// CodeDigest returns the short, non-reversible marker recorded in place of a
// one-time code, so a log reader can tie an audit entry to a specific code
// without the log ever containing the code itself.
func CodeDigest(item, code string, step uint64) string {
	h := sha256.New()
	fmt.Fprintf(h, "ai-auth-code-digest-v1|%s|%d|%s", item, step, code)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
