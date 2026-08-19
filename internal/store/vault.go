package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/linktoming/ai-auth/internal/seal"
)

// ErrNotFound is returned when a named record does not exist.
var ErrNotFound = errors.New("not found")

// ErrSealed is returned when an operation needs the root key and the vault has
// not been unsealed.
var ErrSealed = errors.New("vault is sealed")

// KDFParams records how a passphrase is stretched into the root key. The
// parameters live next to the vault so it can be reopened on another machine.
type KDFParams struct {
	Algorithm string `json:"algorithm"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultKDF returns Argon2id parameters sized for an interactive unseal.
func DefaultKDF(salt []byte) *KDFParams {
	return &KDFParams{Algorithm: "argon2id", Salt: salt, Time: 3, Memory: 256 * 1024, Threads: 4}
}

// Derive stretches a passphrase into a root key.
func (k *KDFParams) Derive(passphrase []byte) ([]byte, error) {
	if k.Algorithm != "argon2id" {
		return nil, fmt.Errorf("store: unsupported kdf %q", k.Algorithm)
	}
	return argon2.IDKey(passphrase, k.Salt, k.Time, k.Memory, k.Threads, seal.KeySize), nil
}

// rootCheckPlaintext is encrypted under the root key at initialisation so a
// wrong key is detected at unseal time rather than at first decrypt.
const rootCheckPlaintext = "ai-auth root key check v1"

// Data is the serialised vault.
type Data struct {
	FormatVersion int                  `json:"format_version"`
	ServerID      string               `json:"server_id"`
	CreatedAt     time.Time            `json:"created_at"`
	KDF           *KDFParams           `json:"kdf,omitempty"`
	RootCheck     []byte               `json:"root_check"`
	Agents        map[string]*Agent    `json:"agents"`
	Items         map[string]*Item     `json:"items"`
	Grants        map[string]*Grant    `json:"grants"`
	Counters      map[string]*Counter  `json:"counters"`
	Leases        map[string]*Lease    `json:"leases"`
	Approvals     map[string]*Approval `json:"approvals"`
}

// Vault is a file-backed store guarded by a mutex. Callers must hold Lock or
// RLock for the duration of a read-modify-write cycle.
type Vault struct {
	mu   sync.RWMutex
	path string
	data *Data
	root []byte
}

// Create initialises a new vault file. rootKey may be nil when kdf is supplied,
// in which case the caller must pass the derived key.
func Create(path, serverID string, rootKey []byte, kdf *KDFParams) (*Vault, error) {
	if len(rootKey) != seal.KeySize {
		return nil, fmt.Errorf("store: root key must be %d bytes", seal.KeySize)
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("store: %s already exists", path)
	}
	check, err := seal.Encrypt(rootKey, []byte(rootCheckPlaintext), []byte(serverID))
	if err != nil {
		return nil, err
	}
	v := &Vault{
		path: path,
		root: rootKey,
		data: &Data{
			FormatVersion: FormatVersion,
			ServerID:      serverID,
			CreatedAt:     time.Now().UTC(),
			KDF:           kdf,
			RootCheck:     check,
			Agents:        map[string]*Agent{},
			Items:         map[string]*Item{},
			Grants:        map[string]*Grant{},
			Counters:      map[string]*Counter{},
			Leases:        map[string]*Lease{},
			Approvals:     map[string]*Approval{},
		},
	}
	return v, v.Save()
}

// Load reads a vault file without unsealing it.
func Load(path string) (*Vault, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- vault path is operator configuration, not user input
	if err != nil {
		return nil, fmt.Errorf("store: read vault: %w", err)
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("store: parse vault: %w", err)
	}
	if d.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("store: vault format version %d is not supported (this build understands %d)", d.FormatVersion, FormatVersion)
	}
	for _, m := range []*map[string]*Agent{&d.Agents} {
		if *m == nil {
			*m = map[string]*Agent{}
		}
	}
	if d.Items == nil {
		d.Items = map[string]*Item{}
	}
	if d.Grants == nil {
		d.Grants = map[string]*Grant{}
	}
	if d.Counters == nil {
		d.Counters = map[string]*Counter{}
	}
	if d.Leases == nil {
		d.Leases = map[string]*Lease{}
	}
	if d.Approvals == nil {
		d.Approvals = map[string]*Approval{}
	}
	return &Vault{path: path, data: &d}, nil
}

// Unseal validates and installs the root key.
func (v *Vault) Unseal(rootKey []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(rootKey) != seal.KeySize {
		return fmt.Errorf("store: root key must be %d bytes", seal.KeySize)
	}
	pt, err := seal.Decrypt(rootKey, v.data.RootCheck, []byte(v.data.ServerID))
	if err != nil || string(pt) != rootCheckPlaintext {
		return errors.New("store: root key does not match this vault")
	}
	v.root = rootKey
	return nil
}

// UnsealWithPassphrase derives the root key from a passphrase.
func (v *Vault) UnsealWithPassphrase(passphrase []byte) error {
	v.mu.RLock()
	kdf := v.data.KDF
	v.mu.RUnlock()
	if kdf == nil {
		return errors.New("store: this vault was not created with a passphrase")
	}
	key, err := kdf.Derive(passphrase)
	if err != nil {
		return err
	}
	return v.Unseal(key)
}

// Sealed reports whether the root key is absent. It takes the read lock, so it
// must not be called by a caller that already holds either lock -- those should
// use SealedLocked instead.
func (v *Vault) Sealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.root == nil
}

// SealedLocked is Sealed for callers already holding a lock. Go's RWMutex is
// not reentrant, so mixing the two deadlocks.
func (v *Vault) SealedLocked() bool { return v.root == nil }

// ServerID returns the vault's stable identifier, which is mixed into every
// handshake transcript so a signature for one server cannot be replayed at
// another.
func (v *Vault) ServerID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.data.ServerID
}

// Lock and Unlock expose the write lock for multi-step transactions.
func (v *Vault) Lock()    { v.mu.Lock() }
func (v *Vault) Unlock()  { v.mu.Unlock() }
func (v *Vault) RLock()   { v.mu.RLock() }
func (v *Vault) RUnlock() { v.mu.RUnlock() }

// Data exposes the in-memory model. The caller must hold the appropriate lock.
func (v *Vault) Data() *Data { return v.data }

// RootKey returns the unsealed root key, or nil. The caller must hold a lock.
func (v *Vault) RootKey() []byte { return v.root }

// Save writes the vault atomically: a crash leaves either the old file or the
// new one, never a truncated mix of the two.
func (v *Vault) Save() error {
	raw, err := json.MarshalIndent(v.data, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode vault: %w", err)
	}
	dir := filepath.Dir(v.path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("store: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: write vault: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: sync vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close vault: %w", err)
	}
	if err := os.Rename(tmpName, v.path); err != nil {
		return fmt.Errorf("store: replace vault: %w", err)
	}
	// Fsync the directory so the rename itself is durable.
	if d, err := os.Open(dir); err == nil { //#nosec G304 -- the directory we just wrote the vault into
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// SaveLocked persists while already holding the write lock.
func (v *Vault) SaveLocked() error { return v.Save() }

// ParseRootKey decodes a base64 root key of the correct length.
func ParseRootKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("store: root key must be base64: %w", err)
	}
	if len(raw) != seal.KeySize {
		return nil, fmt.Errorf("store: root key must decode to %d bytes, got %d", seal.KeySize, len(raw))
	}
	return raw, nil
}

// FormatRootKey renders a root key for storage in a secret manager.
func FormatRootKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }
