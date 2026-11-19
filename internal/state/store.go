package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var ErrNotFound = errors.New("state file not found")

// Store manages atomic, flock-serialized persistence for /etc/dex/state.json.
type Store struct {
	Dir             string
	OnApplyLockWait func() // optional callback invoked once if WithApplyLock waits >= 1s
}

// NewStore returns a Store rooted at stateDir (defaults to /etc/dex if empty).
func NewStore(stateDir string) *Store {
	if stateDir == "" {
		stateDir = "/etc/dex"
	}
	return &Store{Dir: stateDir}
}

func (s *Store) StatePath() string     { return filepath.Join(s.Dir, "state.json") }
func (s *Store) BackupPath() string    { return filepath.Join(s.Dir, "state.json.bak") }
func (s *Store) TxnPath() string       { return filepath.Join(s.Dir, "state.json.txn") }
func (s *Store) LockPath() string      { return filepath.Join(s.Dir, "state.lock") }
func (s *Store) ApplyLockPath() string { return filepath.Join(s.Dir, "apply.lock") }

// WithApplyLock serializes full UpdateAndReconcile / Reconcile transactions across processes
// and goroutines. Lock ordering invariant: apply.lock is strictly outer to state.lock.
func (s *Store) WithApplyLock(ctx context.Context, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureDir(); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(s.ApplyLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open apply lock file: %w", err)
	}
	defer lockFile.Close()

	waitStarted := time.Now()
	warned := false
	for {
		err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("apply flock: %w", err)
		}
		if !warned && time.Since(waitStarted) >= time.Second {
			warned = true
			if s.OnApplyLockWait != nil {
				s.OnApplyLockWait()
			} else {
				fmt.Fprintln(os.Stderr, "waiting for another dex apply...")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	return fn()
}
func (s *Store) GeneratedDir() string { return filepath.Join(s.Dir, "generated") }
func (s *Store) ManifestPath() string { return filepath.Join(s.Dir, "generated", "manifest.json") }
func (s *Store) CertDir() string      { return filepath.Join(s.Dir, "ssl") }
func (s *Store) DefaultCert() string  { return filepath.Join(s.Dir, "ssl", "dex.cer") }
func (s *Store) DefaultKey() string   { return filepath.Join(s.Dir, "ssl", "dex.key") }

func (s *Store) ensureDir() error {
	return os.MkdirAll(s.Dir, 0o755)
}

func (s *Store) withLock(exclusive bool, fn func() error) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(s.LockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lockFile.Close()

	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(lockFile.Fd()), mode); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	return fn()
}

func readValidStateFile(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.Role == "" {
		return nil, errors.New("state missing role")
	}
	if st.Client.Routing.ServiceMap == nil {
		st.Client.Routing.ServiceMap = make(map[string]string)
	}
	if st.Client.DNS.Hosts == nil {
		st.Client.DNS.Hosts = make(map[string]string)
	}
	return &st, nil
}

func (s *Store) loadUnlocked() (*State, error) {
	st, err := readValidStateFile(s.StatePath())
	if err == nil {
		return st, nil
	}
	primaryNotExist := os.IsNotExist(err)
	bak, bakErr := readValidStateFile(s.BackupPath())
	if bakErr == nil {
		return bak, nil
	}
	if primaryNotExist && os.IsNotExist(bakErr) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("load state failed (primary=%v, backup=%v)", err, bakErr)
}

// Load reads and validates state.json under a shared flock, falling back to state.json.bak if primary is corrupted.
func (s *Store) Load() (*State, error) {
	var st *State
	err := s.withLock(false, func() error {
		var lerr error
		st, lerr = s.loadUnlocked()
		return lerr
	})
	return st, err
}

// LoadOrDefault loads existing state or returns NewDefaultState(role) when no state file exists yet.
func (s *Store) LoadOrDefault(role string) (*State, error) {
	st, err := s.Load()
	if errors.Is(err, ErrNotFound) {
		return NewDefaultState(role), nil
	}
	return st, err
}

func writeJSONAtomic(path string, v any, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".state.tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	success = true
	return nil
}

func (s *Store) saveUnlocked(st *State) error {
	if err := st.Validate(); err != nil {
		return fmt.Errorf("validate state: %w", err)
	}
	// Preserve existing valid primary state in .bak before atomic replacement.
	if prev, err := readValidStateFile(s.StatePath()); err == nil && prev != nil {
		if err := writeJSONAtomic(s.BackupPath(), prev, 0o600); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	}
	return writeJSONAtomic(s.StatePath(), st, 0o600)
}

// Save validates and atomically writes st to state.json under an exclusive flock.
func (s *Store) Save(st *State) error {
	return s.withLock(true, func() error {
		return s.saveUnlocked(st)
	})
}

// Update atomically loads (or creates default if missing), applies mutator, validates, backs up, and writes state.json.
func (s *Store) Update(defaultRole string, mutator func(*State) error) (*State, error) {
	var updated *State
	err := s.withLock(true, func() error {
		cur, err := s.loadUnlocked()
		if errors.Is(err, ErrNotFound) {
			cur = NewDefaultState(defaultRole)
		} else if err != nil {
			return err
		}
		if err := mutator(cur); err != nil {
			return err
		}
		if err := s.saveUnlocked(cur); err != nil {
			return err
		}
		updated = cur
		return nil
	})
	return updated, err
}

// BeginTxn snapshots the current valid state.json to state.json.txn.
func (s *Store) BeginTxn() error {
	return s.withLock(true, func() error {
		cur, err := s.loadUnlocked()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return writeJSONAtomic(s.TxnPath(), cur, 0o600)
	})
}

// CommitTxn removes the transaction snapshot after successful apply.
func (s *Store) CommitTxn() error {
	return s.withLock(true, func() error {
		err := os.Remove(s.TxnPath())
		if os.IsNotExist(err) {
			return nil
		}
		return err
	})
}

// RollbackTxn restores state.json from state.json.txn if it exists.
func (s *Store) RollbackTxn() (*State, error) {
	var restored *State
	err := s.withLock(true, func() error {
		txn, err := readValidStateFile(s.TxnPath())
		if err != nil {
			return err
		}
		if err := writeJSONAtomic(s.StatePath(), txn, 0o600); err != nil {
			return err
		}
		_ = os.Remove(s.TxnPath())
		restored = txn
		return nil
	})
	return restored, err
}
