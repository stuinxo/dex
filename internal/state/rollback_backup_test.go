package state

import (
	"context"
	"os"
	"testing"
)

func TestRollbackBackupMatchesRestoredState(t *testing.T) {
	store := NewStore(t.TempDir())
	initial := NewDefaultState(RoleClient)
	initial.Auth.ServerName = "original.example.com"
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	err := store.WithApplyLock(context.Background(), func(locked *Store) error {
		if err := locked.BeginTxn(); err != nil {
			return err
		}
		for _, name := range []string{"intermediate.example.com", "rejected.example.com"} {
			if _, err := locked.Update(RoleClient, func(st *State) error {
				st.Auth.ServerName = name
				return nil
			}); err != nil {
				return err
			}
		}
		_, err := locked.RollbackTxn()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.StatePath(), []byte("corrupt primary"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Auth.ServerName != initial.Auth.ServerName {
		t.Fatal("backup fallback resurrected a rolled-back intermediate state")
	}
}

func TestRollbackRetainsSnapshotWhenBackupRestoreFails(t *testing.T) {
	store := NewStore(t.TempDir())
	st := NewDefaultState(RoleClient)
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginTxn(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(RoleClient, func(st *State) error {
		st.Auth.ServerName = "pending.example.com"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.BackupPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.BackupPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RollbackTxn(); err == nil {
		t.Fatal("expected backup restoration failure")
	}
	if _, err := os.Stat(store.TxnPath()); err != nil {
		t.Fatal("snapshot was lost after failed restore")
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if current.Auth.ServerName != "pending.example.com" {
		t.Fatal("primary changed before backup could be restored")
	}
	if err := os.Remove(store.BackupPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RollbackTxn(); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	current, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if current.Auth.ServerName != st.Auth.ServerName {
		t.Fatal("retry did not restore snapshot")
	}
}
