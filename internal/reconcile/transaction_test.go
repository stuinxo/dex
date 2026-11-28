package reconcile

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func TestMutationReportsRollbackFailure(t *testing.T) {
	store := state.NewStore(t.TempDir())
	if err := store.Save(state.NewDefaultState(state.RoleClient)); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("mutation rejected")
	_, _, err := UpdateAndReconcile(context.Background(), store, state.RoleClient, &mockExecutor{}, ApplyOptions{}, func(*state.State) error {
		if err := os.WriteFile(store.TxnPath(), []byte("invalid snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatalf("lost mutation error: %v", err)
	}
	if !strings.Contains(err.Error(), "rollback state") {
		t.Fatalf("rollback failure was hidden: %v", err)
	}
}

func TestStandaloneApplyReportsRollbackFailure(t *testing.T) {
	root := t.TempDir()
	store := state.NewStore(root + "/state")
	if err := store.Save(state.NewDefaultState(state.RoleClient)); err != nil {
		t.Fatal(err)
	}
	exec := &mockExecutor{failHealthSvc: "dex-xray"}
	exec.onServiceStart = func(string) {
		if err := os.WriteFile(store.TxnPath(), []byte("invalid snapshot"), 0o600); err != nil {
			t.Error(err)
		}
	}
	_, err := Reconcile(context.Background(), store, exec, ApplyOptions{RootPrefix: root})
	if err == nil || !strings.Contains(err.Error(), "failed health check") || !strings.Contains(err.Error(), "rollback state") {
		t.Fatalf("expected activation and rollback errors, got %v", err)
	}
}
