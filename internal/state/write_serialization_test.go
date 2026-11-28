package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDirectWriteSurvivesApplyRollback(t *testing.T) {
	for _, operation := range []string{"save", "update"} {
		t.Run(operation, func(t *testing.T) {
			store := NewStore(t.TempDir())
			initial := NewDefaultState(RoleClient)
			if err := store.Save(initial); err != nil {
				t.Fatal(err)
			}
			direct := NewStore(store.Dir)
			started := make(chan struct{})
			done := make(chan error, 1)
			var wroteDuringApply bool
			err := store.WithApplyLock(context.Background(), func(store *Store) error {
				if err := store.BeginTxn(); err != nil {
					return err
				}
				go func() {
					close(started)
					if operation == "save" {
						next := NewDefaultState(RoleClient)
						next.Auth.ServerName = "concurrent.example.com"
						done <- direct.Save(next)
					} else {
						_, err := direct.Update(RoleClient, func(st *State) error {
							st.Auth.ServerName = "concurrent.example.com"
							return nil
						})
						done <- err
					}
				}()
				<-started
				select {
				case err := <-done:
					if err != nil {
						return err
					}
					wroteDuringApply = true
				case <-time.After(100 * time.Millisecond):
				}
				_, err := store.RollbackTxn()
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if !wroteDuringApply {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("direct writer failed to resume")
				}
			}
			got, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if got.Auth.ServerName != "concurrent.example.com" {
				t.Fatal("apply rollback discarded a successful concurrent write")
			}
		})
	}
}

func TestApplyScopeWritesAndReleasesOnError(t *testing.T) {
	store := NewStore(t.TempDir())
	failure := errors.New("abort apply")
	err := store.WithApplyLock(context.Background(), func(locked *Store) error {
		if err := locked.Save(NewDefaultState(RoleClient)); err != nil {
			return err
		}
		if _, err := locked.Update(RoleClient, func(st *State) error {
			st.Auth.ServerName = "scoped.example.com"
			return nil
		}); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("callback error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- store.Save(NewDefaultState(RoleClient)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("apply lock remained held after callback error")
	}
}

func TestApplyLockCancellation(t *testing.T) {
	store := NewStore(t.TempDir())
	err := store.WithApplyLock(context.Background(), func(_ *Store) error {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := NewStore(store.Dir).WithApplyLock(ctx, func(_ *Store) error {
			t.Error("cancelled waiter entered callback")
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waiting error = %v, want cancellation", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
