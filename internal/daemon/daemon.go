package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// Runner executes background loops (failover/failback, Cloudflare DDNS) alongside the Web UI.
type Runner struct {
	Store    *state.Store
	Exec     reconcile.SystemExecutor
	Hub      *TaskHub
	Failover *FailoverController
	DDNS     *CloudflareDDNS
}

// NewRunner wires background controllers with the shared state store and TaskHub.
func NewRunner(store *state.Store, exec reconcile.SystemExecutor, hub *TaskHub) *Runner {
	if exec == nil {
		exec = reconcile.OSExecutor{}
	}
	if hub == nil {
		hub = NewTaskHub(300)
	}
	r := &Runner{
		Store: store,
		Exec:  exec,
		Hub:   hub,
		DDNS:  NewCloudflareDDNS(hub),
	}
	r.Failover = NewFailoverController(hub, func(ctx context.Context, targetID string) error {
		_, _, err := reconcile.UpdateAndReconcile(ctx, store, state.RoleClient, exec, reconcile.ApplyOptions{}, func(cur *state.State) error {
			cur.Client.ActiveNodeID = targetID
			return nil
		})
		return err
	})
	return r
}

// RunLoops blocks until ctx is cancelled, ticking failover (30s) and DDNS (60s).
func (r *Runner) RunLoops(ctx context.Context) {
	failoverTicker := time.NewTicker(30 * time.Second)
	ddnsTicker := time.NewTicker(60 * time.Second)
	defer failoverTicker.Stop()
	defer ddnsTicker.Stop()

	r.Hub.Log("INFO", "daemon", "background loops started (failover=30s, ddns=60s)")
	for {
		select {
		case <-ctx.Done():
			r.Hub.Log("INFO", "daemon", "background loops stopping")
			return
		case <-failoverTicker.C:
			st, err := r.Store.Load()
			if err != nil {
				continue
			}
			r.Failover.Step(ctx, st)
		case <-ddnsTicker.C:
			st, err := r.Store.Load()
			if err != nil || st.Role != state.RoleClient || !st.Client.DDNS.Enabled {
				continue
			}
			if _, err := r.DDNS.SyncOnce(ctx, st.Client.DDNS.Domain, st.Client.DDNS.CFToken, st.Client.DDNS.EnableIPv6, false); err != nil {
				r.Hub.Log("WARN", "ddns", fmt.Sprintf("sync failed: %v", err))
			}
		}
	}
}
