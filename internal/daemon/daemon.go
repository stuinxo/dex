package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
)

// Runner executes background loops (failover/failback, Cloudflare DDNS, alerting) alongside the Web UI.
type Runner struct {
	Store    *state.Store
	Exec     reconcile.SystemExecutor
	Hub      *TaskHub
	Failover *FailoverController
	DDNS     *CloudflareDDNS
	Notifier *Notifier
	Metrics  *NodeMetricsTracker

	ddnsFailAlerted bool
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
		Store:    store,
		Exec:     exec,
		Hub:      hub,
		DDNS:     NewCloudflareDDNS(hub),
		Notifier: NewNotifier(hub),
		Metrics:  NewNodeMetricsTracker(60),
	}
	r.Failover = NewFailoverController(hub, func(ctx context.Context, targetID string) error {
		_, _, err := reconcile.UpdateAndReconcile(ctx, store, state.RoleClient, exec, reconcile.ApplyOptions{}, func(cur *state.State) error {
			cur.Client.ActiveNodeID = targetID
			return nil
		})
		return err
	})
	r.Failover.Metrics = r.Metrics
	r.Failover.OnEvent = func(ctx context.Context, ev AlertEvent) {
		st, err := r.Store.Load()
		if err != nil || !st.System.Notify.Enabled || !st.System.Notify.NotifyFailover {
			return
		}
		_ = r.Notifier.Send(ctx, st.System.Notify, ev)
	}
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
			r.runFailoverTick(ctx)
		case <-ddnsTicker.C:
			st, err := r.Store.Load()
			if err != nil || st.Role != state.RoleClient || !st.Client.DDNS.Enabled {
				continue
			}
			res, err := r.DDNS.SyncOnceWithEmail(ctx, st.Client.DDNS.Domain, st.Client.DDNS.CFToken, st.Client.DDNS.CFEmail, st.Client.DDNS.EnableIPv6, false)
			if err != nil {
				r.Hub.Log("WARN", "ddns", fmt.Sprintf("sync failed: %v", err))
				if st.System.Notify.Enabled && st.System.Notify.NotifyDDNS && !r.ddnsFailAlerted {
					r.ddnsFailAlerted = true
					_ = r.Notifier.Send(ctx, st.System.Notify, AlertEvent{
						Event:    "ddns_failed",
						Severity: "warn",
						Host:     defaultEventHost(st),
						Title:    "DEX DDNS Sync Failed",
						Message:  fmt.Sprintf("domain=%s error=%v", st.Client.DDNS.Domain, err),
					})
				}
			} else {
				r.ddnsFailAlerted = false
				if (res.Updated4 || res.Updated6) && st.System.Notify.Enabled && st.System.Notify.NotifyDDNS {
					_ = r.Notifier.Send(ctx, st.System.Notify, AlertEvent{
						Event:    "ddns_updated",
						Severity: "info",
						Host:     defaultEventHost(st),
						Title:    "DEX DDNS Updated",
						Message:  fmt.Sprintf("domain=%s ipv4=%s ipv6=%s", res.Domain, res.IPv4, res.IPv6),
					})
				}
			}
		}
	}
}

func (r *Runner) runFailoverTick(ctx context.Context) {
	st, err := r.Store.Load()
	if err != nil {
		return
	}
	if st.Role == state.RoleClient && r.Exec != nil {
		initSys := r.Exec.DetectInitSystem()
		if !r.Exec.ServiceIsActive(ctx, initSys, "dex-xray") || !r.Exec.ServiceIsActive(ctx, initSys, "dex-nft") {
			return
		}
	}
	r.Failover.Step(ctx, st)
}
