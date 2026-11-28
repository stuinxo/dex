package cli

import (
	"context"
	"fmt"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/version"
	"io"
	"os"
	"strings"
)

// Run is the main CLI entrypoint invoked by cmd/dex/main.go and tests.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return RunWithExecutor(args, reconcile.OSExecutor{}, stdin, stdout, stderr)
}

// RunWithExecutor executes the CLI with a caller-provided SystemExecutor (primarily for tests).
func RunWithExecutor(args []string, exec reconcile.SystemExecutor, stdin io.Reader, stdout, stderr io.Writer) int {
	if exec == nil {
		exec = reconcile.OSExecutor{}
	}
	stateDir := strings.TrimSpace(os.Getenv("DEX_STATE_DIR"))
	if stateDir == "" {
		stateDir = "/etc/dex"
	}

	// Parse leading global --state-dir flag
	for len(args) > 0 && strings.HasPrefix(args[0], "--state-dir") {
		if args[0] == "--state-dir" {
			if len(args) < 2 {
				fmt.Fprintln(stderr, "missing argument for --state-dir")
				return 2
			}
			stateDir = args[1]
			args = args[2:]
		} else if val, ok := strings.CutPrefix(args[0], "--state-dir="); ok {
			stateDir = val
			args = args[1:]
		}
	}

	store := state.NewStore(stateDir)
	store.OnApplyLockWait = func() {
		fmt.Fprintln(stderr, "waiting for another dex apply...")
	}

	if len(args) == 0 {
		return runInteractiveMenu(store, exec, stdin, stdout, stderr)
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "dex %s\n", version.Summary())
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "menu":
		return runInteractiveMenu(store, exec, stdin, stdout, stderr)
	case "-c", "--client":
		return dispatchRoleFlag(store, exec, state.RoleClient, rest, stdin, stdout, stderr)
	case "-s", "--server":
		return dispatchRoleFlag(store, exec, state.RoleServer, rest, stdin, stdout, stderr)
	case "-r", "--relay":
		return dispatchRoleFlag(store, exec, state.RoleRelay, rest, stdin, stdout, stderr)
	case "-l", "--landing":
		return dispatchRoleFlag(store, exec, state.RoleLanding, rest, stdin, stdout, stderr)
	case "init":
		return cmdInit(store, exec, rest, stdout, stderr)
	case "apply":
		return cmdApply(store, exec, rest, stdout, stderr)
	case "refresh":
		return cmdApply(store, exec, rest, stdout, stderr)
	case "status":
		return cmdStatus(store, exec, stdout, stderr)
	case "server":
		return cmdServer(store, exec, rest, stdout, stderr)
	case "dns":
		return cmdDNS(store, exec, rest, stdout, stderr)
	case "node":
		return cmdNode(store, exec, rest, stdout, stderr)
	case "cert":
		return cmdCert(store, exec, rest, stdout, stderr)
	case "wg":
		return cmdWG(store, exec, rest, stdout, stderr)
	case "ddns":
		return cmdDDNS(store, exec, rest, stdout, stderr)
	case "socks5":
		return cmdSocks5(store, exec, rest, stdout, stderr)
	case "relay":
		return cmdRelay(store, exec, rest, stdout, stderr)
	case "rproxy":
		return cmdRproxy(store, exec, rest, stdout, stderr)
	case "extra":
		return cmdExtra(store, exec, rest, stdout, stderr)
	case "rules":
		return cmdRules(store, exec, rest, stdout, stderr)
	case "update":
		return cmdUpdate(store, exec, rest, stdout, stderr)
	case "kernel":
		return cmdKernel(store, exec, rest, stdout, stderr)
	case "migrate":
		return cmdMigrate(store, exec, rest, stdout, stderr)
	case "daemon":
		return cmdDaemon(store, exec, rest, stdout, stderr)
	case "serve-doh":
		return cmdServeDoH(rest, stdout, stderr)
	default:
		if isShareNodeURI(sub) {
			return dispatchRoleFlag(store, exec, state.RoleClient, args, stdin, stdout, stderr)
		}
		fmt.Fprintf(stderr, "unknown command %q\n\n", sub)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `DEX — Unified Bypass Gateway & Node Controller

Usage:
  dex [--state-dir DIR] [command] [flags]
  dex 'vless://...'
  dex [-c|-s|-r|-l] [flags]

Role Shortcuts:
  'vless://...'         Initialize & apply client role directly from Server share URI (auto-derives /dq DoH)
  -c, --client          Initialize & apply client role (wizard if no args, e.g. dex -c 'vless://...')
  -s, --server          Initialize & apply server role (wizard if no args, e.g. dex -s srv.example.com)
  -r, --relay           Initialize & apply relay role (wizard if no args, or pass --no-apply to skip apply)
  -l, --landing         Initialize & apply landing role (wizard if no args, e.g. dex -l land.example.com)

Commands:
  menu                  Open interactive numbered menu (default when no args)
  init                  Initialize a new client / server / landing / relay state
  apply                 Validate, render, pre-flight check, and reconcile configs
  status                Show role, active node, certificate, and service health
  server <subcmd>       Inspect or update server/landing configuration (show|set)
  dns <subcmd>          Inspect or update client DNS & DoH server (show|set)
  node <subcmd>         Manage client outbound nodes (list|add|edit|move|del|select|probe|show)
  cert <subcmd>         Manage TLS certificates (self-sign|import|issue|inspect|reload)
  wg <subcmd>           Manage WireGuard VPN (enable|disable|keygen-server|peer-add|peer-regen|peer-del|show)
  ddns <subcmd>         Manage Cloudflare DDNS (set|sync|disable)
  socks5 <subcmd>       Manage server Option 35 SOCKS5 exits (list|add|del|toggle|test)
  relay <subcmd>        Manage Option 44 port forwards (list|add|del)
  rproxy <subcmd>       Manage RproxyS/RproxyC reverse proxy (show|set|map-add|map-del|disable|client-*)
  extra <subcmd>        Manage Option 55 extra inbounds (list|add-reality|add-xhttp|add-vless-ws|add-vmess-ws|add-dokodemo|add-socks5|del|disable-all)
  rules <subcmd>        Inspect or hot-update GeoIP/Domain rule files (status|update)
  update                Upgrade dex, xray, mosdns, and/or rule datasets cleanly
  kernel <subcmd>       Inspect kernel or install Zabbly mainline kernel (status|zabbly)
  migrate               Import v2 0conf, v2 server, des, or dexs state (--cleanup-v2 --apply)
  daemon                Run embedded Web UI (client :443 + :80->HTTPS redirect; server 127.0.0.1:8443) + failover + DDNS loops
  serve-doh             Run standalone RFC 8484 DoH forwarding server
  refresh               Re-resolve dynamic relay targets and re-apply nftables
  version               Print dex version
`)
}

func applyOrSave(store *state.Store, exec reconcile.SystemExecutor, defRole string, doApply bool, mut func(*state.State) error) error {
	if doApply {
		_, _, err := reconcile.UpdateAndReconcile(context.Background(), store, defRole, exec, reconcile.ApplyOptions{}, mut)
		return err
	}
	_, err := store.Update(defRole, mut)
	return err
}

func firstOrEmpty(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}
