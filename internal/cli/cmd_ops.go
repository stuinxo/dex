package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/doh"
	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/migrate"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/web"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func cmdCert(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	return cmdCertWithOpts(store, exec, reconcile.ApplyOptions{}, args, stdout, stderr)
}

func cmdCertWithOpts(store *state.Store, exec reconcile.SystemExecutor, applyOpts reconcile.ApplyOptions, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "inspect" {
		st, _ := store.Load()
		certFile, keyFile := reconcile.ResolveActiveCertPaths(store, st)
		if applyOpts.RootPrefix != "" {
			certFile = fsutil.MapRootPrefix(applyOpts.RootPrefix, certFile)
			keyFile = fsutil.MapRootPrefix(applyOpts.RootPrefix, keyFile)
		}
		cb, err1 := os.ReadFile(certFile)
		kb, err2 := os.ReadFile(keyFile)
		if err1 != nil || err2 != nil {
			fmt.Fprintf(stderr, "cannot read cert/key (%s / %s): %v / %v\n", certFile, keyFile, err1, err2)
			return 1
		}
		rep, err := cert.InspectPair(cb, kb)
		if err != nil {
			fmt.Fprintf(stderr, "inspect error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "CN: %s\nSANs: %s\nExpires: %s\nSelfSigned: %v | ChainValid: %v\n",
			rep.CommonName, strings.Join(rep.SANs, ", "), rep.NotAfter.Format(time.RFC3339), rep.SelfSigned, rep.ChainValid)
		for _, w := range rep.Warnings {
			fmt.Fprintf(stdout, "Warning: %s\n", w)
		}
		return 0
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "self-sign":
		fs := flag.NewFlagSet("cert self-sign", flag.ContinueOnError)
		fs.SetOutput(stderr)
		force := fs.Bool("force", false, "overwrite existing valid certificate")
		cn := "localhost"
		parseArgs := rest
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			cn = rest[0]
			parseArgs = rest[1:]
		}
		if err := fs.Parse(parseArgs); err != nil {
			return 2
		}
		if fs.NArg() > 0 && cn == "localhost" {
			cn = fs.Arg(0)
		}
		if _, _, _, err := reconcile.SelfSignCertAndSync(context.Background(), store, exec, applyOpts, cn, *force, true, stdout); err != nil {
			fmt.Fprintf(stderr, "self-sign failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Self-signed certificate ready at %s\n", store.DefaultCert())
		return 0
	case "import":
		if len(rest) < 2 {
			fmt.Fprintln(stderr, "usage: dex cert import <cert.pem> <key.pem> [--allow-self-signed]")
			return 2
		}
		allowSelf := len(rest) > 2 && rest[2] == "--allow-self-signed"
		rep, changed, _, err := reconcile.ImportCertAndSync(context.Background(), store, exec, applyOpts, rest[0], rest[1], allowSelf, true, stdout)
		if err != nil {
			fmt.Fprintf(stderr, "import failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Certificate imported (changed=%v, expires=%s, SANs=%s)\n",
			changed, rep.NotAfter.Format("2006-01-02"), strings.Join(rep.SANs, ", "))
		return 0
	case "issue":
		fs := flag.NewFlagSet("cert issue", flag.ContinueOnError)
		fs.SetOutput(stderr)
		mode := fs.String("mode", "cf", "ACME validation mode: cf|http")
		dom := fs.String("domain", "", "domain")
		tok := fs.String("cf-token", "", "Cloudflare API Token (or Global API Key with --cf-email)")
		email := fs.String("cf-email", "", "Cloudflare account email (for Global API Key)")
		webroot := fs.String("webroot", "", "HTTP-01 webroot directory (uses --standalone if empty)")
		renew := fs.Bool("renew", true, "keep CF token for automatic renewal")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		acmeMode := strings.ToLower(strings.TrimSpace(*mode))
		switch acmeMode {
		case "", "cf", "cloudflare", "dns", "http", "http-01":
		default:
			fmt.Fprintf(stderr, "unsupported --mode %q (expected cf or http)\n", *mode)
			return 2
		}
		rep, _, err := reconcile.IssueACMEAndSync(context.Background(), store, exec, applyOpts, nil, reconcile.IssueACMEParams{
			Mode:          acmeMode,
			Domain:        *dom,
			CFToken:       *tok,
			CFEmail:       *email,
			Webroot:       *webroot,
			AutoRenew:     renew,
			ReloadCmd:     buildCertReloadCmd(store.Dir),
			IncludeDaemon: true,
			LogOut:        stdout,
		})
		if err != nil {
			fmt.Fprintf(stderr, "acme issue failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Certificate issued for %s (expires %s)\n", strings.Join(rep.SANs, ", "), rep.NotAfter.Format("2006-01-02"))
		return 0
	case "reload":
		reconcile.ReloadCertConsumers(context.Background(), exec, true, stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown cert subcommand %q\n", sub)
		return 2
	}
}

func buildCertReloadCmd(stateDir string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" || strings.HasSuffix(exe, ".test") || strings.Contains(exe, "/go-build") {
		exe = "/usr/local/bin/dex"
	}
	return fmt.Sprintf("%s --state-dir %s cert reload", render.ShellSingleQuote(exe), render.ShellSingleQuote(stateDir))
}

func cmdMigrate(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	return runMigrateWithExec(store, exec, "/opt/de_GWD/nftables", reconcile.ApplyOptions{}, args, stdout, stderr)
}

func runMigrateWithExec(store *state.Store, exec reconcile.SystemExecutor, v2NFTDir string, baseOpts reconcile.ApplyOptions, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "/opt/de_GWD/0conf", "source file or root path")
	kind := fs.String("kind", "v2_client", "v2_client|v2_server|des|dexs")
	doApply := fs.Bool("apply", false, "apply immediately after migration")
	cleanupV2 := fs.Bool("cleanup-v2", false, "stop legacy v2 services, pihole container, and v2 nft tables (requires --apply)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cleanupV2 && !*doApply {
		fmt.Fprintln(stderr, "migrate failed: --cleanup-v2 requires --apply")
		return 2
	}

	var imported *state.State
	var notes []string
	var err error
	switch *kind {
	case "v2_client":
		imported, notes, err = migrate.ImportV2Client(*from, filepath.Dir(*from))
	case "v2_server":
		imported, notes, err = migrate.ImportV2Server(*from)
	case "des":
		imported, notes, err = migrate.ImportDES(*from)
	case "dexs":
		imported, notes, err = migrate.ImportDEXS(*from)
	default:
		fmt.Fprintf(stderr, "unknown migrate kind %q\n", *kind)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "migrate failed: %v\n", err)
		return 1
	}

	if imported.Auth.PasswordHash == "" {
		if cur, cerr := store.Load(); cerr == nil && cur.Auth.PasswordHash != "" {
			imported.Auth.PasswordHash = cur.Auth.PasswordHash
		} else {
			pw, _ := cryptoext.GenerateInitialPassword()
			imported.Auth.PasswordHash, _ = cryptoext.HashPassword(pw)
			fmt.Fprintf(stdout, "Generated initial Web password: %s\n", pw)
		}
	}

	if err := store.Save(imported); err != nil {
		fmt.Fprintf(stderr, "save migrated state: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Migrated %s -> %s (role=%s)\n", *kind, store.StatePath(), imported.Role)
	for _, n := range notes {
		fmt.Fprintf(stdout, "  * %s\n", n)
	}
	ctx := context.Background()
	if *cleanupV2 {
		dryOpts := baseOpts
		dryOpts.DryRun = true
		if _, err := reconcile.Reconcile(ctx, store, exec, dryOpts); err != nil {
			fmt.Fprintf(stderr, "migrate dry-run validation failed (legacy v2 untouched): %v\n", err)
			return 1
		}
		nginxConfDir := "/etc/nginx/conf.d"
		if baseOpts.RootPrefix != "" {
			nginxConfDir = filepath.Join(baseOpts.RootPrefix, "etc", "nginx", "conf.d")
		}
		snap := cleanupLegacyV2WithPaths(ctx, exec, v2NFTDir, nginxConfDir, stdout)
		if _, err := reconcile.Reconcile(ctx, store, exec, baseOpts); err != nil {
			snap.restore(ctx, exec, stderr)
			fmt.Fprintf(stderr, "apply failed after v2 cleanup (legacy v2 restored): %v\n", err)
			return 1
		}
		return 0
	}
	if *doApply {
		if _, err := reconcile.Reconcile(ctx, store, exec, baseOpts); err != nil {
			fmt.Fprintf(stderr, "apply failed: %v\n", err)
			return 1
		}
	}
	return 0
}

func cmdDaemon(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDirFlag := fs.String("state-dir", "", "override state directory")
	listen := fs.String("listen", "", "override Web UI listen address")
	httpOnly := fs.Bool("http", false, "serve plain HTTP (e.g. behind local proxy)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*stateDirFlag) != "" {
		store = state.NewStore(strings.TrimSpace(*stateDirFlag))
	}

	st, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load state: %v\n", err)
		return 1
	}
	addr := st.Auth.ListenAddr
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		switch st.Role {
		case state.RoleClient:
			addr = ":443"
		case state.RoleServer:
			addr = "127.0.0.1:8443"
		default:
			addr = ":8443"
		}
	}

	hub := daemon.NewTaskHub(300)
	runner := daemon.NewRunner(store, exec, hub)
	webSrv := web.NewServer(store, exec, hub, runner.DDNS, reconcile.ApplyOptions{})
	webSrv.Notifier = runner.Notifier
	webSrv.Metrics = runner.Metrics
	webSrv.CertReloadCmd = buildCertReloadCmd(store.Dir)
	webSrv.UpdateRulesFn = func(ctx context.Context, includeAds bool, w io.Writer) error {
		return UpdateRules(ctx, store, exec, OpsConfig{}, includeAds, false, w)
	}
	webSrv.UpdateComponentsFn = func(ctx context.Context, component, ver string, w io.Writer) error {
		return UpdateComponents(ctx, store, exec, OpsConfig{SkipDaemonRestart: true}, component, ver, w)
	}
	webSrv.ReloadCertFn = func(ctx context.Context) {
		reconcile.ReloadCertConsumers(ctx, exec, false, nil)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go runner.RunLoops(ctx)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           webSrv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var redirSrv *http.Server
	if st.Role == state.RoleClient && !*httpOnly {
		_, httpsPort, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			httpsPort = "443"
		}
		if httpsPort != "80" {
			ln80, lerr := net.Listen("tcp", ":80")
			if lerr != nil {
				fmt.Fprintf(stderr, "warning: HTTP->HTTPS redirect on :80 disabled: %v\n", lerr)
			} else {
				redirSrv = &http.Server{
					Addr:              ":80",
					Handler:           newHTTPSRedirectHandler(httpsPort),
					ReadHeaderTimeout: 5 * time.Second,
				}
				fmt.Fprintf(stdout, "dex daemon listening HTTP->HTTPS redirect on :80 -> :%s\n", httpsPort)
				go func() {
					if serr := redirSrv.Serve(ln80); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
						fmt.Fprintf(stderr, "http redirect error: %v\n", serr)
					}
				}()
			}
		}
	}

	errCh := make(chan error, 1)
	go func() {
		if *httpOnly {
			fmt.Fprintf(stdout, "dex daemon listening HTTP on %s\n", addr)
			errCh <- httpSrv.ListenAndServe()
			return
		}
		cer := store.DefaultCert()
		key := store.DefaultKey()
		if st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
			cer = st.Cert.CertFile
			key = st.Cert.KeyFile
		}
		if err := cert.EnsureSelfSigned(cer, key, st.Auth.ServerName); err != nil {
			errCh <- err
			return
		}
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		fmt.Fprintf(stdout, "dex daemon listening HTTPS on %s\n", addr)
		errCh <- httpSrv.ListenAndServeTLS(cer, key)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if redirSrv != nil {
			_ = redirSrv.Shutdown(shutCtx)
		}
		_ = httpSrv.Shutdown(shutCtx)
		return 0
	case err := <-errCh:
		if redirSrv != nil {
			_ = redirSrv.Close()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "daemon error: %v\n", err)
			return 1
		}
		return 0
	}
}

func newHTTPSRedirectHandler(httpsPort string) http.Handler {
	port := strings.TrimSpace(httpsPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := extractRedirectHost(r.Host)
		if host == "" || strings.ContainsAny(host, "/\\@ \t\r\n") {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		var authority string
		if port == "" || port == "443" {
			if strings.Contains(host, ":") {
				authority = "[" + host + "]"
			} else {
				authority = host
			}
		} else {
			authority = net.JoinHostPort(host, port)
		}

		reqURI := r.URL.RequestURI()
		if reqURI == "" || !strings.HasPrefix(reqURI, "/") {
			reqURI = "/"
		}
		// Collapse multiple leading slashes or leading backslash (e.g. //evil.com, /\evil.com)
		// so the path never looks like a scheme-relative URL.
		if strings.HasPrefix(reqURI, "//") || strings.HasPrefix(reqURI, "/\\") {
			reqURI = "/" + strings.TrimLeft(reqURI, "/\\")
		}
		target := "https://" + authority + reqURI
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func extractRedirectHost(rawHost string) string {
	h := strings.TrimSpace(rawHost)
	if h == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		return parsedHost
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}

func cmdServeDoH(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve-doh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:9853", "listen addr")
	upstream := fs.String("upstream", "1.1.1.1:53,8.8.8.8:53,127.0.0.53:53,127.0.0.1:53", "comma-separated DNS upstreams")
	path := fs.String("path", "/dq", "HTTP DoH path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var ups []string
	for _, u := range strings.Split(*upstream, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			ups = append(ups, u)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "dex serve-doh listening on %s%s -> %v\n", *listen, *path, ups)
	if err := doh.ListenAndServe(ctx, doh.Config{
		ListenAddr: *listen,
		Path:       *path,
		Upstreams:  ups,
	}); err != nil {
		fmt.Fprintf(stderr, "serve-doh error: %v\n", err)
		return 1
	}
	return 0
}
