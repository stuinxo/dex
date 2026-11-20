package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/state"
	"github.com/stuinxo/de_GWD/v3/internal/version"
)

func runInteractiveMenu(store *state.Store, exec reconcile.SystemExecutor, stdin io.Reader, stdout, stderr io.Writer) int {
	sc := bufio.NewScanner(stdin)
	ask := func(prompt, def string) string {
		if def != "" {
			fmt.Fprintf(stdout, "%s [%s]: ", prompt, def)
		} else {
			fmt.Fprintf(stdout, "%s: ", prompt)
		}
		if !sc.Scan() {
			return def
		}
		v := strings.TrimSpace(sc.Text())
		if v == "" {
			return def
		}
		return v
	}

	for {
		st, err := store.Load()
		roleStr := "uninitialized"
		svcLine := ""
		if err == nil {
			roleStr = st.Role
			if sum := serviceStatusSummary(exec, st); sum != "" {
				svcLine = "Services: " + sum + "\n"
			}
		}
		fmt.Fprintf(stdout, `
================ DEX %s (%s) ================
%s 1. 初始化向导 (Client / Server / Landing / Relay)
 3. 域名与证书管理 (导入 / ACME 签发 / 自检 / 服务端端口域名)
 4. 修改主节点 UUID / Path
 8. 修改 Web 面板监听端口
 9. 修改 Web 登录密码
11. 查看节点信息与导入链接
22. Rproxy 反向代理设置
35. SOCKS5 多出口分流管理 (Server)
44. TCP/UDP 端口转发管理 (nft / haproxy / xray)
55. 附加协议管理 (Reality / XHTTP / WS / SOCKS5 / Dokodemo)
66. WireGuard 回家管理
77. Cloudflare DDNS 设置与同步
88. 从 v2 (0conf/server) / des / dexs 导入迁移
90. 路由与分流规则库热更新 (rules)
99. 核心组件在线更新 (dex/xray/mosdns)
 0. 应用配置 (Apply) 并查看状态
 q. 退出
====================================================
`, version.Summary(), roleStr, svcLine)

		choice := ask("Select", "q")
		switch choice {
		case "q", "Q":
			return 0
		case "1":
			r := ask("Role (client/server/landing/relay)", "client")
			d := ask("Domain", "")
			p := ask("Port", "")
			args := []string{"--role", r}
			if d != "" {
				args = append(args, "--domain", d)
			}
			if p != "" {
				args = append(args, "--port", p)
			}
			cmdInit(store, exec, args, stdout, stderr)
		case "3":
			sub := ask("Action (inspect/import/issue/self-sign/server)", "inspect")
			switch sub {
			case "import":
				c := ask("Cert file", "/root/de_GWD.cer")
				k := ask("Key file", "/root/de_GWD.key")
				cmdCert(store, exec, []string{"import", c, k}, stdout, stderr)
			case "issue":
				m := ask("Mode (cf/http)", "cf")
				d := ask("Domain", "")
				args := []string{"issue", "--mode", m, "--domain", d}
				if strings.EqualFold(m, "http") {
					wr := ask("Webroot (empty for standalone)", "")
					if wr != "" {
						args = append(args, "--webroot", wr)
					}
				} else {
					t := ask("Cloudflare Token", "")
					args = append(args, "--cf-token", t)
				}
				cmdCert(store, exec, args, stdout, stderr)
			case "server":
				d := ask("Server Domain", "")
				p := ask("Listen Port (empty to keep)", "")
				pp := ask("Public Port (empty to keep)", "")
				proto := ask("Protocol (vless-xhttp/vmess-ws/vless-ws, empty to keep)", "")
				args := []string{"set"}
				if d != "" {
					args = append(args, "--domain", d)
				}
				if p != "" {
					args = append(args, "--port", p)
				}
				if pp != "" {
					args = append(args, "--public-port", pp)
				}
				if proto != "" {
					args = append(args, "--protocol", proto)
				}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdServer(store, exec, args, stdout, stderr)
			default:
				cmdCert(store, exec, []string{sub}, stdout, stderr)
			}
		case "4":
			if st == nil {
				fmt.Fprintln(stderr, "Initialize state first (option 1).")
				continue
			}
			u, _ := cryptoext.GenerateUUID()
			u = ask("New UUID", u)
			p := ask("New Path", cryptoext.UUIDToDefaultPath(u))
			_, err := store.Update(st.Role, func(cur *state.State) error {
				if cur.Role == state.RoleServer || cur.Role == state.RoleLanding {
					cur.Server.UUIDs = []string{u}
					cur.Server.Path = p
				} else if n := cur.Client.ActiveNode(); n != nil {
					n.UUID = u
					n.Path = p
				}
				return nil
			})
			if err != nil {
				fmt.Fprintf(stderr, "update failed: %v\n", err)
			} else {
				fmt.Fprintln(stdout, "Updated UUID & Path.")
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					cmdApply(store, exec, nil, stdout, stderr)
				}
			}
		case "8":
			if st == nil {
				fmt.Fprintln(stderr, "Initialize state first.")
				continue
			}
			pStr := ask("Web UI port", "8443")
			if p, perr := strconv.Atoi(pStr); perr == nil && p >= 1 && p <= 65535 {
				if _, uerr := store.Update(st.Role, func(cur *state.State) error {
					cur.Auth.ListenAddr = fmt.Sprintf(":%d", p)
					return nil
				}); uerr != nil {
					fmt.Fprintf(stderr, "update failed: %v\n", uerr)
					continue
				}
				fmt.Fprintf(stdout, "Web listen port set to :%d\n", p)
				if exec != nil {
					initSys := exec.DetectInitSystem()
					if exec.ServiceIsActive(context.Background(), initSys, "dex-daemon") {
						if rerr := exec.ServiceRestart(context.Background(), initSys, "dex-daemon"); rerr != nil {
							fmt.Fprintf(stderr, "restart dex-daemon failed: %v\n", rerr)
						} else {
							fmt.Fprintln(stdout, "Restarted dex-daemon with new listen port.")
						}
					}
				}
			}
		case "9":
			if st == nil {
				fmt.Fprintln(stderr, "Initialize state first.")
				continue
			}
			pw := ask("New Web UI password (min 6 chars)", "")
			if len(pw) >= 6 {
				if h, herr := cryptoext.HashPassword(pw); herr == nil {
					_, _ = store.Update(st.Role, func(cur *state.State) error {
						cur.Auth.PasswordHash = h
						return nil
					})
					fmt.Fprintln(stdout, "Password updated.")
				}
			} else {
				fmt.Fprintln(stderr, "Password too short.")
			}
		case "11":
			cmdNode(store, exec, []string{"show"}, stdout, stderr)
		case "22":
			sub := ask("Action (show/set/map-add/map-del/disable)", "show")
			switch sub {
			case "set":
				d := ask("RproxyS domain", "")
				p := ask("Tunnel port", "20000")
				cmdRproxy(store, exec, []string{"set", "--domain", d, "--port", p}, stdout, stderr)
			case "map-add":
				p := ask("Public port", "")
				pr := ask("Protocol (tcp/udp/tcp,udp)", "tcp")
				args := []string{"map-add", "--port", p, "--proto", pr}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdRproxy(store, exec, args, stdout, stderr)
			case "map-del":
				p := ask("Mapped port", "")
				cmdRproxy(store, exec, []string{"map-del", p}, stdout, stderr)
			default:
				cmdRproxy(store, exec, []string{sub}, stdout, stderr)
			}
		case "35":
			sub := ask("Action (list/add/del/toggle/test)", "list")
			if sub == "add" {
				n := ask("Profile name", "default")
				ep := ask("Endpoint (socks5://... or host:port)", "")
				dom := ask("Domain rules (@ai,@stream,@tg or empty)", "")
				ip := ask("IP rules (@tg,CIDR or empty)", "")
				pb := ask("Private bypass? (Y/n)", "y")
				args := []string{"add", "--name", n, "--endpoint", ep, "--domains", dom, "--ips", ip}
				if strings.EqualFold(pb, "n") || strings.EqualFold(pb, "false") {
					args = append(args, "--private-bypass=false")
				}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdSocks5(store, exec, args, stdout, stderr)
			} else if sub == "del" || sub == "toggle" {
				n := ask("Profile name", "default")
				cmdSocks5(store, exec, []string{sub, n}, stdout, stderr)
			} else {
				cmdSocks5(store, exec, []string{sub}, stdout, stderr)
			}
		case "44":
			sub := ask("Action (list/add/del)", "list")
			if sub == "add" {
				lp := ask("Listen port", "10001")
				th := ask("Target host", "")
				tp := ask("Target port", "443")
				pr := ask("Proto (tcp/udp/tcp,udp)", "tcp")
				eng := ask("Engine (nft/haproxy/xray)", "nft")
				cmdRelay(store, exec, []string{"add", "--listen", lp, "--target-host", th, "--target-port", tp, "--proto", pr, "--engine", eng}, stdout, stderr)
			} else if sub == "del" {
				k := ask("Rule ID or port", "")
				cmdRelay(store, exec, []string{"del", k}, stdout, stderr)
			} else {
				cmdRelay(store, exec, []string{"list"}, stdout, stderr)
			}
		case "55":
			sub := ask("Action (list/add-reality/add-xhttp/add-vless-ws/add-vmess-ws/add-dokodemo/add-socks5/del/disable-all)", "list")
			switch sub {
			case "add-reality":
				pStr := ask("Listen port", "2443")
				sni := ask("Reality SNI", "www.apple.com")
				args := []string{"add-reality", "--port", pStr, "--sni", sni}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdExtra(store, exec, args, stdout, stderr)
			case "add-xhttp", "add-vless-ws", "add-vmess-ws":
				pStr := ask("Listen port", "")
				dom := ask("TLS domain (empty to share server domain)", "")
				path := ask("Path (empty for auto)", "")
				viaNginx := ask("Via Nginx? (y/N)", "n")
				args := []string{sub, "--port", pStr}
				if dom != "" {
					args = append(args, "--domain", dom)
				}
				if path != "" {
					args = append(args, "--path", path)
				}
				if strings.EqualFold(viaNginx, "y") {
					args = append(args, "--via-nginx")
				}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdExtra(store, exec, args, stdout, stderr)
			case "add-dokodemo":
				pStr := ask("Listen port", "")
				tgt := ask("Target (host:port)", "")
				netProto := ask("Network (tcp/udp/tcp,udp)", "tcp,udp")
				args := []string{"add-dokodemo", "--port", pStr, "--target", tgt, "--network", netProto}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdExtra(store, exec, args, stdout, stderr)
			case "add-socks5":
				pStr := ask("Listen port", "1080")
				u := ask("Username (optional)", "")
				pw := ask("Password (optional)", "")
				args := []string{"add-socks5", "--port", pStr, "--user", u, "--pass", pw}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdExtra(store, exec, args, stdout, stderr)
			case "del":
				k := ask("Tag or port", "")
				cmdExtra(store, exec, []string{"del", k}, stdout, stderr)
			case "disable-all":
				args := []string{"disable-all"}
				if strings.EqualFold(ask("Apply now? (y/N)", "n"), "y") {
					args = append(args, "--apply")
				}
				cmdExtra(store, exec, args, stdout, stderr)
			default:
				cmdExtra(store, exec, []string{"list"}, stdout, stderr)
			}
		case "66":
			sub := ask("Action (show/enable/disable/keygen-server/peer-add/peer-regen/peer-del)", "show")
			if sub == "peer-add" {
				n := ask("Peer name", "laptop")
				cmdWG(store, exec, []string{"peer-add", n}, stdout, stderr)
			} else if sub == "peer-regen" {
				n := ask("Peer name", "")
				cmdWG(store, exec, []string{"peer-regen", n}, stdout, stderr)
			} else if sub == "peer-del" {
				n := ask("Peer name", "")
				cmdWG(store, exec, []string{"peer-del", n}, stdout, stderr)
			} else if sub == "enable" {
				ep := ask("Public endpoint host/IP", "")
				cmdWG(store, exec, []string{"enable", "--endpoint", ep}, stdout, stderr)
			} else {
				cmdWG(store, exec, []string{sub}, stdout, stderr)
			}
		case "77":
			sub := ask("Action (set/sync/disable)", "sync")
			if sub == "set" {
				d := ask("Domain", "")
				t := ask("CF Token", "")
				cmdDDNS(store, exec, []string{"set", "--domain", d, "--token", t}, stdout, stderr)
			} else {
				cmdDDNS(store, exec, []string{sub}, stdout, stderr)
			}
		case "88":
			k := ask("Source kind (v2_client/v2_server/des/dexs)", "v2_client")
			p := ask("Source path", "/opt/de_GWD/0conf")
			cmdMigrate(store, exec, []string{"--kind", k, "--from", p}, stdout, stderr)
		case "90":
			cmdRules(store, exec, []string{"update"}, stdout, stderr)
		case "99":
			comp := ask("Component (all/dex/xray/mosdns/rules)", "all")
			ver := ask("Version tag", "latest")
			cmdUpdate(store, exec, []string{"--component", comp, "--version", ver}, stdout, stderr)
		case "0":
			cmdApply(store, exec, nil, stdout, stderr)
			cmdStatus(store, exec, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "Unknown option %q\n", choice)
		}
	}
}

var _ = render.RenderAll // ensure render imported for helper completeness
