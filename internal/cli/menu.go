package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/version"
)

type menuPrompter struct {
	sc     *bufio.Scanner
	stdout io.Writer
	eof    bool
}

func newMenuPrompter(stdin io.Reader, stdout io.Writer) *menuPrompter {
	return &menuPrompter{
		sc:     bufio.NewScanner(stdin),
		stdout: stdout,
	}
}

func (p *menuPrompter) ask(prompt, def string) (string, bool) {
	if p.eof {
		return "", false
	}
	if def != "" {
		fmt.Fprintf(p.stdout, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(p.stdout, "%s: ", prompt)
	}
	if !p.sc.Scan() {
		p.eof = true
		return "", false
	}
	v := strings.TrimSpace(p.sc.Text())
	if v == "" {
		return def, true
	}
	return v, true
}

func (p *menuPrompter) askYesNo(prompt string, defaultYes bool) bool {
	def := "n"
	hint := "(y/N)"
	if defaultYes {
		def = "y"
		hint = "(Y/n)"
	}
	ans, ok := p.ask(prompt+" "+hint, def)
	if !ok {
		return false
	}
	return strings.EqualFold(ans, "y") || strings.EqualFold(ans, "yes")
}

func (p *menuPrompter) maybeApply(args []string) ([]string, bool) {
	if p.askYesNo("立即应用配置?", false) {
		return append(args, "--apply"), true
	}
	return args, !p.eof
}

func (p *menuPrompter) pickProto() (string, bool) {
	fmt.Fprint(p.stdout, "协议类型: 1. TCP  2. UDP  3. TCP+UDP\n")
	v, ok := p.ask("选择协议", "1")
	if !ok {
		return "", false
	}
	switch v {
	case "2", "udp", "UDP":
		return "udp", true
	case "3", "tcp,udp", "TCP+UDP":
		return "tcp,udp", true
	default:
		return "tcp", true
	}
}

func shortServiceLabel(svc string) string {
	switch svc {
	case "dex-xray":
		return "Xray"
	case "nginx":
		return "Nginx"
	case "dex-doh":
		return "DoH"
	case "dex-mosdns":
		return "MosDNS"
	case "dex-nft":
		return "NFT"
	case "haproxy":
		return "HAProxy"
	case "wg-quick@wg0":
		return "WG"
	case "dex-daemon":
		return "Daemon"
	default:
		return svc
	}
}

func formatServiceBadges(exec reconcile.SystemExecutor, st *state.State) string {
	if exec == nil || st == nil {
		return ""
	}
	initSys := exec.DetectInitSystem()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var parts []string
	for _, svc := range serviceNamesForState(st, initSys) {
		mark := "✕"
		if exec.ServiceIsActive(ctx, initSys, svc) {
			mark = "✓"
		}
		parts = append(parts, fmt.Sprintf("%s [%s]", shortServiceLabel(svc), mark))
	}
	return strings.Join(parts, "  ")
}

func readServerCertSummary(store *state.Store, st *state.State) string {
	if store == nil || st == nil {
		return "未找到"
	}
	certFile, keyFile := resolveActiveCertPaths(store, st)
	cb, err1 := os.ReadFile(certFile)
	kb, err2 := os.ReadFile(keyFile)
	if err1 != nil || err2 != nil {
		return "未找到"
	}
	rep, err := cert.InspectPair(cb, kb)
	if err != nil {
		return "无效"
	}
	exp := rep.NotAfter.Format("2006-01-02")
	if rep.SelfSigned {
		return exp + " (自签)"
	}
	return exp
}

func runInteractiveMenu(store *state.Store, exec reconcile.SystemExecutor, stdin io.Reader, stdout, stderr io.Writer) int {
	p := newMenuPrompter(stdin, stdout)

	for !p.eof {
		st, err := store.Load()
		if err != nil {
			st = nil
		}

		if st == nil {
			fmt.Fprintf(stdout, "\n──────────────── DEX %s ────────────────\n", version.Summary())
		} else {
			fmt.Fprintf(stdout, "\n──────────────── DEX %s · %s ────────────────\n", version.Summary(), strings.ToUpper(st.Role))
		}

		kInfo := InspectKernel(context.Background(), exec, KernelConfig{})
		kernLine := formatKernelSummaryLine(kInfo)

		if st == nil {
			fmt.Fprintf(stdout, "内核: %s\n", kernLine)
			fmt.Fprint(stdout, `
 1. 初始化安装 DEX       (或直接输入 c / s / l / r，或粘贴 vless:// 链接直装 Client)
 2. 内核管理             (查看状态 / 安装 Zabbly 主线内核)
 0. 更新 DEX 主程序
 q. 退出
────────────────────────────────────────────────
`)
			choice, ok := p.ask("Select", "q")
			if !ok || strings.EqualFold(choice, "q") {
				return 0
			}
			if isShareNodeURI(choice) {
				dispatchRoleFlag(store, exec, state.RoleClient, []string{choice}, stdin, stdout, stderr)
				continue
			}
			switch strings.ToLower(choice) {
			case "1":
				menuInitWizard(store, exec, p, stdout, stderr)
			case "c", "-c", "client":
				_ = menuInitWizardForRole(store, exec, state.RoleClient, p, stdout, stderr)
			case "s", "-s", "server":
				_ = menuInitWizardForRole(store, exec, state.RoleServer, p, stdout, stderr)
			case "l", "-l", "landing":
				_ = menuInitWizardForRole(store, exec, state.RoleLanding, p, stdout, stderr)
			case "r", "-r", "relay":
				_ = menuInitWizardForRole(store, exec, state.RoleRelay, p, stdout, stderr)
			case "2":
				menuKernelManager(exec, p, stdout, stderr)
			case "0":
				cmdUpdate(store, exec, []string{"--component", "dex", "--version", "latest"}, stdout, stderr)
			default:
				fmt.Fprintf(stdout, "无效选项 %q\n", choice)
			}
			continue
		}

		if badges := formatServiceBadges(exec, st); badges != "" {
			fmt.Fprintln(stdout, badges)
		}

		switch st.Role {
		case state.RoleClient:
			nodeInfo := "(未配置)"
			if active := st.Client.ActiveNode(); active != nil {
				nodeInfo = fmt.Sprintf("%s (%s %s:%d)", active.Name, active.Protocol, active.Address, active.Port)
			}
			fmt.Fprintf(stdout, "当前节点: %s | 内核: %s\n", nodeInfo, kernLine)
			fmt.Fprint(stdout, `
 1. 初始化 / 重装 DEX
 2. 内核管理             (查看状态 / 安装 Zabbly 主线内核)
 3. 节点管理             (切换 / 测速 / 添加 / 删除)
 5. 本机 DoH 与 DNS      (外网去广告分流 DoH / 路径设置)
 8. 修改 Web 面板端口
 9. 修改 Web 登录密码
 0. 更新 DEX 与规则库

11. 查看节点信息与链接
22. 反向代理 (RproxyC)
44. TCP/UDP 端口转发
66. WireGuard & DDNS
 a. 应用配置并查看状态 (Apply)
 q. 退出
────────────────────────────────────────────────
`)
			choice, ok := p.ask("Select", "q")
			if !ok || strings.EqualFold(choice, "q") {
				return 0
			}
			switch strings.ToLower(choice) {
			case "1":
				menuInitWizard(store, exec, p, stdout, stderr)
			case "2":
				menuKernelManager(exec, p, stdout, stderr)
			case "3":
				menuClientNodes(store, exec, p, stdout, stderr)
			case "5":
				menuClientDNS(store, exec, p, stdout, stderr)
			case "8":
				menuChangeWebPort(store, exec, st, p, stdout, stderr)
			case "9":
				menuChangeWebPassword(store, st, p, stdout, stderr)
			case "0":
				menuUpdateComponents(store, exec, p, stdout, stderr)
			case "11":
				cmdNode(store, exec, []string{"show"}, stdout, stderr)
			case "22":
				menuRproxyClient(store, exec, p, stdout, stderr)
			case "44":
				menuRelayForwards(store, exec, p, stdout, stderr)
			case "66":
				menuClientWGAndDDNS(store, exec, p, stdout, stderr)
			case "a":
				menuApplyAndStatus(store, exec, stdout, stderr)
			default:
				fmt.Fprintf(stdout, "无效选项 %q\n", choice)
			}

		case state.RoleRelay:
			fmt.Fprintf(stdout, "转发规则: %d 条 | 内核: %s\n", len(st.Relay.Forwards), kernLine)
			fmt.Fprint(stdout, `
 1. 初始化 / 重装 DEX
 2. 内核管理             (查看状态 / 安装 Zabbly 主线内核)
 0. 更新 DEX 与规则库

22. 反向代理 (RproxyS)
44. TCP/UDP 端口转发
55. 附加协议 (Reality / Dokodemo / SOCKS5 等)
 a. 应用配置并查看状态 (Apply)
 q. 退出
────────────────────────────────────────────────
`)
			choice, ok := p.ask("Select", "q")
			if !ok || strings.EqualFold(choice, "q") {
				return 0
			}
			switch strings.ToLower(choice) {
			case "1":
				menuInitWizard(store, exec, p, stdout, stderr)
			case "2":
				menuKernelManager(exec, p, stdout, stderr)
			case "0":
				menuUpdateComponents(store, exec, p, stdout, stderr)
			case "22":
				menuRproxyServer(store, exec, p, stdout, stderr)
			case "44":
				menuRelayForwards(store, exec, p, stdout, stderr)
			case "55":
				menuExtraInbounds(store, exec, p, stdout, stderr)
			case "a":
				menuApplyAndStatus(store, exec, stdout, stderr)
			default:
				fmt.Fprintf(stdout, "无效选项 %q\n", choice)
			}

		default: // RoleServer / RoleLanding
			fmt.Fprintf(stdout, "节点: %s:%d (%s/%s) | 证书: %s | 内核: %s\n",
				st.Server.Domain, st.Server.EffectivePublicPort(),
				st.Server.TLSMode, st.Server.EffectiveProtocol(),
				readServerCertSummary(store, st), kernLine)
			fmt.Fprint(stdout, `
 1. 初始化 / 重装 DEX
 2. 内核管理             (查看状态 / 安装 Zabbly 主线内核)
 3. 域名、证书与端口协议
 4. 修改 Path & UUID
 8. 修改 Web 面板端口
 9. 修改 Web 登录密码
 0. 更新 DEX 与规则库

11. 查看节点信息与分享链接
22. 反向代理 (RproxyS)
35. SOCKS5 多出口分流
44. TCP/UDP 端口转发
55. 附加协议 (Reality / XHTTP / WS / SOCKS5 / Dokodemo)
 a. 应用配置并查看状态 (Apply)
 q. 退出
────────────────────────────────────────────────
`)
			choice, ok := p.ask("Select", "q")
			if !ok || strings.EqualFold(choice, "q") {
				return 0
			}
			switch strings.ToLower(choice) {
			case "1":
				menuInitWizard(store, exec, p, stdout, stderr)
			case "2":
				menuKernelManager(exec, p, stdout, stderr)
			case "3":
				menuServerDomainAndCert(store, exec, p, stdout, stderr)
			case "4":
				editMainUUIDAndPath(store, exec, p, stdout, stderr)
			case "8":
				menuChangeWebPort(store, exec, st, p, stdout, stderr)
			case "9":
				menuChangeWebPassword(store, st, p, stdout, stderr)
			case "0":
				menuUpdateComponents(store, exec, p, stdout, stderr)
			case "11":
				cmdNode(store, exec, []string{"show"}, stdout, stderr)
			case "22":
				menuRproxyServer(store, exec, p, stdout, stderr)
			case "35":
				menuSocks5Outbounds(store, exec, p, stdout, stderr)
			case "44":
				menuRelayForwards(store, exec, p, stdout, stderr)
			case "55":
				menuExtraInbounds(store, exec, p, stdout, stderr)
			case "a":
				menuApplyAndStatus(store, exec, stdout, stderr)
			default:
				fmt.Fprintf(stdout, "无效选项 %q\n", choice)
			}
		}
	}
	return 0
}

func menuApplyAndStatus(store *state.Store, exec reconcile.SystemExecutor, stdout, stderr io.Writer) {
	if _, isOS := exec.(reconcile.OSExecutor); isOS {
		if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, "", OpsConfig{}, stdout); err != nil {
			fmt.Fprintf(stderr, "bootstrap runtime dependencies failed: %v\n", err)
			return
		}
	}
	cmdApply(store, exec, nil, stdout, stderr)
	cmdStatus(store, exec, stdout, stderr)
}

func runRoleInitWizard(store *state.Store, exec reconcile.SystemExecutor, role string, stdin io.Reader, stdout, stderr io.Writer) int {
	p := newMenuPrompter(stdin, stdout)
	fmt.Fprintf(stdout, "\n── 初始化角色: %s ──\n", strings.ToUpper(role))
	return menuInitWizardForRole(store, exec, role, p, stdout, stderr)
}

func menuInitWizard(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	fmt.Fprint(stdout, "\n── 初始化 / 切换角色 ──\n1. Client (透明网关)\n2. Server (全功能服务端)\n3. Landing (轻量落地机)\n4. Relay (端口转发中转机)\n0. 返回\n")
	rc, ok := p.ask("选择角色", "1")
	if !ok || rc == "0" {
		return
	}
	roleMap := map[string]string{
		"1": state.RoleClient, "client": state.RoleClient, "-c": state.RoleClient, "c": state.RoleClient,
		"2": state.RoleServer, "server": state.RoleServer, "-s": state.RoleServer, "s": state.RoleServer,
		"3": state.RoleLanding, "landing": state.RoleLanding, "-l": state.RoleLanding, "l": state.RoleLanding,
		"4": state.RoleRelay, "relay": state.RoleRelay, "-r": state.RoleRelay, "r": state.RoleRelay,
	}
	r := roleMap[strings.ToLower(rc)]
	if r == "" {
		fmt.Fprintf(stdout, "无效角色 %q\n", rc)
		return
	}
	_ = menuInitWizardForRole(store, exec, r, p, stdout, stderr)
}

func menuInitWizardForRole(store *state.Store, exec reconcile.SystemExecutor, r string, p *menuPrompter, stdout, stderr io.Writer) int {
	args := []string{"--role", r}
	if _, err := os.Stat(store.StatePath()); err == nil {
		if !p.askYesNo("检测到已有配置，是否覆盖重建?", false) {
			return 0
		}
		args = append(args, "--force")
	}
	if r == state.RoleClient {
		var suggestedDoH string
		for {
			if p.eof {
				fmt.Fprintln(stderr, "client init requires Server node URI (pass --node <vless://...>)")
				return 1
			}
			nodeRaw, ok := p.ask("Server 节点链接 (必填，粘贴 Server 输出的 vless:// 或 vmess://，多个逗号分隔；0 取消)", "")
			if !ok {
				fmt.Fprintln(stderr, "client init requires Server node URI (pass --node <vless://...>)")
				return 1
			}
			if strings.TrimSpace(nodeRaw) == "0" {
				return 0
			}
			nodes, nerr := parseNodeURIList(nodeRaw)
			if nerr != nil {
				fmt.Fprintf(stdout, "请输入有效的 Server 节点链接 (%v)\n", nerr)
				continue
			}
			args = append(args, "--node", strings.TrimSpace(nodeRaw))
			var derived []string
			seen := make(map[string]struct{})
			for _, n := range nodes {
				if d := render.DeriveServerDoHFromNode(n); d != "" {
					if _, dup := seen[d]; !dup {
						seen[d] = struct{}{}
						derived = append(derived, d)
					}
				}
			}
			suggestedDoH = strings.Join(derived, ",")
			break
		}
		if suggestedDoH != "" {
			fmt.Fprintf(stdout, "[+] 已从节点链接自动获取自建 DoH: %s\n", suggestedDoH)
			args = append(args, "--doh", suggestedDoH)
		} else {
			for {
				if p.eof {
					fmt.Fprintln(stderr, "client init requires self-hosted DoH (pass --doh <url>)")
					return 1
				}
				dohRaw, ok := p.ask("自建 DoH 地址 (当前节点非 TLS 服务端，需手动填入，多个逗号分隔；0 取消)", "")
				if !ok {
					fmt.Fprintln(stderr, "client init requires self-hosted DoH (pass --doh <url>)")
					return 1
				}
				if strings.TrimSpace(dohRaw) == "0" {
					return 0
				}
				list, perr := parseAndNormalizeDoHList(dohRaw)
				if perr != nil {
					fmt.Fprintf(stdout, "请输入有效的自建 DoH 地址 (%v)\n", perr)
					continue
				}
				args = append(args, "--doh", strings.Join(list, ","))
				break
			}
		}
	}
	if r == state.RoleServer || r == state.RoleLanding {
		var domainVal string
		for {
			if p.eof {
				fmt.Fprintln(stderr, "aborted: domain input required (or pass --domain <dom>)")
				return 1
			}
			d, ok := p.ask("域名 (必填，例如 srv.example.com；0 取消)", "")
			if !ok {
				fmt.Fprintln(stderr, "aborted: domain input required (or pass --domain <dom>)")
				return 1
			}
			d = strings.TrimSpace(d)
			if d == "0" {
				return 0
			}
			if d == "" || !state.IsValidAddress(d) {
				fmt.Fprintln(stdout, "请输入有效的域名")
				continue
			}
			domainVal = d
			break
		}
		args = append(args, "--domain", domainVal)
		portStr, ok := p.ask("监听端口", "443")
		if !ok {
			return 1
		}
		if portStr != "" {
			args = append(args, "--port", portStr)
		}
	}
	if r == state.RoleServer || r == state.RoleLanding || r == state.RoleRelay {
		defV6 := isIPv6OnlyHost()
		if p.askYesNo("启用 IPv6 入站/转发?", defV6) {
			args = append(args, "--ipv6=true")
		}
	}
	if code := cmdInit(store, exec, args, stdout, stderr); code != 0 {
		return code
	}
	if _, isOS := exec.(reconcile.OSExecutor); isOS {
		if r == state.RoleServer || r == state.RoleLanding {
			fmt.Fprint(stdout, "\nTLS 证书配置 (Client 连接 Xray 与 DoH 均需有效 CA 证书):\n  1. Cloudflare DNS-01 自动签发 (推荐)\n  2. HTTP-01 自动签发 (需 80 端口指向本机)\n  3. 导入已有证书文件\n  0. 暂用自签证书，稍后在菜单 3 配置\n")
			if certChoice, ok := p.ask("选择证书方式", "0"); ok {
				stCur, _ := store.Load()
				dom := ""
				if stCur != nil {
					dom = stCur.Server.Domain
				}
				switch strings.TrimSpace(certChoice) {
				case "1":
					if tok, ok := p.ask("Cloudflare API Token", ""); ok && strings.TrimSpace(tok) != "" {
						cmdCert(store, exec, []string{"issue", "--mode", "cf", "--domain", dom, "--cf-token", strings.TrimSpace(tok)}, stdout, stderr)
					}
				case "2":
					cmdCert(store, exec, []string{"issue", "--mode", "http", "--domain", dom}, stdout, stderr)
				case "3":
					cPath, ok1 := p.ask("证书路径 (.cer/.pem)", "/root/de_GWD.cer")
					kPath, ok2 := p.ask("私钥路径 (.key)", "/root/de_GWD.key")
					if ok1 && ok2 && cPath != "" && kPath != "" {
						cmdCert(store, exec, []string{"import", cPath, kPath}, stdout, stderr)
					}
				}
			}
		}
		if p.askYesNo("立即安装运行依赖并应用配置?", true) {
			if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, r, OpsConfig{}, stdout); err != nil {
				fmt.Fprintf(stderr, "bootstrap runtime dependencies failed: %v\n", err)
				return 1
			}
			if code := cmdApply(store, exec, nil, stdout, stderr); code != 0 {
				return code
			}
			if r == state.RoleServer || r == state.RoleLanding {
				if stFinal, err := store.Load(); err == nil {
					printServerClientBootstrapInfo(stdout, store, stFinal)
				}
			}
		}
	}
	return 0
}

func editMainUUIDAndPath(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	st, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load state: %v\n", err)
		return
	}
	u, _ := cryptoext.GenerateUUID()
	u, ok := p.ask("新 UUID", u)
	if !ok {
		return
	}
	pathVal, ok := p.ask("新 Path", cryptoext.UUIDToDefaultPath(u))
	if !ok {
		return
	}
	if _, err := store.Update(st.Role, func(cur *state.State) error {
		if cur.Role == state.RoleServer || cur.Role == state.RoleLanding {
			cur.Server.UUIDs = []string{u}
			cur.Server.Path = pathVal
		} else if n := cur.Client.ActiveNode(); n != nil {
			n.UUID = u
			n.Path = pathVal
		}
		return nil
	}); err != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", err)
		return
	}
	fmt.Fprintln(stdout, "已更新 UUID 与 Path。")
	if p.askYesNo("立即应用配置?", false) {
		cmdApply(store, exec, nil, stdout, stderr)
	}
}

func menuChangeWebPort(store *state.Store, exec reconcile.SystemExecutor, st *state.State, p *menuPrompter, stdout, stderr io.Writer) {
	if st == nil {
		fmt.Fprintln(stderr, "请先初始化 DEX。")
		return
	}
	defPort := "8443"
	if st.Role == state.RoleClient {
		defPort = "443"
	}
	pStr, ok := p.ask("Web 面板端口", defPort)
	if !ok {
		return
	}
	portNum, perr := strconv.Atoi(pStr)
	if perr != nil || portNum < 1 || portNum > 65535 {
		fmt.Fprintln(stderr, "端口无效。")
		return
	}
	newAddr := ""
	if _, uerr := store.Update(st.Role, func(cur *state.State) error {
		host := ""
		if h, _, serr := net.SplitHostPort(cur.Auth.ListenAddr); serr == nil {
			host = h
		}
		if host == "" && cur.Role == state.RoleServer {
			host = "127.0.0.1"
		}
		if host == "" {
			newAddr = fmt.Sprintf(":%d", portNum)
		} else {
			newAddr = net.JoinHostPort(host, strconv.Itoa(portNum))
		}
		cur.Auth.ListenAddr = newAddr
		return nil
	}); uerr != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", uerr)
		return
	}
	fmt.Fprintf(stdout, "Web listen port set to %s\n", newAddr)
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

func menuChangeWebPassword(store *state.Store, st *state.State, p *menuPrompter, stdout, stderr io.Writer) {
	if st == nil {
		fmt.Fprintln(stderr, "请先初始化 DEX。")
		return
	}
	pw, ok := p.ask("新 Web 登录密码 (至少 6 位)", "")
	if !ok {
		return
	}
	if len(pw) < 6 {
		fmt.Fprintln(stderr, "密码过短。")
		return
	}
	h, herr := cryptoext.HashPassword(pw)
	if herr != nil {
		fmt.Fprintf(stderr, "hash password failed: %v\n", herr)
		return
	}
	if _, uerr := store.Update(st.Role, func(cur *state.State) error {
		cur.Auth.PasswordHash = h
		return nil
	}); uerr != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", uerr)
		return
	}
	fmt.Fprintln(stdout, "登录密码已更新。")
}

func menuServerDomainAndCert(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "\n── 域名、证书与服务端 ──\n域名: %s | 端口: %d (外部 %d) | 模式: %s/%s | 证书: %s\n",
			st.Server.Domain, st.Server.ListenPort, st.Server.EffectivePublicPort(),
			st.Server.TLSMode, st.Server.EffectiveProtocol(), readServerCertSummary(store, st))
		fmt.Fprint(stdout, "1. 查看证书详情\n2. ACME 签发证书 (CF / HTTP)\n3. 导入已有证书\n4. 重新生成自签证书\n5. 修改域名、端口或协议\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			cmdCert(store, exec, []string{"inspect"}, stdout, stderr)
		case "2":
			fmt.Fprint(stdout, "验证方式: 1. Cloudflare DNS-01  2. HTTP-01\n")
			mc, ok := p.ask("选择方式", "1")
			if !ok {
				return
			}
			d, ok := p.ask("域名", st.Server.Domain)
			if !ok || d == "" {
				continue
			}
			if mc == "2" || strings.EqualFold(mc, "http") {
				wr, ok := p.ask("Webroot 目录 (留空使用独立验证端口 80)", "")
				if !ok {
					return
				}
				args := []string{"issue", "--mode", "http", "--domain", d}
				if wr != "" {
					args = append(args, "--webroot", wr)
				}
				cmdCert(store, exec, args, stdout, stderr)
			} else {
				tok, ok := p.ask("Cloudflare API Token", "")
				if !ok || tok == "" {
					continue
				}
				cmdCert(store, exec, []string{"issue", "--mode", "cf", "--domain", d, "--cf-token", tok}, stdout, stderr)
			}
		case "3":
			c, ok := p.ask("证书路径 (.cer/.pem)", "/root/de_GWD.cer")
			if !ok {
				return
			}
			k, ok := p.ask("私钥路径 (.key)", "/root/de_GWD.key")
			if !ok {
				return
			}
			cmdCert(store, exec, []string{"import", c, k}, stdout, stderr)
		case "4":
			cmdCert(store, exec, []string{"self-sign", "--force"}, stdout, stderr)
		case "5":
			d, ok := p.ask("域名 (留空保留当前)", "")
			if !ok {
				return
			}
			lp, ok := p.ask("监听端口 (留空保留当前)", "")
			if !ok {
				return
			}
			pp, ok := p.ask("外部映射端口 (留空保留当前)", "")
			if !ok {
				return
			}
			fmt.Fprint(stdout, "传输协议: 0. 保持不变  1. vless-xhttp  2. vless-ws  3. vmess-ws\n")
			prChoice, ok := p.ask("选择协议", "0")
			if !ok {
				return
			}
			protoMap := map[string]string{"1": "vless-xhttp", "2": "vless-ws", "3": "vmess-ws"}
			args := []string{"set"}
			if d != "" {
				args = append(args, "--domain", d)
			}
			if lp != "" {
				args = append(args, "--port", lp)
			}
			if pp != "" {
				args = append(args, "--public-port", pp)
			}
			if proto := protoMap[prChoice]; proto != "" {
				args = append(args, "--protocol", proto)
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdServer(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuClientNodes(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "\n── 节点管理 (%d 个节点) ──\n", len(st.Client.Nodes))
		if len(st.Client.Nodes) == 0 {
			fmt.Fprintln(stdout, "当前暂无节点。")
		} else {
			for i, n := range st.Client.Nodes {
				mark := " "
				if n.ID == st.Client.ActiveNodeID {
					mark = "*"
				}
				fmt.Fprintf(stdout, " %s [%d] %-12s %-14s %-13s %s:%d\n", mark, i+1, n.ID, n.Name, n.Protocol, n.Address, n.Port)
			}
		}
		fmt.Fprint(stdout, "\n1. 切换活动节点\n2. 节点延迟测速\n3. 通过分享链接添加节点\n4. 删除节点\n5. 修改当前节点 UUID·Path\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			target, ok := p.pickNodeID(st.Client.Nodes, "输入序号或节点 ID")
			if !ok || target == "" {
				continue
			}
			args := []string{"select", target}
			if p.askYesNo("立即切换并应用?", true) {
				args = append(args, "--apply")
			}
			cmdNode(store, exec, args, stdout, stderr)
		case "2":
			cmdNode(store, exec, []string{"probe"}, stdout, stderr)
		case "3":
			uri, ok := p.ask("分享链接 (vless:// 或 vmess://)", "")
			if !ok || uri == "" {
				continue
			}
			name, ok := p.ask("节点名称 (留空使用链接备注)", "")
			if !ok {
				return
			}
			args := []string{"add", "--from-uri", uri}
			if name != "" {
				args = append(args, "--name", name)
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdNode(store, exec, args, stdout, stderr)
		case "4":
			target, ok := p.pickNodeID(st.Client.Nodes, "输入要删除的序号或节点 ID")
			if !ok || target == "" {
				continue
			}
			args, ok := p.maybeApply([]string{"del", target})
			if !ok {
				return
			}
			cmdNode(store, exec, args, stdout, stderr)
		case "5":
			editMainUUIDAndPath(store, exec, p, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func (p *menuPrompter) pickNodeID(nodes []state.OutboundNode, prompt string) (string, bool) {
	if len(nodes) == 0 {
		fmt.Fprintln(p.stdout, "当前没有可选节点。")
		return "", true
	}
	v, ok := p.ask(prompt, "")
	if !ok || v == "" {
		return "", ok
	}
	if idx, err := strconv.Atoi(v); err == nil && idx >= 1 && idx <= len(nodes) {
		return nodes[idx-1].ID, true
	}
	return v, true
}

func menuExtraInbounds(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "\n── 附加协议入站 (%d 个) ──\n", len(st.ExtraInbounds))
		if len(st.ExtraInbounds) == 0 {
			fmt.Fprintln(stdout, "当前无附加协议。")
		} else {
			for i, ex := range st.ExtraInbounds {
				fmt.Fprintf(stdout, " [%d] %-20s %-14s :%d\n", i+1, ex.Tag, ex.Protocol, ex.ListenPort)
			}
		}
		fmt.Fprint(stdout, "\n1. 添加 Reality\n2. 添加 XHTTP\n3. 添加 VLESS-WS\n4. 添加 VMess-WS\n5. 添加 Dokodemo\n6. 添加 SOCKS5\n7. 删除指定入站\n8. 停用全部附加协议\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			pStr, ok := p.ask("监听端口", "2443")
			if !ok {
				return
			}
			sni, ok := p.ask("Reality SNI", "www.apple.com")
			if !ok {
				return
			}
			args, ok := p.maybeApply([]string{"add-reality", "--port", pStr, "--sni", sni})
			if !ok {
				return
			}
			cmdExtra(store, exec, args, stdout, stderr)
		case "2", "3", "4":
			protoMap := map[string]string{"2": "add-xhttp", "3": "add-vless-ws", "4": "add-vmess-ws"}
			pStr, ok := p.ask("监听端口", "")
			if !ok || pStr == "" {
				continue
			}
			dom, ok := p.ask("TLS 域名 (留空复用主域名)", "")
			if !ok {
				return
			}
			pathVal, ok := p.ask("Path (留空自动生成)", "")
			if !ok {
				return
			}
			args := []string{protoMap[sub], "--port", pStr}
			if dom != "" {
				args = append(args, "--domain", dom)
			}
			if pathVal != "" {
				args = append(args, "--path", pathVal)
			}
			if p.askYesNo("经由 Nginx 反代共享端口?", false) {
				args = append(args, "--via-nginx")
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdExtra(store, exec, args, stdout, stderr)
		case "5":
			pStr, ok := p.ask("监听端口", "")
			if !ok || pStr == "" {
				continue
			}
			tgt, ok := p.ask("目标地址 (host:port)", "")
			if !ok || tgt == "" {
				continue
			}
			netProto, ok := p.pickProto()
			if !ok {
				return
			}
			args, ok := p.maybeApply([]string{"add-dokodemo", "--port", pStr, "--target", tgt, "--network", netProto})
			if !ok {
				return
			}
			cmdExtra(store, exec, args, stdout, stderr)
		case "6":
			pStr, ok := p.ask("监听端口", "1080")
			if !ok {
				return
			}
			u, ok := p.ask("用户名 (可选)", "")
			if !ok {
				return
			}
			pw, ok := p.ask("密码 (可选)", "")
			if !ok {
				return
			}
			args, ok := p.maybeApply([]string{"add-socks5", "--port", pStr, "--user", u, "--pass", pw})
			if !ok {
				return
			}
			cmdExtra(store, exec, args, stdout, stderr)
		case "7":
			if len(st.ExtraInbounds) == 0 {
				continue
			}
			k, ok := p.ask("输入序号、Tag 或端口", "")
			if !ok || k == "" {
				continue
			}
			if idx, err := strconv.Atoi(k); err == nil && idx >= 1 && idx <= len(st.ExtraInbounds) {
				k = st.ExtraInbounds[idx-1].Tag
			}
			args, ok := p.maybeApply([]string{"del", k})
			if !ok {
				return
			}
			cmdExtra(store, exec, args, stdout, stderr)
		case "8":
			if !p.askYesNo("确认停用全部附加协议?", false) {
				continue
			}
			args, ok := p.maybeApply([]string{"disable-all"})
			if !ok {
				return
			}
			cmdExtra(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuRproxyServer(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		fmt.Fprintln(stdout, "\n── 反向代理 RproxyS (服务端) ──")
		if !st.RproxyS.Enabled {
			fmt.Fprintln(stdout, "状态: 未启用")
		} else {
			dom := firstNonEmpty(st.RproxyS.Domain, "(未指定域名)")
			fmt.Fprintf(stdout, "状态: 已启用 | 隧道端口: :%d | 域名: %s | 映射: %d 条\n",
				st.RproxyS.ListenPort, dom, len(st.RproxyS.Mappings))
			for i, m := range st.RproxyS.Mappings {
				fmt.Fprintf(stdout, " [%d] 公网 :%d (%s)\n", i+1, m.Port, m.Proto)
			}
		}
		fmt.Fprint(stdout, "\n1. 配置并启用隧道\n2. 添加端口映射\n3. 删除端口映射\n4. 停用 RproxyS\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			d, ok := p.ask("隧道域名 (可选)", "")
			if !ok {
				return
			}
			portStr, ok := p.ask("隧道监听端口", "20000")
			if !ok {
				return
			}
			args := []string{"set", "--port", portStr}
			if d != "" {
				args = append(args, "--domain", d)
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		case "2":
			portStr, ok := p.ask("公网映射端口", "")
			if !ok || portStr == "" {
				continue
			}
			pr, ok := p.pickProto()
			if !ok {
				return
			}
			args, ok := p.maybeApply([]string{"map-add", "--port", portStr, "--proto", pr})
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		case "3":
			if len(st.RproxyS.Mappings) == 0 {
				fmt.Fprintln(stdout, "当前无端口映射。")
				continue
			}
			portStr, ok := p.ask("输入序号或公网端口", "")
			if !ok || portStr == "" {
				continue
			}
			if idx, err := strconv.Atoi(portStr); err == nil && idx >= 1 && idx <= len(st.RproxyS.Mappings) {
				portStr = strconv.Itoa(st.RproxyS.Mappings[idx-1].Port)
			}
			args, ok := p.maybeApply([]string{"map-del", portStr})
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		case "4":
			if !p.askYesNo("确认停用 RproxyS?", false) {
				continue
			}
			args, ok := p.maybeApply([]string{"disable"})
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuRproxyClient(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		rc := st.Client.RproxyC
		fmt.Fprintln(stdout, "\n── 反向代理 RproxyC (客户端) ──")
		if !rc.Enabled {
			fmt.Fprintln(stdout, "状态: 未启用")
		} else {
			fmt.Fprintf(stdout, "状态: 已启用 | 隧道: %s:%d | 映射: %d 条\n",
				rc.TunnelAddress, rc.TunnelPort, len(rc.Mappings))
			for i, m := range rc.Mappings {
				fmt.Fprintf(stdout, " [%d] 公网 :%d (%s) -> %s:%d\n", i+1, m.ExtPort, m.Proto, m.IntIP, m.IntPort)
			}
		}
		fmt.Fprint(stdout, "\n1. 配置并启用隧道\n2. 添加内网映射\n3. 删除内网映射\n4. 停用 RproxyC\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			addr, ok := p.ask("RproxyS 服务端地址", rc.TunnelAddress)
			if !ok || addr == "" {
				continue
			}
			portDef := "20000"
			if rc.TunnelPort > 0 {
				portDef = strconv.Itoa(rc.TunnelPort)
			}
			portStr, ok := p.ask("隧道端口", portDef)
			if !ok {
				return
			}
			uuidStr, ok := p.ask("隧道 UUID", rc.TunnelUUID)
			if !ok {
				return
			}
			args := []string{"client-set", "--address", addr, "--port", portStr}
			if uuidStr != "" {
				args = append(args, "--uuid", uuidStr)
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		case "2":
			extPort, ok := p.ask("远端公网端口", "")
			if !ok || extPort == "" {
				continue
			}
			intTarget, ok := p.ask("内网目标 (ip:port)", "")
			if !ok || intTarget == "" {
				continue
			}
			pr, ok := p.pickProto()
			if !ok {
				return
			}
			args, ok := p.maybeApply([]string{"client-map-add", "--ext-port", extPort, "--int", intTarget, "--proto", pr})
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		case "3":
			if len(rc.Mappings) == 0 {
				fmt.Fprintln(stdout, "当前无内网映射。")
				continue
			}
			epStr, ok := p.ask("输入序号或远端公网端口", "")
			if !ok || epStr == "" {
				continue
			}
			if idx, err := strconv.Atoi(epStr); err == nil && idx >= 1 && idx <= len(rc.Mappings) {
				epStr = strconv.Itoa(rc.Mappings[idx-1].ExtPort)
			}
			args, ok := p.maybeApply([]string{"client-map-del", epStr})
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		case "4":
			if !p.askYesNo("确认停用 RproxyC?", false) {
				continue
			}
			args, ok := p.maybeApply([]string{"client-disable"})
			if !ok {
				return
			}
			cmdRproxy(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuRelayForwards(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "\n── TCP/UDP 端口转发 (%d 条) ──\n", len(st.Relay.Forwards))
		if len(st.Relay.Forwards) == 0 {
			fmt.Fprintln(stdout, "当前无转发规则。")
		} else {
			for i, f := range st.Relay.Forwards {
				fmt.Fprintf(stdout, " [%d] %-12s :%d -> %s:%d (%s / %s)\n", i+1, f.ID, f.ListenPort, f.TargetHost, f.TargetPort, f.Proto, f.Engine)
			}
		}
		fmt.Fprint(stdout, "\n1. 添加转发规则\n2. 删除转发规则\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			lp, ok := p.ask("本地监听端口", "10001")
			if !ok {
				return
			}
			th, ok := p.ask("目标主机 / IP", "")
			if !ok || th == "" {
				continue
			}
			tp, ok := p.ask("目标端口", "443")
			if !ok {
				return
			}
			pr, ok := p.pickProto()
			if !ok {
				return
			}
			fmt.Fprint(stdout, "转发引擎: 1. nft (内核级)  2. haproxy (仅 TCP)  3. xray\n")
			ec, ok := p.ask("选择引擎", "1")
			if !ok {
				return
			}
			eng := "nft"
			switch ec {
			case "2", "haproxy":
				eng = "haproxy"
			case "3", "xray":
				eng = "xray"
			}
			args, ok := p.maybeApply([]string{"add", "--listen", lp, "--target-host", th, "--target-port", tp, "--proto", pr, "--engine", eng})
			if !ok {
				return
			}
			cmdRelay(store, exec, args, stdout, stderr)
		case "2":
			if len(st.Relay.Forwards) == 0 {
				continue
			}
			k, ok := p.ask("输入序号、规则 ID 或监听端口", "")
			if !ok || k == "" {
				continue
			}
			if idx, err := strconv.Atoi(k); err == nil && idx >= 1 && idx <= len(st.Relay.Forwards) {
				k = st.Relay.Forwards[idx-1].ID
			}
			args, ok := p.maybeApply([]string{"del", k})
			if !ok {
				return
			}
			cmdRelay(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuSocks5Outbounds(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		profiles := st.Server.Socks5Outbounds
		fmt.Fprintf(stdout, "\n── SOCKS5 多出口分流 (%d 个) ──\n", len(profiles))
		if len(profiles) == 0 {
			fmt.Fprintln(stdout, "当前无 SOCKS5 出口配置。")
		} else {
			for i, prof := range profiles {
				stLabel := "停用"
				if prof.Enabled {
					stLabel = "启用"
				}
				fmt.Fprintf(stdout, " [%d] %-12s [%s] %s (域名:%d IP:%d)\n",
					i+1, prof.Name, stLabel, state.FormatEndpoint(prof.Address, prof.Port), len(prof.Domains), len(prof.IPs))
			}
		}
		fmt.Fprint(stdout, "\n1. 添加出口配置\n2. 启用 / 停用出口\n3. 测试出口连通性\n4. 删除出口\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			n, ok := p.ask("配置名称", "default")
			if !ok {
				return
			}
			ep, ok := p.ask("出口地址 (socks5://user:pass@host:port 或 host:port)", "")
			if !ok || ep == "" {
				continue
			}
			dom, ok := p.ask("域名分流规则 (@ai,@stream,@tg 或留空)", "")
			if !ok {
				return
			}
			ip, ok := p.ask("IP 分流规则 (@tg,CIDR 或留空)", "")
			if !ok {
				return
			}
			args := []string{"add", "--name", n, "--endpoint", ep, "--domains", dom, "--ips", ip}
			if !p.askYesNo("跳过私有网段 (Private Bypass)?", true) {
				args = append(args, "--private-bypass=false")
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdSocks5(store, exec, args, stdout, stderr)
		case "2":
			target, ok := pickSocks5Name(p, profiles)
			if !ok || target == "" {
				continue
			}
			args, ok := p.maybeApply([]string{"toggle", target})
			if !ok {
				return
			}
			cmdSocks5(store, exec, args, stdout, stderr)
		case "3":
			cmdSocks5(store, exec, []string{"test"}, stdout, stderr)
		case "4":
			target, ok := pickSocks5Name(p, profiles)
			if !ok || target == "" {
				continue
			}
			args, ok := p.maybeApply([]string{"del", target})
			if !ok {
				return
			}
			cmdSocks5(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func pickSocks5Name(p *menuPrompter, profiles []state.Socks5Profile) (string, bool) {
	if len(profiles) == 0 {
		fmt.Fprintln(p.stdout, "当前没有可选出口。")
		return "", true
	}
	v, ok := p.ask("输入序号或配置名称", "")
	if !ok || v == "" {
		return "", ok
	}
	if idx, err := strconv.Atoi(v); err == nil && idx >= 1 && idx <= len(profiles) {
		return profiles[idx-1].Name, true
	}
	return v, true
}

func menuClientWGAndDDNS(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		fmt.Fprint(stdout, "\n── WireGuard 与 DDNS ──\n1. WireGuard 回家 VPN\n2. Cloudflare DDNS\n0. 返回\n")
		sub, ok := p.ask("选择模块", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			menuWireGuard(store, exec, p, stdout, stderr)
		case "2":
			menuDDNS(store, exec, p, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuWireGuard(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		wg := st.Client.WireGuard
		fmt.Fprintln(stdout, "\n── WireGuard 回家 VPN ──")
		if !wg.Enabled {
			fmt.Fprintf(stdout, "状态: 未启用 | 已保存 Peer: %d\n", len(wg.Peers))
		} else {
			fmt.Fprintf(stdout, "状态: 已启用 | 端口: :%d | 端点: %s | Peer: %d\n", wg.ListenPort, wg.EndpointHost, len(wg.Peers))
		}
		for i, peer := range wg.Peers {
			fmt.Fprintf(stdout, " [%d] %-12s %s\n", i+1, peer.Name, peer.IP)
		}
		fmt.Fprint(stdout, "\n1. 启用 WireGuard\n2. 添加客户端 Peer\n3. 重置 Peer 密钥\n4. 删除 Peer\n5. 重置服务端密钥\n6. 查看 Peer 配置详情\n7. 停用 WireGuard\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			ep, ok := p.ask("公网访问域名或 IP", wg.EndpointHost)
			if !ok {
				return
			}
			args := []string{"enable"}
			if ep != "" {
				args = append(args, "--endpoint", ep)
			}
			args, ok = p.maybeApply(args)
			if !ok {
				return
			}
			cmdWG(store, exec, args, stdout, stderr)
		case "2":
			n, ok := p.ask("客户端名称", "laptop")
			if !ok || n == "" {
				continue
			}
			args, ok := p.maybeApply([]string{"peer-add", n})
			if !ok {
				return
			}
			cmdWG(store, exec, args, stdout, stderr)
		case "3":
			n, ok := pickWGPeerName(p, wg.Peers)
			if !ok || n == "" {
				continue
			}
			args, ok := p.maybeApply([]string{"peer-regen", n})
			if !ok {
				return
			}
			cmdWG(store, exec, args, stdout, stderr)
		case "4":
			n, ok := pickWGPeerName(p, wg.Peers)
			if !ok || n == "" {
				continue
			}
			args, ok := p.maybeApply([]string{"peer-del", n})
			if !ok {
				return
			}
			cmdWG(store, exec, args, stdout, stderr)
		case "5":
			if !p.askYesNo("确认重新生成服务端密钥对?", false) {
				continue
			}
			args, ok := p.maybeApply([]string{"keygen-server"})
			if !ok {
				return
			}
			cmdWG(store, exec, args, stdout, stderr)
		case "6":
			if len(wg.Peers) == 0 {
				cmdWG(store, exec, []string{"show"}, stdout, stderr)
				continue
			}
			n, ok := pickWGPeerName(p, wg.Peers)
			if !ok {
				return
			}
			if n == "" {
				cmdWG(store, exec, []string{"show"}, stdout, stderr)
			} else {
				cmdWG(store, exec, []string{"show", n}, stdout, stderr)
			}
		case "7":
			args, ok := p.maybeApply([]string{"disable"})
			if !ok {
				return
			}
			cmdWG(store, exec, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func pickWGPeerName(p *menuPrompter, peers []state.WGPeer) (string, bool) {
	if len(peers) == 0 {
		fmt.Fprintln(p.stdout, "当前没有 Peer。")
		return "", true
	}
	v, ok := p.ask("输入序号或 Peer 名称", "")
	if !ok || v == "" {
		return "", ok
	}
	if idx, err := strconv.Atoi(v); err == nil && idx >= 1 && idx <= len(peers) {
		return peers[idx-1].Name, true
	}
	return v, true
}

func menuDDNS(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		dd := st.Client.DDNS
		fmt.Fprintln(stdout, "\n── Cloudflare DDNS ──")
		if !dd.Enabled {
			fmt.Fprintln(stdout, "状态: 未启用")
		} else {
			fmt.Fprintf(stdout, "状态: 已启用 | 域名: %s | IPv6(AAAA): %v\n", dd.Domain, dd.EnableIPv6)
		}
		fmt.Fprint(stdout, "\n1. 配置并启用 DDNS\n2. 立即同步一次\n3. 停用 DDNS\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			d, ok := p.ask("域名", dd.Domain)
			if !ok || d == "" {
				continue
			}
			t, ok := p.ask("Cloudflare API Token", "")
			if !ok || t == "" {
				continue
			}
			args := []string{"set", "--domain", d, "--token", t}
			if p.askYesNo("同时更新 IPv6 (AAAA)?", dd.EnableIPv6) {
				args = append(args, "--ipv6")
			}
			cmdDDNS(store, exec, args, stdout, stderr)
		case "2":
			cmdDDNS(store, exec, []string{"sync"}, stdout, stderr)
		case "3":
			cmdDDNS(store, exec, []string{"disable"}, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuKernelManager(exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		fmt.Fprintln(stdout, "\n── 内核管理 ──")
		info := InspectKernel(context.Background(), exec, KernelConfig{})
		printKernelStatus(info, stdout)
		fmt.Fprint(stdout, "\n1. 刷新内核与环境检查\n2. 安装 Zabbly 主线内核\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			continue
		case "2":
			if !info.Eligible {
				fmt.Fprintf(stderr, "当前环境不可安装: %s\n", info.BlockReason)
				continue
			}
			if !p.askYesNo("确认安装 linux-zabbly 主线内核?", false) {
				continue
			}
			args := []string{"zabbly"}
			if p.askYesNo("安装完成后立即重启服务器?", false) {
				args = append(args, "--reboot")
			}
			cmdKernelWithConfig(exec, KernelConfig{}, args, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

func menuUpdateComponents(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		fmt.Fprint(stdout, "\n── 更新组件与规则 ──\n1. 更新全部核心组件 (dex / xray / mosdns / rules)\n2. 单独更新组件\n3. 热更新路由规则库 (rules)\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		switch sub {
		case "1":
			ver, ok := p.ask("目标版本标签", "latest")
			if !ok {
				return
			}
			cmdUpdate(store, exec, []string{"--component", "all", "--version", ver}, stdout, stderr)
		case "2":
			fmt.Fprint(stdout, "组件: 1. dex  2. xray  3. mosdns  4. rules\n")
			cc, ok := p.ask("选择组件", "1")
			if !ok {
				return
			}
			compMap := map[string]string{"1": "dex", "2": "xray", "3": "mosdns", "4": "rules"}
			comp := compMap[cc]
			if comp == "" {
				fmt.Fprintf(stdout, "无效选项 %q\n", cc)
				continue
			}
			ver, ok := p.ask("目标版本标签", "latest")
			if !ok {
				return
			}
			cmdUpdate(store, exec, []string{"--component", comp, "--version", ver}, stdout, stderr)
		case "3":
			cmdRules(store, exec, []string{"update"}, stdout, stderr)
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
		}
	}
}

// bootstrapRoleRuntimeDeps installs missing OS packages, core binaries, and rule datasets for role.
func bootstrapRoleRuntimeDeps(ctx context.Context, store *state.Store, exec reconcile.SystemExecutor, role string, opsCfg OpsConfig, stdout io.Writer) error {
	if exec == nil {
		return nil
	}
	cfg := opsCfg.withDefaults("latest")
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" && store != nil {
		if st, err := store.Load(); err == nil && st != nil {
			role = st.Role
		}
	}
	if role == "" {
		return nil
	}

	var missingPkgs []string
	switch role {
	case state.RoleClient:
		if !exec.HasCommand("wg-quick") {
			missingPkgs = append(missingPkgs, "wireguard-tools")
		}
	case state.RoleServer:
		if !exec.HasCommand("nginx") {
			missingPkgs = append(missingPkgs, "nginx")
		}
		if !exec.HasCommand("socat") {
			missingPkgs = append(missingPkgs, "socat")
		}
		if !exec.HasCommand("wg-quick") {
			missingPkgs = append(missingPkgs, "wireguard-tools")
		}
	case state.RoleRelay:
		if !exec.HasCommand("haproxy") {
			missingPkgs = append(missingPkgs, "haproxy")
		}
	}
	if len(missingPkgs) > 0 {
		if stdout != nil {
			fmt.Fprintf(stdout, "[*] Installing missing packages for %s (%s)...\n", role, strings.Join(missingPkgs, ", "))
		}
		if err := installSystemPackages(ctx, exec, missingPkgs); err != nil {
			return err
		}
	}
	if role == state.RoleServer {
		_ = os.Remove("/etc/nginx/sites-enabled/default")
	}

	if !exec.HasCommand(cfg.XrayBinPath) {
		if err := UpdateComponents(ctx, store, exec, cfg, "xray", "latest", stdout); err != nil {
			return fmt.Errorf("install xray: %w", err)
		}
	}

	rulesDir := "/etc/dex/rules"
	if store != nil {
		rulesDir = filepath.Join(store.Dir, "rules")
	}
	switch role {
	case state.RoleClient:
		if !exec.HasCommand(cfg.MosDNSBinPath) {
			if err := UpdateComponents(ctx, store, exec, cfg, "mosdns", "latest", stdout); err != nil {
				return fmt.Errorf("install mosdns: %w", err)
			}
		}
		if clientRulesMissing(store, rulesDir) {
			if err := UpdateRules(ctx, store, exec, cfg, false, true, stdout); err != nil {
				return fmt.Errorf("install client rules: %w", err)
			}
		}
	case state.RoleServer, state.RoleLanding, state.RoleRelay:
		if err := ensureGeoDatRules(ctx, cfg, rulesDir, stdout); err != nil {
			return err
		}
	}
	return nil
}

func installSystemPackages(ctx context.Context, exec reconcile.SystemExecutor, pkgs []string) error {
	if len(pkgs) == 0 {
		return nil
	}
	if exec.HasCommand("apk") {
		args := append([]string{"add", "--no-cache"}, pkgs...)
		if out, err := exec.RunCommand(ctx, nil, "apk", args...); err != nil {
			return fmt.Errorf("apk add %s: %w (%s)", strings.Join(pkgs, " "), err, strings.TrimSpace(out))
		}
		return nil
	}
	if exec.HasCommand("apt-get") {
		env := []string{"DEBIAN_FRONTEND=noninteractive"}
		_, _ = exec.RunCommand(ctx, env, "apt-get", "update", "-qq")
		args := append([]string{"install", "-y", "-qq", "--no-install-recommends"}, pkgs...)
		if out, err := exec.RunCommand(ctx, env, "apt-get", args...); err != nil {
			return fmt.Errorf("apt-get install %s: %w (%s)", strings.Join(pkgs, " "), err, strings.TrimSpace(out))
		}
		return nil
	}
	return nil
}

func clientRulesMissing(store *state.Store, rulesDir string) bool {
	required := append([]string(nil), state.RequiredClientBaseRuleFiles...)
	if store != nil {
		if st, err := store.Load(); err == nil && st != nil && st.Client.DNS.BlockAds {
			required = append(required, "Domains.ads.txt")
		}
	}
	for _, name := range required {
		info, err := os.Stat(filepath.Join(rulesDir, name))
		if err != nil || info.IsDir() || info.Size() == 0 {
			return true
		}
	}
	return false
}

func ensureGeoDatRules(ctx context.Context, cfg OpsConfig, rulesDir string, stdout io.Writer) error {
	targets := []struct {
		name string
		url  string
		dst  string
	}{
		{name: "geoip.dat", url: cfg.GeoIPURL, dst: filepath.Join(rulesDir, "geoip.dat")},
		{name: "geosite.dat", url: cfg.GeoSiteURL, dst: filepath.Join(rulesDir, "geosite.dat")},
	}
	var missingIdx []int
	for i, t := range targets {
		if info, err := os.Stat(t.dst); err != nil || info.IsDir() || info.Size() == 0 {
			missingIdx = append(missingIdx, i)
		}
	}
	if len(missingIdx) == 0 {
		return nil
	}
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	for _, i := range missingIdx {
		t := targets[i]
		if stdout != nil {
			fmt.Fprintf(stdout, "[*] Downloading %s (SHA256 verified)...\n", t.name)
		}
		if err := DownloadVerifiedFile(ctx, cfg.Client, t.url, t.url+".sha256sum", t.dst, false); err != nil {
			return fmt.Errorf("download %s: %w", t.name, err)
		}
	}
	return nil
}

func menuClientDNS(store *state.Store, exec reconcile.SystemExecutor, p *menuPrompter, stdout, stderr io.Writer) {
	for !p.eof {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return
		}
		hostname, _ := os.Hostname()
		dohURL := render.BuildDoHURL(st, hostname)
		if dohURL == "" {
			dohURL = "(已关闭)"
		}
		fmt.Fprintf(stdout, "\n── 本机 DoH 与 DNS ──\n本机 DoH: %v (%s) | 去广告: %v | 禁外部53: %v\n本机 DoH 端点: %s\n国外自建 DoH:  %s\n",
			st.Client.DNS.EnableDoHServer, st.Client.DNS.EffectiveDoHPath(),
			st.Client.DNS.BlockAds, st.Client.DNS.BlockExternal53, dohURL,
			strings.Join(st.Client.DNS.DoHServers, ", "))
		fmt.Fprint(stdout, "1. 开启/关闭本机 DoH 服务端\n2. 自定义本机 DoH 路径 (如 /dq 或 /dq-xxxxxx)\n3. 重新生成随机 DoH 私密路径\n4. 开启/关闭广告域名屏蔽\n5. 修改国外自建 DoH 上游 (doh_servers)\n0. 返回\n")
		sub, ok := p.ask("操作", "0")
		if !ok || sub == "0" {
			return
		}
		var args []string
		switch sub {
		case "1":
			args = []string{"set", fmt.Sprintf("--enable-doh-server=%v", !st.Client.DNS.EnableDoHServer)}
		case "2":
			np, ok := p.ask("输入新路径", st.Client.DNS.EffectiveDoHPath())
			if !ok || strings.TrimSpace(np) == "" {
				continue
			}
			args = []string{"set", "--doh-path", strings.TrimSpace(np)}
		case "3":
			args = []string{"set", "--regen-doh-path"}
		case "4":
			args = []string{"set", fmt.Sprintf("--block-ads=%v", !st.Client.DNS.BlockAds)}
		case "5":
			nd, ok := p.ask("输入自建 DoH 地址 (多个用逗号分隔)", strings.Join(st.Client.DNS.DoHServers, ", "))
			if !ok || strings.TrimSpace(nd) == "" {
				continue
			}
			args = []string{"set", "--doh", strings.TrimSpace(nd)}
		default:
			fmt.Fprintf(stdout, "无效选项 %q\n", sub)
			continue
		}
		args, ok = p.maybeApply(args)
		if !ok {
			return
		}
		cmdDNS(store, exec, args, stdout, stderr)
	}
}

var _ = render.RenderAll // ensure render imported for helper completeness
