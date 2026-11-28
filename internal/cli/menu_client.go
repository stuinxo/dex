package cli

import (
	"fmt"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"io"
	"os"
	"strconv"
	"strings"
)

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
