package cli

import (
	"bufio"
	"context"
	"fmt"
	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
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
	certFile, keyFile := reconcile.ResolveActiveCertPaths(store, st)
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
