package render

import (
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func TestExtraShareContract(t *testing.T) {
	for _, protocol := range []string{"vless-reality", "vless-xhttp", "vless-ws", "vmess-ws", "socks5"} {
		t.Run(protocol, func(t *testing.T) {
			ex := state.ExtraInbound{Tag: "share", Protocol: protocol, Domain: " node.example.com ", ListenPort: 2443, UUID: "11111111-1111-4111-8111-111111111111", RealitySNI: " www.apple.com ", RealityPubKey: "public", RealityShortID: "abcd", SocksUser: "user", SocksPass: "pass"}
			path := ex.Path
			if protocol == "vless-xhttp" || protocol == "vless-ws" || protocol == "vmess-ws" {
				path = NormalizePath(path, ex.UUID)
			}
			want := BuildNodeURI(state.OutboundNode{Name: ex.Tag, Protocol: protocol, Address: "node.example.com", Port: ex.ListenPort, UUID: ex.UUID, TLSSNI: "www.apple.com", Path: path, RealityPubKey: ex.RealityPubKey, RealityShortID: ex.RealityShortID, Username: ex.SocksUser, Password: ex.SocksPass})
			if got := BuildExtraURI(nil, ex); got != want || got == "" {
				t.Fatalf("share contract mismatch: got %q, want %q", got, want)
			}
		})
	}
	ex := state.ExtraInbound{Protocol: "vless-ws", Domain: " domain.example.com ", ListenPort: 443, UUID: "11111111-1111-4111-8111-111111111111"}
	parsed, err := ParseNodeURI(BuildExtraURI(nil, ex))
	if err != nil || parsed.TLSSNI != "domain.example.com" {
		t.Fatalf("domain SNI fallback: got %q, err %v", parsed.TLSSNI, err)
	}
	for _, host := range []string{"", "192.0.2.1", "2001:db8::1"} {
		s := state.NewDefaultState(state.RoleLanding)
		s.Server.ConnectHost = host
		s.Server.Domain = ""
		ex := state.ExtraInbound{Protocol: "vless-ws", ListenPort: 443, UUID: "11111111-1111-4111-8111-111111111111"}
		expectedHost := host
		if expectedHost == "" {
			expectedHost = "node.example.com"
		}
		got := BuildExtraURI(s, ex)
		parsed, err := ParseNodeURI(got)
		if err != nil || strings.Trim(parsed.Address, "[]") != expectedHost {
			t.Fatalf("fallback host %q: got %q, err %v", expectedHost, got, err)
		}
	}
}
