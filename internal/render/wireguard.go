package render

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// NextAvailableWGIP allocates the lowest unused host IP (>= .11) inside subnetCIDR for a WireGuard peer.
func NextAvailableWGIP(subnetCIDR string, peers []state.WGPeer) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(subnetCIDR))
	if err != nil {
		prefix = netip.MustParsePrefix("172.16.66.1/24")
	}
	used := map[netip.Addr]bool{prefix.Addr(): true}
	for _, p := range peers {
		raw := strings.TrimSpace(strings.Split(p.IP, "/")[0])
		if a, err := netip.ParseAddr(raw); err == nil {
			used[a] = true
		}
	}
	base4 := prefix.Addr().As4()
	for lastOctet := 11; lastOctet <= 254; lastOctet++ {
		cand := netip.AddrFrom4([4]byte{base4[0], base4[1], base4[2], byte(lastOctet)})
		if prefix.Contains(cand) && !used[cand] {
			return cand.String(), nil
		}
	}
	return "", errors.New("no free WireGuard peer IP available in subnet")
}

func wireGuardServerIP(wg state.WireGuardConfig) string {
	if p, err := netip.ParsePrefix(strings.TrimSpace(wg.SubnetCIDR)); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(wg.SubnetCIDR)); err == nil {
		return a.String()
	}
	return "172.16.66.1"
}

func normalizePeerAllowedIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		return raw
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		if a.Is4() {
			return a.String() + "/32"
		}
		return a.String() + "/128"
	}
	return raw
}

// BuildWGPeerConfig builds the client wg-quick configuration text for a peer (suitable for download or QR).
func BuildWGPeerConfig(wg state.WireGuardConfig, peer state.WGPeer) string {
	srvIP := wireGuardServerIP(wg)
	endpoint := wg.EndpointHost
	if strings.Contains(endpoint, ":") && !strings.HasPrefix(endpoint, "[") {
		endpoint = "[" + endpoint + "]"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s
MTU = 1400

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
`, peer.PrivateKey, normalizePeerAllowedIP(peer.IP), srvIP, wg.ServerPublicKey, endpoint, wg.ListenPort)
}

func wireGuardServerAddr(wg state.WireGuardConfig) string {
	raw := strings.TrimSpace(wg.SubnetCIDR)
	if _, err := netip.ParsePrefix(raw); err == nil {
		return raw
	}
	return wireGuardServerIP(wg) + "/24"
}

// RenderWireGuard renders /etc/wireguard/wg0.conf and per-peer config files.
func RenderWireGuard(s *state.State, opts RenderOptions) ([]RenderedFile, bool, error) {
	opts = opts.WithDefaults()
	if s.Role != state.RoleClient || !s.Client.WireGuard.Enabled {
		return nil, false, nil
	}
	wg := s.Client.WireGuard
	srvAddr := wireGuardServerAddr(wg)

	var b strings.Builder
	fmt.Fprintf(&b, `[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
MTU = 1420
`, wg.ServerPrivateKey, srvAddr, wg.ListenPort)

	files := make([]RenderedFile, 0, 1+len(wg.Peers))
	for i, peer := range wg.Peers {
		fmt.Fprintf(&b, "\n# Peer: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n",
			peer.Name, peer.PublicKey, normalizePeerAllowedIP(peer.IP))

		peerFileName := fmt.Sprintf("peer-%d.conf", i+1)
		if peer.Name != "" {
			safe := strings.Map(func(r rune) rune {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
					return r
				}
				return '_'
			}, peer.Name)
			peerFileName = "peer-" + safe + ".conf"
		}
		files = append(files, RenderedFile{
			RelName:    "wg-peers/" + peerFileName,
			TargetPath: filepath.Join(opts.GeneratedDir, "wg-peers", peerFileName),
			Content:    []byte(BuildWGPeerConfig(wg, peer)),
			Mode:       0o600,
		})
	}

	files = append([]RenderedFile{{
		RelName:    "wg0.conf",
		TargetPath: "/etc/wireguard/wg0.conf",
		Content:    []byte(b.String()),
		Mode:       0o600,
	}}, files...)

	return files, true, nil
}
