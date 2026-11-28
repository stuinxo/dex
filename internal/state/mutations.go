package state

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/stuinxo/dex/internal/cryptoext"
)

// NextAvailableWGIP allocates the lowest unused host IP (>= .11) inside subnetCIDR for a WireGuard peer.
func NextAvailableWGIP(subnetCIDR string, peers []WGPeer) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(subnetCIDR))
	if err != nil {
		prefix = netip.MustParsePrefix(DefaultWGSubnet)
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

// EnsureGeneratedDefaults populates missing generated credentials and normalizes role-exclusive flags
// before saving or validating a candidate State.
func (s *State) EnsureGeneratedDefaults() error {
	if s == nil {
		return nil
	}
	s.Normalize()

	for i := range s.ExtraInbounds {
		ex := &s.ExtraInbounds[i]
		switch ex.Protocol {
		case "vless-reality":
			if strings.TrimSpace(ex.UUID) == "" {
				u, err := cryptoext.GenerateUUID()
				if err != nil {
					return err
				}
				ex.UUID = u
			}
			if strings.TrimSpace(ex.RealityPrivKey) == "" {
				priv, pub, err := cryptoext.GenerateRealityKeypair()
				if err != nil {
					return err
				}
				ex.RealityPrivKey = priv
				ex.RealityPubKey = pub
			}
			if strings.TrimSpace(ex.RealityShortID) == "" {
				sid, err := cryptoext.GenerateHexToken(4)
				if err != nil {
					return err
				}
				ex.RealityShortID = sid
			}
			if strings.TrimSpace(ex.RealitySNI) == "" {
				ex.RealitySNI = "www.apple.com"
			}
			if strings.TrimSpace(ex.RealityDest) == "" {
				ex.RealityDest = ex.RealitySNI + ":443"
			}
		case "vless-xhttp", "vless-ws", "vmess-ws":
			if strings.TrimSpace(ex.UUID) == "" {
				u, err := cryptoext.GenerateUUID()
				if err != nil {
					return err
				}
				ex.UUID = u
			}
		}
	}

	if s.Role == RoleClient && s.Client.WireGuard.Enabled {
		if err := s.Client.WireGuard.EnsureServerKeys(); err != nil {
			return err
		}
	}
	if s.Role == RoleClient && s.Client.DNS.EnableDoHServer && strings.TrimSpace(s.Client.DNS.DoHServerPath) == "" {
		s.Client.DNS.DoHServerPath = GenerateDefaultClientDoHPath()
	}
	if s.Role != RoleServer {
		s.Server.EnableDoH = false
	}
	if s.Role != RoleClient {
		s.Client.DNS.EnableDoHServer = false
	}
	return nil
}

// EnsureServerKeys generates a WireGuard Curve25519 keypair when either key is empty.
func (c *WireGuardConfig) EnsureServerKeys() error {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.ServerPrivateKey) != "" && strings.TrimSpace(c.ServerPublicKey) != "" {
		return nil
	}
	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		return err
	}
	c.ServerPrivateKey = priv
	c.ServerPublicKey = pub
	return nil
}

func (s *State) applyWGDefaults(endpoint string, listenPort int, subnetCIDR string) error {
	wg := &s.Client.WireGuard
	if err := wg.EnsureServerKeys(); err != nil {
		return err
	}
	if ep := strings.TrimSpace(endpoint); ep != "" && IsValidAddress(ep) {
		wg.EndpointHost = ep
	}
	if listenPort >= 1 && listenPort <= 65535 {
		wg.ListenPort = listenPort
	}
	if sub := strings.TrimSpace(subnetCIDR); sub != "" {
		if p, err := netip.ParsePrefix(sub); err == nil && p.Addr().Is4() {
			wg.SubnetCIDR = sub
		}
	}
	if wg.ListenPort == 0 {
		wg.ListenPort = DefaultWGPort
	}
	if wg.SubnetCIDR == "" {
		wg.SubnetCIDR = DefaultWGSubnet
	}
	if wg.EndpointHost == "" {
		if s.Client.DDNS.Domain != "" {
			wg.EndpointHost = s.Client.DDNS.Domain
		} else if s.Cert.Domain != "" {
			wg.EndpointHost = s.Cert.Domain
		} else {
			wg.EndpointHost = "vpn.example.com"
		}
	}
	wg.Enabled = true
	return nil
}

// EnableWireGuard enables WireGuard on a Client state with normalized endpoint, port, subnet, and keys.
func (s *State) EnableWireGuard(endpoint string, listenPort int, subnetCIDR string) error {
	return s.applyWGDefaults(endpoint, listenPort, subnetCIDR)
}

// AddWireGuardPeer allocates an IP, generates a keypair, enables WireGuard if needed, and appends a new peer.
func (s *State) AddWireGuardPeer(name, endpoint string, listenPort int, subnetCIDR string) (WGPeer, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return WGPeer{}, errors.New("peer name is required")
	}
	for _, p := range s.Client.WireGuard.Peers {
		if p.Name == name {
			return WGPeer{}, fmt.Errorf("peer %q already exists", name)
		}
	}
	if err := s.applyWGDefaults(endpoint, listenPort, subnetCIDR); err != nil {
		return WGPeer{}, err
	}
	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		return WGPeer{}, err
	}
	ip, err := NextAvailableWGIP(s.Client.WireGuard.SubnetCIDR, s.Client.WireGuard.Peers)
	if err != nil {
		return WGPeer{}, err
	}
	peer := WGPeer{
		Name:       name,
		IP:         ip,
		PrivateKey: priv,
		PublicKey:  pub,
	}
	s.Client.WireGuard.Peers = append(s.Client.WireGuard.Peers, peer)
	return peer, nil
}

// RegenerateWireGuardServerKeys rotates the server WireGuard keypair and returns the new public key.
func (s *State) RegenerateWireGuardServerKeys() (string, error) {
	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		return "", err
	}
	s.Client.WireGuard.ServerPrivateKey = priv
	s.Client.WireGuard.ServerPublicKey = pub
	return pub, nil
}

// RegenerateWireGuardPeer rotates the keypair of an existing WireGuard peer.
func (s *State) RegenerateWireGuardPeer(name string) (WGPeer, error) {
	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		return WGPeer{}, err
	}
	for i := range s.Client.WireGuard.Peers {
		if s.Client.WireGuard.Peers[i].Name == name {
			s.Client.WireGuard.Peers[i].PrivateKey = priv
			s.Client.WireGuard.Peers[i].PublicKey = pub
			return s.Client.WireGuard.Peers[i], nil
		}
	}
	return WGPeer{}, fmt.Errorf("peer %q not found", name)
}

// DeleteWireGuardPeer removes the named WireGuard peer from state.
func (s *State) DeleteWireGuardPeer(name string) error {
	var next []WGPeer
	found := false
	for _, p := range s.Client.WireGuard.Peers {
		if p.Name == name {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		return fmt.Errorf("peer %q not found", name)
	}
	s.Client.WireGuard.Peers = next
	return nil
}

// NextForwardID returns a collision-free relay forward ID matching "fwd-<port>" or "fwd-<proto>-<port>[-n]".
func (r *RelayConfig) NextForwardID(listenPort int, proto string) string {
	used := make(map[string]bool, len(r.Forwards))
	for _, f := range r.Forwards {
		used[f.ID] = true
	}
	cand := fmt.Sprintf("fwd-%d", listenPort)
	if !used[cand] {
		return cand
	}
	pTag := strings.ReplaceAll(strings.TrimSpace(proto), ",", "-")
	if pTag == "" {
		pTag = "tcp"
	}
	cand = fmt.Sprintf("fwd-%s-%d", pTag, listenPort)
	for suffix := 2; used[cand]; suffix++ {
		cand = fmt.Sprintf("fwd-%s-%d-%d", pTag, listenPort, suffix)
	}
	return cand
}

// DefaultExtraInboundTag returns the canonical generated tag for an ExtraInbound protocol and listen port.
func DefaultExtraInboundTag(protocol string, port int) string {
	short := strings.ReplaceAll(strings.TrimSpace(protocol), "vless-", "")
	return fmt.Sprintf("inbound-%s-%d", short, port)
}
