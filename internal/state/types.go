package state

import (
	"encoding/json"
	"strings"
)

const (
	CurrentSchemaVersion = 3

	RoleClient  = "client"
	RoleServer  = "server"
	RoleLanding = "landing"
	RoleRelay   = "relay"
)

// State is the single declarative source of truth persisted at /etc/dex/state.json.
type State struct {
	Version       int            `json:"version"`
	Role          string         `json:"role"`
	System        SystemConfig   `json:"system"`
	Auth          AuthConfig     `json:"auth"`
	Cert          CertConfig     `json:"cert"`
	Client        ClientConfig   `json:"client"`
	Server        ServerConfig   `json:"server"`
	Relay         RelayConfig    `json:"relay"`
	RproxyS       RproxySConfig  `json:"rproxys"`
	ExtraInbounds []ExtraInbound `json:"extra_inbounds,omitempty"`
}

type SystemConfig struct {
	Hostname        string `json:"hostname,omitempty"`
	LANInterface    string `json:"lan_interface,omitempty"`
	LANAddrCIDR     string `json:"lan_addr_cidr,omitempty"`
	GatewayIP       string `json:"gateway_ip,omitempty"`
	EnableIPv6      bool   `json:"enable_ipv6"`
	EnableFlowtable bool   `json:"enable_flowtable"`
	AutoTuneSysctl  bool   `json:"auto_tune_sysctl"`
	AutoUpdateRules bool   `json:"auto_update_rules"`
	AutoUpdateCore  bool   `json:"auto_update_core"`
}

type AuthConfig struct {
	ListenAddr   string `json:"listen_addr"`
	PasswordHash string `json:"password_hash,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
}

type CertConfig struct {
	Mode      string `json:"mode"` // self_signed | imported | acme_cf | acme_http
	Domain    string `json:"domain,omitempty"`
	CertFile  string `json:"cert_file,omitempty"`
	KeyFile   string `json:"key_file,omitempty"`
	CFToken   string `json:"cf_token,omitempty"`
	CFEmail   string `json:"cf_email,omitempty"`
	AutoRenew bool   `json:"auto_renew"`
}

type ClientConfig struct {
	ActiveNodeID    string          `json:"active_node_id,omitempty"`
	FailoverEnabled bool            `json:"failover_enabled"`
	Nodes           []OutboundNode  `json:"nodes,omitempty"`
	Routing         RoutingConfig   `json:"routing"`
	DNS             DNSConfig       `json:"dns"`
	FWD0            FWD0Config      `json:"fwd0"`
	FWD1            FWD1Config      `json:"fwd1"`
	RproxyC         RproxyCConfig   `json:"rproxyc"`
	WireGuard       WireGuardConfig `json:"wireguard"`
	DDNS            DDNSConfig      `json:"ddns"`
}

type OutboundNode struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"` // vless-xhttp | vless-reality | vless-ws | vmess-ws | vmess-tcp | socks5
	Address        string `json:"address"`
	Port           int    `json:"port"`
	UUID           string `json:"uuid,omitempty"`
	TLSSNI         string `json:"tls_sni,omitempty"`
	Path           string `json:"path,omitempty"`
	RealityPubKey  string `json:"reality_pubkey,omitempty"`
	RealityShortID string `json:"reality_shortid,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
}

type RoutingConfig struct {
	Divert      DivertConfig      `json:"divert"`
	Custom      CustomRouteConfig `json:"custom"`
	ServiceMap  map[string]string `json:"service_map,omitempty"` // service -> node_id
	AppleNodeID string            `json:"apple_node_id,omitempty"`
	SteamProxy  bool              `json:"steam_proxy"`
}

type DivertConfig struct {
	Enabled          bool     `json:"enabled"`
	NodeID           string   `json:"node_id,omitempty"`
	CHNProxyLANIPs   []string `json:"chn_proxy_lan_ips,omitempty"`
	GlobalProxyLANIP []string `json:"global_proxy_lan_ips,omitempty"`
	DirectLANIPs     []string `json:"direct_lan_ips,omitempty"`
}

type CustomRouteConfig struct {
	Enabled bool     `json:"enabled"`
	NodeID  string   `json:"node_id,omitempty"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

type DNSConfig struct {
	ChinaServers     []string          `json:"china_servers,omitempty"`
	DoHServers       []string          `json:"doh_servers,omitempty"`
	Hosts            map[string]string `json:"hosts,omitempty"`
	BlacklistDomains []string          `json:"blacklist_domains,omitempty"`
	WhitelistDomains []string          `json:"whitelist_domains,omitempty"`
	BlacklistIPs     []string          `json:"blacklist_ips,omitempty"`
	WhitelistIPs     []string          `json:"whitelist_ips,omitempty"`
	BlockAds         bool              `json:"block_ads"`
	BlockExternal53  bool              `json:"block_external_53"`
}

type FWD0Config struct {
	Enabled  bool     `json:"enabled"`
	Protocol string   `json:"protocol,omitempty"` // vless-xhttp (default) | vmess-tcp
	Port     int      `json:"port"`
	Path     string   `json:"path,omitempty"`
	UUIDs    []string `json:"uuids,omitempty"`
}

// EffectiveProtocol returns the FWD0 inbound protocol, defaulting to vless-xhttp.
func (f FWD0Config) EffectiveProtocol() string {
	if strings.TrimSpace(f.Protocol) != "" {
		return strings.TrimSpace(f.Protocol)
	}
	return "vless-xhttp"
}

type FWD1Config struct {
	Enabled        bool     `json:"enabled"`
	Protocol       string   `json:"protocol,omitempty"` // vless-xhttp (default) | vmess-tcp
	Port           int      `json:"port"`
	Path           string   `json:"path,omitempty"`
	UUIDs          []string `json:"uuids,omitempty"`
	UpstreamNodeID string   `json:"upstream_node_id,omitempty"`
}

// EffectiveProtocol returns the FWD1 inbound protocol, defaulting to vless-xhttp.
func (f FWD1Config) EffectiveProtocol() string {
	if strings.TrimSpace(f.Protocol) != "" {
		return strings.TrimSpace(f.Protocol)
	}
	return "vless-xhttp"
}

type RproxyCConfig struct {
	Enabled              bool                  `json:"enabled"`
	TunnelAddress        string                `json:"tunnel_address,omitempty"`
	TunnelPort           int                   `json:"tunnel_port,omitempty"`
	TunnelUUID           string                `json:"tunnel_uuid,omitempty"`
	Security             string                `json:"security,omitempty"` // tls (default) | none
	ServerName           string                `json:"server_name,omitempty"`
	PinnedPeerCertSha256 string                `json:"pinned_peer_cert_sha256,omitempty"`
	OutDirect            bool                  `json:"out_direct,omitempty"`
	Mappings             []RproxyClientMapping `json:"mappings,omitempty"`
}

type RproxyClientMapping struct {
	ExtPort int    `json:"ext_port"`
	Proto   string `json:"proto"` // tcp | udp | tcp,udp
	IntIP   string `json:"int_ip"`
	IntPort int    `json:"int_port"`
}

type WireGuardConfig struct {
	Enabled          bool     `json:"enabled"`
	EndpointHost     string   `json:"endpoint_host,omitempty"`
	ListenPort       int      `json:"listen_port"`
	SubnetCIDR       string   `json:"subnet_cidr,omitempty"`
	ServerPrivateKey string   `json:"server_private_key,omitempty"`
	ServerPublicKey  string   `json:"server_public_key,omitempty"`
	Peers            []WGPeer `json:"peers,omitempty"`
}

type WGPeer struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type DDNSConfig struct {
	Enabled    bool   `json:"enabled"`
	Provider   string `json:"provider,omitempty"` // cloudflare
	Domain     string `json:"domain,omitempty"`
	CFToken    string `json:"cf_token,omitempty"`
	CFEmail    string `json:"cf_email,omitempty"`
	EnableIPv6 bool   `json:"enable_ipv6"`
}

type ServerConfig struct {
	Protocol        string          `json:"protocol,omitempty"` // vless-xhttp (default) | vmess-ws | vless-ws
	TLSMode         string          `json:"tls_mode"`           // direct | nginx
	Domain          string          `json:"domain,omitempty"`
	ConnectHost     string          `json:"connect_host,omitempty"`
	ListenPort      int             `json:"listen_port"`
	PublicPort      int             `json:"public_port,omitempty"`
	Path            string          `json:"path,omitempty"`
	UUIDs           []string        `json:"uuids,omitempty"`
	EnableDoH       bool            `json:"enable_doh"`
	CamouflageDir   string          `json:"camouflage_dir,omitempty"`
	Socks5Outbounds []Socks5Profile `json:"socks5_outbounds,omitempty"`
}

// EffectiveProtocol returns the server main inbound protocol, defaulting to vless-xhttp.
func (s ServerConfig) EffectiveProtocol() string {
	if strings.TrimSpace(s.Protocol) != "" {
		return strings.TrimSpace(s.Protocol)
	}
	return "vless-xhttp"
}

type Socks5Profile struct {
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	Address       string   `json:"address"`
	Port          int      `json:"port"`
	Username      string   `json:"username,omitempty"`
	Password      string   `json:"password,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	IPs           []string `json:"ips,omitempty"`
	PrivateBypass bool     `json:"private_bypass"`
}

type RelayConfig struct {
	Forwards []ForwardRule `json:"forwards,omitempty"`
}

type ForwardRule struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	ListenPort int    `json:"listen_port"`
	PublicPort int    `json:"public_port,omitempty"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	Proto      string `json:"proto"`  // tcp | udp | tcp,udp
	Engine     string `json:"engine"` // nft | haproxy | xray
}

type RproxySConfig struct {
	Enabled    bool                  `json:"enabled"`
	Domain     string                `json:"domain,omitempty"`
	ListenPort int                   `json:"listen_port"`
	Security   string                `json:"security,omitempty"` // tls (default) | none
	UUIDs      []string              `json:"uuids,omitempty"`
	InUUIDs    []string              `json:"in_uuids,omitempty"`
	Mappings   []RproxyServerMapping `json:"mappings,omitempty"`
}

type RproxyServerMapping struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp | udp | tcp,udp
}

type ExtraInbound struct {
	Tag            string `json:"tag"`
	Protocol       string `json:"protocol"` // vless-reality | vless-xhttp | vless-ws | vmess-ws | socks5 | dokodemo
	ListenPort     int    `json:"listen_port"`
	UUID           string `json:"uuid,omitempty"`
	Path           string `json:"path,omitempty"`
	Domain         string `json:"domain,omitempty"`
	RealityDest    string `json:"reality_dest,omitempty"`
	RealitySNI     string `json:"reality_sni,omitempty"`
	RealityPrivKey string `json:"reality_privkey,omitempty"`
	RealityPubKey  string `json:"reality_pubkey,omitempty"`
	RealityShortID string `json:"reality_shortid,omitempty"`
	SocksUser      string `json:"socks_user,omitempty"`
	SocksPass      string `json:"socks_pass,omitempty"`
	TargetAddr     string `json:"target_addr,omitempty"`
	TargetPort     int    `json:"target_port,omitempty"`
	Network        string `json:"network,omitempty"` // tcp | udp | tcp,udp (dokodemo)
	ViaNginx       bool   `json:"via_nginx,omitempty"`
}

// NewDefaultState constructs a normalized empty state for the given role.
func NewDefaultState(role string) *State {
	if role == "" {
		role = RoleClient
	}
	listen := ":8443"
	switch role {
	case RoleClient:
		listen = ":443"
	case RoleServer:
		listen = "127.0.0.1:8443"
	}
	tlsMode := "nginx"
	enableDoH := true
	listenPort := 443
	if role == RoleLanding {
		tlsMode = "direct"
		enableDoH = false
	}
	return &State{
		Version: CurrentSchemaVersion,
		Role:    role,
		System: SystemConfig{
			AutoTuneSysctl:  true,
			EnableFlowtable: true,
			AutoUpdateRules: role == RoleClient,
		},
		Auth: AuthConfig{
			ListenAddr: listen,
			ServerName: "dex",
		},
		Cert: CertConfig{
			Mode: "self_signed",
		},
		Client: ClientConfig{
			Routing: RoutingConfig{
				ServiceMap: make(map[string]string),
			},
			DNS: DNSConfig{
				ChinaServers: append([]string(nil), DefaultChinaDNS...),
				DoHServers:   append([]string(nil), DefaultDoHServers...),
				Hosts:        make(map[string]string),
			},
			WireGuard: WireGuardConfig{
				ListenPort: 51820,
				SubnetCIDR: "172.16.66.1/24",
			},
			DDNS: DDNSConfig{
				Provider: "cloudflare",
			},
		},
		Server: ServerConfig{
			TLSMode:    tlsMode,
			ListenPort: listenPort,
			EnableDoH:  enableDoH,
		},
	}
}

// FindNode returns a pointer to the node with the given ID, or nil if absent.
func (c *ClientConfig) FindNode(id string) *OutboundNode {
	for i := range c.Nodes {
		if c.Nodes[i].ID == id {
			return &c.Nodes[i]
		}
	}
	return nil
}

// ActiveNode returns the currently active outbound node, falling back to the first node if needed.
func (c *ClientConfig) ActiveNode() *OutboundNode {
	if c.ActiveNodeID != "" {
		if n := c.FindNode(c.ActiveNodeID); n != nil {
			return n
		}
	}
	if len(c.Nodes) > 0 {
		return &c.Nodes[0]
	}
	return nil
}

// PruneNodeRefs removes or updates any dangling references to a deleted node ID.
func (c *ClientConfig) PruneNodeRefs(id string) {
	if c == nil || id == "" {
		return
	}
	if c.ActiveNodeID == id {
		fallback := ""
		for _, n := range c.Nodes {
			if n.ID != id {
				fallback = n.ID
				break
			}
		}
		c.ActiveNodeID = fallback
	}
	for k, v := range c.Routing.ServiceMap {
		if v == id {
			delete(c.Routing.ServiceMap, k)
		}
	}
	if c.Routing.AppleNodeID == id {
		c.Routing.AppleNodeID = ""
	}
	if c.Routing.Divert.NodeID == id {
		c.Routing.Divert.NodeID = ""
	}
	if c.Routing.Custom.NodeID == id {
		c.Routing.Custom.NodeID = ""
	}
	if c.FWD1.UpstreamNodeID == id {
		c.FWD1.UpstreamNodeID = ""
	}
}

// EffectiveSNI returns the TLS serverName for a node, defaulting to its address.
func (n OutboundNode) EffectiveSNI() string {
	if strings.TrimSpace(n.TLSSNI) != "" {
		return strings.TrimSpace(n.TLSSNI)
	}
	return strings.TrimSpace(n.Address)
}

// EffectiveConnectHost returns the external connect host for server/landing nodes.
func (s ServerConfig) EffectiveConnectHost() string {
	if strings.TrimSpace(s.ConnectHost) != "" {
		return strings.TrimSpace(s.ConnectHost)
	}
	return strings.TrimSpace(s.Domain)
}

// EffectivePublicPort returns PublicPort if set, otherwise ListenPort.
func (s ServerConfig) EffectivePublicPort() int {
	if s.PublicPort > 0 {
		return s.PublicPort
	}
	return s.ListenPort
}

// Clone deep-copies the state via JSON round-trip.
func (s *State) Clone() (*State, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out State
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
