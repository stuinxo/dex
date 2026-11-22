package migrate

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/render"
)

func TestImportV2ClientAndRender(t *testing.T) {
	dir := t.TempDir()
	pwHash := cryptoext.LegacyV2Digest("oldV2Secret!")

	zeroConf := `{
    "address": {
      "alias": "home-gw",
      "localIP": "192.168.50.2",
      "serverName": "gw.example.com",
      "webUIport": "443",
      "PWD": "` + pwHash + `"
    },
    "dns": {
      "china": "223.5.5.5 119.29.29.29",
      "doh": ["hk.example.com/dq", "hk.example.com/dq", "https://dns.google/dns-query"],
      "hosts": {"nas.lan": "192.168.50.10"},
      "listB": ["openai.com"],
      "listW": ["cn.bing.com"],
      "adlists": ["https://example.com/hosts"]
    },
  "v2node": [
    {"domain": "hk.example.com:443", "name": "HK", "uuid": "11111111-1111-4111-8111-111111111111", "path": "/11111111", "tls": "hk.example.com"},
    {"domain": "jp.example.com:20443", "name": "JP", "uuid": "22222222-2222-4222-8222-222222222222", "path": "/22222222", "tls": "jp.example.com"}
  ],
  "update": {
    "v2node": {"domain": "jp.example.com", "port": 20443, "uuid": "22222222-2222-4222-8222-222222222222", "tls": "jp.example.com", "path": "/22222222"}
  },
  "v2nodeDIV": {
    "failover": {"status": "on"},
    "ss": {"status": "off", "ssAddress": "198.51.100.5", "ssPort": "443", "ssUUID": "33333333-3333-4333-8333-333333333333", "ssSNI": "www.apple.com", "ssPBK": "pub1234567890", "ssSID": "abcd"},
    "nodeDT": {"status": "on", "address": "hk.example.com:443", "CHNlistProxyIP": ["192.168.50.30"], "globalProxyIP": ["192.168.50.31"], "directProxyIP": ["192.168.50.32"]},
    "nodeCU": {"status": "on", "address": "jp.example.com:20443", "rulesDomain": ["geosite:github"], "rulesIP": ["8.8.4.4/32"]},
    "nodeSM": {"status": "on", "openai": "jp.example.com:20443", "apple": "hk.example.com:443", "steam": "proxy"}
  },
  "FORWARD": {
    "domain": "gw.example.com",
    "token": "cf-tok-123",
    "FWD0": {"status": "on", "port": "443", "path": "/fwd0", "uuid": [{"FWD0uuid": "44444444-4444-4444-8444-444444444444"}]},
    "FWD1": {"status": "on", "port": 3443, "path": "/fwd1", "upstream": "hk.example.com:443", "uuid": [{"FWD1uuid": "55555555-5555-4555-8555-555555555555"}]},
    "Rproxy": {"client": {"status": "on", "mappingStatus": "on", "tunnel": {"address": "rp.example.com:9443", "uuid": "66666666-6666-4666-8666-666666666666"}, "mapping": [{"extPort": "18080", "extProtocol": "tcp", "intIP": "192.168.50.10", "intPort": "8080"}, {"extPort": "", "extProtocol": "tcp", "intIP": "", "intPort": ""}]}}
  },
  "wireguard": {
    "server": {"WGaddress": "home.example.com", "WGport": "51820", "sprivatekey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "spublickey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="},
    "clients": [{"cprivatekey": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", "cpublickey": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=", "mark": "iphone 16"}]
  },
  "ddns": {
    "ddns3322": {"domain": "ignored"},
    "ddnsCF": {"cfDomain": "home.example.com", "cfToken": "ddns-tok"}
  },
  "app": {"jellyfin": "installed"}
}`

	confPath := filepath.Join(dir, "0conf")
	if err := os.WriteFile(confPath, []byte(zeroConf), 0o600); err != nil {
		t.Fatalf("write 0conf: %v", err)
	}

	st, notes, err := ImportV2Client(confPath, "")
	if err != nil {
		t.Fatalf("ImportV2Client: %v", err)
	}
	if len(notes) < 3 {
		t.Fatalf("expected migration notes, got %v", notes)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("migrated state failed validation: %v", err)
	}
	ok, needsRehash := cryptoext.VerifyPassword(st.Auth.PasswordHash, "oldV2Secret!")
	if !ok || !needsRehash {
		t.Fatalf("expected legacy v2 password to verify with needsRehash=true")
	}
	if st.Client.ActiveNodeID != "v2node-2" {
		t.Fatalf("expected active node v2node-2, got %q", st.Client.ActiveNodeID)
	}
	if st.Client.Routing.ServiceMap["openai"] != "v2node-2" || !st.Client.Routing.SteamProxy {
		t.Fatalf("unexpected NodeSM migration: %+v", st.Client.Routing)
	}
	if !st.Client.WireGuard.Enabled || len(st.Client.WireGuard.Peers) != 1 || !st.Client.DDNS.Enabled {
		t.Fatalf("unexpected WG/DDNS migration")
	}
	if st.Client.WireGuard.Peers[0].Name != "iphone_16" {
		t.Fatalf("expected sanitized peer name from mark, got %q", st.Client.WireGuard.Peers[0].Name)
	}
	if st.Auth.ListenAddr != ":8443" {
		t.Fatalf("expected Web UI shifted to :8443 away from FWD0 :443, got %q", st.Auth.ListenAddr)
	}
	if len(st.Client.DNS.DoHServers) != 2 || st.Client.DNS.DoHServers[0] != "https://hk.example.com/dq" {
		t.Fatalf("unexpected normalized DoH list: %v", st.Client.DNS.DoHServers)
	}
	if len(st.Client.RproxyC.Mappings) != 1 || st.Client.RproxyC.Mappings[0].ExtPort != 18080 {
		t.Fatalf("expected valid filtered RproxyC mappings, got %+v", st.Client.RproxyC.Mappings)
	}

	if _, err := render.RenderAll(st, render.RenderOptions{
		ResolvedHostIPs: map[string][]netip.Addr{
			"hk.example.com": {netip.MustParseAddr("203.0.113.1")},
			"jp.example.com": {netip.MustParseAddr("203.0.113.2")},
			"rp.example.com": {netip.MustParseAddr("203.0.113.3")},
			"dns.google":     {netip.MustParseAddr("8.8.8.8")},
		},
	}); err != nil {
		t.Fatalf("RenderAll migrated client failed: %v", err)
	}
}

func TestImportV2ServerDESAndDEXS(t *testing.T) {
	// 1. v2 server fixture
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc", "nginx", "conf.d"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "opt", "de_GWD", "vtrui"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "opt", "de_GWD", "RproxyS"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "etc", "haproxy"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "var", "www", "ssl"), 0o755)

	_ = os.WriteFile(filepath.Join(root, "etc", "nginx", "conf.d", "default.conf"), []byte(`
server {
  listen 443 default ssl fastopen=500 reuseport;
  server_name srv.example.com;
  location /dq { proxy_pass http://127.0.0.1:9853/dq; }
}
`), 0o644)
	_ = os.WriteFile(filepath.Join(root, "opt", "de_GWD", "vtrui", "config.json"), []byte(`{
  "inbounds": [{"port": 9890, "protocol": "vless", "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111"}]}, "streamSettings": {"xhttpSettings": {"path": "/11111111"}}}]
}`), 0o644)
	_ = os.WriteFile(filepath.Join(root, "opt", "de_GWD", "socks5-outbound.json"), []byte(`{
  "enabled": true,
  "server": {"address": "198.51.100.1", "port": 1080, "username": "u", "password": "p"},
  "domains": ["geosite:netflix"]
}`), 0o600)
	_ = os.WriteFile(filepath.Join(root, "opt", "de_GWD", "RproxyS", "settings.json"), []byte(`{
  "port": 20000,
  "uuid": "22222222-2222-4222-8222-222222222222",
  "mapping": [{"port": 18080, "protocol": "tcp"}]
}`), 0o600)
	_ = os.WriteFile(filepath.Join(root, "etc", "haproxy", "haproxy.cfg"), []byte(`
frontend ft_10001
  bind :10001
  default_backend bk_10001
backend bk_10001
  server srv1 203.0.113.5:443 check
`), 0o644)

	srvState, _, err := ImportV2Server(root)
	if err != nil {
		t.Fatalf("ImportV2Server: %v", err)
	}
	if err := srvState.Validate(); err != nil {
		t.Fatalf("ImportV2Server Validate: %v", err)
	}
	if _, err := render.RenderAll(srvState, render.RenderOptions{}); err != nil {
		t.Fatalf("RenderAll imported v2 server: %v", err)
	}

	// 2. des landing fixture
	desPath := filepath.Join(root, "des-state.json")
	_ = os.WriteFile(desPath, []byte(`{
  "version": 1, "role": "landing", "domain": "land.example.com", "public_host": "198.51.100.9",
  "landing": {"listen_port": 20001, "public_port": 30001, "uuids": ["11111111-1111-4111-8111-111111111111"], "path": "/11111111"},
  "extras": {"socks": {"listen_port": 20002, "public_port": 30002, "user": "u1", "pass": "p1"}}
}`), 0o600)
	desState, _, err := ImportDES(desPath)
	if err != nil {
		t.Fatalf("ImportDES: %v", err)
	}
	if err := desState.Validate(); err != nil {
		t.Fatalf("ImportDES Validate: %v", err)
	}

	// 3. dexs fixture
	dexsPath := filepath.Join(root, "dexs-state.json")
	_ = os.WriteFile(dexsPath, []byte(`{
  "version": 1, "domain": "lite.example.com",
  "nodes": [{"name": "main", "port": 2096, "uuid": "00000000-0000-4000-8000-000000123456"}],
  "relays": [{"name": "transit", "port": 33346, "host": "target.example.com", "target_port": 33344, "network": "tcp,udp"}]
}`), 0o600)
	dexsState, _, err := ImportDEXS(dexsPath)
	if err != nil {
		t.Fatalf("ImportDEXS: %v", err)
	}
	if err := dexsState.Validate(); err != nil {
		t.Fatalf("ImportDEXS Validate: %v", err)
	}
	if _, err := render.RenderAll(dexsState, render.RenderOptions{}); err != nil {
		t.Fatalf("RenderAll dexsState: %v", err)
	}
}

func TestImportV2ClientWave1Fixes(t *testing.T) {
	dir := t.TempDir()
	_, pub, err := cryptoext.GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	priv, derivedPub, err := cryptoext.GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	// 1. v2_client without vtrui/config.json: path!="" -> vmess-ws, path=="" -> vmess-tcp,
	// CIDR already having /24, nodeSM.status==off, wireguard.status==off, RproxyS, block53, cfEmail, DoG note.
	zeroConf := `{
  "address": {
    "alias": "edge-gw",
    "localIP": "192.168.50.2/24",
    "serverName": "gw.example.com",
    "webUIport": "8443"
  },
  "dns": {
    "dog": "dog.example.com:443"
  },
  "v2node": [
    {"domain": "ws.example.com:443", "name": "WS", "uuid": "11111111-1111-4111-8111-111111111111", "path": "wsnode", "tls": "ws.example.com"},
    {"domain": "tcp.example.com:10443", "name": "TCP", "uuid": "22222222-2222-4222-8222-222222222222", "path": ""}
  ],
  "update": {
    "v2node": {"domain": "ws.example.com", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "path": "wsnode", "tls": "ws.example.com"}
  },
  "v2nodeDIV": {
    "nodeSM": {"status": "off", "openai": "ws.example.com:443", "steam": "proxy"}
  },
  "FORWARD": {
    "domain": "gw.example.com",
    "email": "cert@example.com",
    "block53": "on",
    "DoGs": {"port": 9443},
    "FWD0": {"status": "on", "port": "1443", "uuid": [{"FWD0uuid": "33333333-3333-4333-8333-333333333333"}]},
    "Rproxy": {
      "server": {
        "status": "on",
        "inStatus": "on",
        "mappingStatus": "on",
        "tunnel": {"port": "20000", "uuid": "44444444-4444-4444-8444-444444444444"},
        "inUUID": [{"RproxyS0uuid": "55555555-5555-4555-8555-555555555555"}],
        "mapping": [{"port": "18080", "protocol": "tcp"}]
      }
    }
  },
  "wireguard": {
    "status": "off",
    "server": {"WGaddress": "home.example.com", "WGport": "51820", "sprivatekey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "spublickey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}
  },
  "ddns": {
    "ddnsCF": {"cfDomain": "home.example.com", "cfAPIkey": "global-key", "cfEmail": "ddns@example.com"}
  }
}`
	confPath := filepath.Join(dir, "0conf")
	_ = os.WriteFile(confPath, []byte(zeroConf), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "extra_inbounds.json"), []byte(`[
  {"tag": "inbound-reality-9443", "port": 9443, "protocol": "vless", "settings": {"clients": [{"id": "66666666-6666-4666-8666-666666666666"}]}, "streamSettings": {"security": "reality", "realitySettings": {"dest": "www.apple.com:443", "serverNames": ["www.apple.com"], "privateKey": "`+priv+`", "shortIds": ["abcd"]}}}
]`), 0o600)

	st, notes, err := ImportV2Client(confPath, dir)
	if err != nil {
		t.Fatalf("ImportV2Client: %v", err)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if st.System.Hostname != "edge-gw" || st.System.LANAddrCIDR != "192.168.50.2/24" {
		t.Fatalf("unexpected hostname/LANAddrCIDR: %q / %q", st.System.Hostname, st.System.LANAddrCIDR)
	}
	if st.Client.Nodes[0].Protocol != "vmess-ws" || st.Client.Nodes[0].Path != "/wsnode" || st.Client.Nodes[1].Protocol != "vmess-tcp" {
		t.Fatalf("unexpected node protocols: %+v", st.Client.Nodes)
	}
	if len(st.Client.Routing.ServiceMap) != 0 || st.Client.Routing.SteamProxy {
		t.Fatalf("expected nodeSM.status==off respected, got %+v", st.Client.Routing)
	}
	if st.Client.WireGuard.Enabled {
		t.Fatalf("expected wireguard.status==off respected")
	}
	if !st.RproxyS.Enabled || len(st.RproxyS.InUUIDs) != 1 || st.RproxyS.ListenPort != 20000 {
		t.Fatalf("expected RproxyS imported, got %+v", st.RproxyS)
	}
	if !st.Client.DNS.BlockExternal53 || st.Client.DDNS.CFEmail != "ddns@example.com" || st.Cert.CFEmail != "cert@example.com" {
		t.Fatalf("expected block53/emails imported: block53=%v ddnsEmail=%q certEmail=%q", st.Client.DNS.BlockExternal53, st.Client.DDNS.CFEmail, st.Cert.CFEmail)
	}
	if st.Client.FWD0.Protocol != "vmess-tcp" {
		t.Fatalf("expected FWD0 protocol=vmess-tcp, got %q", st.Client.FWD0.Protocol)
	}
	if len(st.ExtraInbounds) != 1 || st.ExtraInbounds[0].RealityPubKey != derivedPub {
		t.Fatalf("expected RealityPubKey derived=%q, got %+v", derivedPub, st.ExtraInbounds)
	}
	joinedNotes := strings.Join(notes, "\n")
	if !strings.Contains(joinedNotes, "dns.dog") || !strings.Contains(joinedNotes, "FORWARD.DoGs") || !strings.Contains(joinedNotes, "vmess-tcp") {
		t.Fatalf("expected DoG/DoGs/vmess-tcp notes, got:\n%s", joinedNotes)
	}

	// 2. v2_server with vmess+ws main inbound
	srvRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(srvRoot, "etc", "nginx", "conf.d"), 0o755)
	_ = os.MkdirAll(filepath.Join(srvRoot, "opt", "de_GWD", "vtrui"), 0o755)
	_ = os.WriteFile(filepath.Join(srvRoot, "etc", "nginx", "conf.d", "default.conf"), []byte("server {\n  listen 443 ssl;\n  server_name ws.example.com;\n}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(srvRoot, "opt", "de_GWD", "vtrui", "config.json"), []byte(`{
  "inbounds": [{"port": 9890, "protocol": "vmess", "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111", "alterId": 0}]}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws-legacy"}}}]
}`), 0o644)
	srvSt, _, err := ImportV2Server(srvRoot)
	if err != nil {
		t.Fatalf("ImportV2Server vmess-ws: %v", err)
	}
	if srvSt.Server.Protocol != "vmess-ws" || srvSt.Server.Path != "/ws-legacy" {
		t.Fatalf("expected vmess-ws /ws-legacy, got %q %q", srvSt.Server.Protocol, srvSt.Server.Path)
	}
}

func TestImportV2ClientFWD1PortConflictAvoidance(t *testing.T) {
	dir := t.TempDir()
	// Case 1: FWD1 conflicts with webUIport 443 -> shifts to :8443
	conf1 := filepath.Join(dir, "0conf-fwd1")
	_ = os.WriteFile(conf1, []byte(`{
  "address": {"webUIport": "443"},
  "FORWARD": {
    "FWD1": {"status": "on", "port": 443, "uuid": [{"FWD1uuid": "55555555-5555-4555-8555-555555555555"}]}
  }
}`), 0o600)
	st1, notes1, err := ImportV2Client(conf1, "")
	if err != nil {
		t.Fatalf("ImportV2Client case1: %v", err)
	}
	if err := st1.Validate(); err != nil {
		t.Fatalf("Validate case1: %v", err)
	}
	if st1.Auth.ListenAddr != ":8443" {
		t.Fatalf("expected ListenAddr shifted to :8443 away from FWD1 :443, got %q", st1.Auth.ListenAddr)
	}
	if !strings.Contains(strings.Join(notes1, "\n"), "FWD1 port 443") {
		t.Fatalf("expected FWD1 conflict note, got %v", notes1)
	}

	// Case 2: FWD0 on 443 AND FWD1 on 8443 -> shifts to :8444
	conf2 := filepath.Join(dir, "0conf-both")
	_ = os.WriteFile(conf2, []byte(`{
  "address": {"webUIport": "443"},
  "FORWARD": {
    "FWD0": {"status": "on", "port": 443, "uuid": [{"FWD0uuid": "44444444-4444-4444-8444-444444444444"}]},
    "FWD1": {"status": "on", "port": 8443, "uuid": [{"FWD1uuid": "55555555-5555-4555-8555-555555555555"}]}
  }
}`), 0o600)
	st2, _, err := ImportV2Client(conf2, "")
	if err != nil {
		t.Fatalf("ImportV2Client case2: %v", err)
	}
	if err := st2.Validate(); err != nil {
		t.Fatalf("Validate case2: %v", err)
	}
	if st2.Auth.ListenAddr != ":8444" {
		t.Fatalf("expected ListenAddr shifted to :8444 avoiding FWD0:443 & FWD1:8443, got %q", st2.Auth.ListenAddr)
	}
}

func TestHardeningV2ServerInMemoryExtraAndDEXSEmptyNames(t *testing.T) {
	// 1. ImportV2Server decodes vtrui extra_inbounds in memory (without /tmp temp files) and ImportV2Client sets acme_cf
	root := t.TempDir()
	vtruiDir := filepath.Join(root, "opt", "de_GWD", "vtrui")
	_ = os.MkdirAll(vtruiDir, 0o755)
	_ = os.WriteFile(filepath.Join(vtruiDir, "config.json"), []byte(`{
  "inbounds": [
    {
      "tag": "main",
      "port": 9890,
      "protocol": "vless",
      "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111"}]},
      "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/1111"}}
    },
    {
      "tag": "inbound-socks5",
      "port": 1080,
      "protocol": "socks",
      "settings": {"accounts": [{"user": "u1", "pass": "p1"}]}
    }
  ]
}`), 0o600)
	stSrv, _, err := ImportV2Server(root)
	if err != nil {
		t.Fatalf("ImportV2Server: %v", err)
	}
	if len(stSrv.ExtraInbounds) != 1 || stSrv.ExtraInbounds[0].Tag != "inbound-socks5" || stSrv.ExtraInbounds[0].SocksUser != "u1" {
		t.Fatalf("expected decoded extra inbound from vtrui, got %+v", stSrv.ExtraInbounds)
	}

	confCF := filepath.Join(t.TempDir(), "0conf-cf")
	_ = os.WriteFile(confCF, []byte(`{
  "FORWARD": {"domain": "cf.example.com", "token": "cf-tok-1"}
}`), 0o600)
	stCF, _, err := ImportV2Client(confCF, "")
	if err != nil {
		t.Fatalf("ImportV2Client cf: %v", err)
	}
	if stCF.Cert.Mode != "acme_cf" {
		t.Fatalf("expected Cert.Mode=acme_cf, got %q", stCF.Cert.Mode)
	}

	// 2. ImportDEXS falls back to node-<i+1> / relay-<idx+1> when Name is empty
	dexsPath := filepath.Join(t.TempDir(), "dexs-state.json")
	_ = os.WriteFile(dexsPath, []byte(`{
  "version": 1,
  "domain": "dexs.example.com",
  "nodes": [
    {"name": "", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111"},
    {"name": "", "port": 8443, "uuid": "22222222-2222-4222-8222-222222222222"},
    {"name": "", "port": 8444, "uuid": "33333333-3333-4333-8333-333333333333"}
  ],
  "relays": [
    {"name": "", "port": 10001, "host": "1.1.1.1", "target_port": 443, "network": "tcp"},
    {"name": "", "port": 10002, "host": "1.1.1.1", "target_port": 443, "network": "udp"}
  ]
}`), 0o600)
	stDexs, _, err := ImportDEXS(dexsPath)
	if err != nil {
		t.Fatalf("ImportDEXS: %v", err)
	}
	if err := stDexs.Validate(); err != nil {
		t.Fatalf("ImportDEXS state Validate failed: %v", err)
	}
	if stDexs.ExtraInbounds[0].Tag != "dexs-node-2" || stDexs.ExtraInbounds[1].Tag != "dexs-node-3" {
		t.Fatalf("unexpected fallback extra tags: %+v", stDexs.ExtraInbounds)
	}
	if stDexs.Relay.Forwards[0].ID != "dexs-relay-1" || stDexs.Relay.Forwards[1].ID != "dexs-relay-2" {
		t.Fatalf("unexpected fallback relay IDs: %+v", stDexs.Relay.Forwards)
	}
}
