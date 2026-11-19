package socks5out

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		raw      string
		kind     string
		addr     string
		port     int
		user     string
		pass     string
		hasAuth  bool
		wantFail bool
	}{
		{"socks5://us%40er:p%3Ass%25w@proxy.example.test:1080#my-node", "uri", "proxy.example.test", 1080, "us@er", "p:ss%w", true, false},
		{"socks://dXNlcjpwYXNz@1.2.3.4:1080#b64", "uri", "1.2.3.4", 1080, "user", "pass", true, false},
		{"socks5h://u1:p1@[2001:db8::1]:1080?x=1", "uri", "2001:db8::1", 1080, "u1", "p1", true, false},
		{"1.2.3.4:1080:u:p:extra", "tuple4", "1.2.3.4", 1080, "u", "p:extra", true, false},
		{"[2001:db8::1]:1080", "hostport", "2001:db8::1", 1080, "", "", false, false},
		{"[2001:db8::1]:1080:u:p", "tuple4", "2001:db8::1", 1080, "u", "p", true, false},
		{"2001:db8::1", "host", "2001:db8::1", 0, "", "", false, false},
		{"::192.0.2.1", "host", "::192.0.2.1", 0, "", "", false, false},
		{"proxy.example.test", "host", "proxy.example.test", 0, "", "", false, false},
		// Reject invalid
		{"http://1.2.3.4:1080", "", "", 0, "", "", false, true},
		{"socks5://useronly@1.2.3.4:1080", "", "", 0, "", "", false, true},
		{"socks5://u:p%00w@1.2.3.4:1080", "", "", 0, "", "", false, true},
		{"socks5://1.2.3.4:99999", "", "", 0, "", "", false, true},
		{"12345::1", "", "", 0, "", "", false, true},
		{"1:2:3::4:", "", "", 0, "", "", false, true},
		{"999.1.2.3:1080", "", "", 0, "", "", false, true},
	}

	for _, tc := range cases {
		got, err := ParseEndpoint(tc.raw)
		if tc.wantFail {
			if err == nil {
				t.Errorf("ParseEndpoint(%q) unexpectedly succeeded: %+v", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEndpoint(%q) failed: %v", tc.raw, err)
			continue
		}
		if got.Kind != tc.kind || got.Address != tc.addr || got.Port != tc.port ||
			got.Username != tc.user || got.Password != tc.pass || got.HasAuth != tc.hasAuth {
			t.Errorf("ParseEndpoint(%q) = %+v, want kind=%s addr=%s port=%d user=%s pass=%s auth=%v",
				tc.raw, got, tc.kind, tc.addr, tc.port, tc.user, tc.pass, tc.hasAuth)
		}
	}
}

func TestExpandPresetRules(t *testing.T) {
	gotAI, err := ExpandPresetRules("domain", "@ai,domain:claude.ai,geosite:openai,@tg")
	if err != nil {
		t.Fatalf("ExpandPresetRules domain: %v", err)
	}
	wantAI := []string{
		"geosite:openai", "geosite:anthropic", "domain:claude.ai", "domain:chatgpt.com",
		"domain:gemini.google.com", "domain:perplexity.ai", "domain:x.ai", "domain:grok.com",
		"geosite:telegram",
	}
	if !reflect.DeepEqual(gotAI, wantAI) {
		t.Fatalf("domain preset = %v, want %v", gotAI, wantAI)
	}

	gotIP, err := ExpandPresetRules("ip", "@tg,1.1.1.1/32,geoip:telegram,2001:db8::/32")
	if err != nil {
		t.Fatalf("ExpandPresetRules ip: %v", err)
	}
	wantIP := []string{"geoip:telegram", "1.1.1.1/32", "2001:db8::/32"}
	if !reflect.DeepEqual(gotIP, wantIP) {
		t.Fatalf("ip preset = %v, want %v", gotIP, wantIP)
	}

	if _, err := ExpandPresetRules("domain", "@nonexistent"); err == nil {
		t.Fatalf("expected error on unknown preset")
	}
	if _, err := ExpandPresetRules("ip", "not-an-ip/33"); err == nil {
		t.Fatalf("expected error on invalid IP rule")
	}
}

func TestProbeProfileWithLoopbackSOCKS5(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "fl=1f1\nh=example.test\nip=203.0.113.88\nts=1700000000\nloc=SG\n")
	}))
	defer targetSrv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5(c, "u-test", "p-secret")
		}
	}()

	proxyPort := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := ProbeProfile(ctx, "127.0.0.1", proxyPort, "u-test", "p-secret", []string{targetSrv.URL + "/cdn-cgi/trace"})
	if err != nil {
		t.Fatalf("ProbeProfile valid creds failed: %v", err)
	}
	if res.ExitIP != "203.0.113.88" || res.Location != "SG" || res.StatusCode != 200 {
		t.Fatalf("unexpected probe result: %+v", res)
	}

	if _, err := ProbeProfile(ctx, "127.0.0.1", proxyPort, "u-test", "wrong-pass", []string{targetSrv.URL}); err == nil {
		t.Fatalf("expected ProbeProfile to fail with wrong credentials")
	}

	_ = ln.Close()
	wg.Wait()
}

func handleMockSOCKS5(c net.Conn, expUser, expPass string) {
	defer c.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x02})

	var authHdr [2]byte
	if _, err := io.ReadFull(c, authHdr[:]); err != nil {
		return
	}
	ub := make([]byte, authHdr[1])
	_, _ = io.ReadFull(c, ub)
	var plen [1]byte
	_, _ = io.ReadFull(c, plen[:])
	pb := make([]byte, plen[0])
	_, _ = io.ReadFull(c, pb)
	if string(ub) != expUser || string(pb) != expPass {
		_, _ = c.Write([]byte{0x01, 0x01})
		return
	}
	_, _ = c.Write([]byte{0x01, 0x00})

	var reqHdr [4]byte
	if _, err := io.ReadFull(c, reqHdr[:]); err != nil {
		return
	}
	var host string
	switch reqHdr[3] {
	case 0x01:
		var ip [4]byte
		_, _ = io.ReadFull(c, ip[:])
		host = net.IP(ip[:]).String()
	case 0x03:
		var l [1]byte
		_, _ = io.ReadFull(c, l[:])
		b := make([]byte, l[0])
		_, _ = io.ReadFull(c, b)
		host = string(b)
	case 0x04:
		var ip [16]byte
		_, _ = io.ReadFull(c, ip[:])
		host = net.IP(ip[:]).String()
	default:
		return
	}
	var portB [2]byte
	_, _ = io.ReadFull(c, portB[:])
	port := binary.BigEndian.Uint16(portB[:])

	remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.Copy(remote, c) }()
	_, _ = io.Copy(c, remote)
}
