package socks5out

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/stuinxo/dex/internal/state"
)

// ProbeResult holds the connectivity result of probing an upstream SOCKS5 endpoint.
type ProbeResult struct {
	StatusCode int
	ExitIP     string
	Location   string
	Latency    time.Duration
}

// DialSOCKS5 establishes a TCP connection via a SOCKS5 proxy (RFC 1928 / RFC 1929)
// using remote hostname resolution (ATYP 0x03) unless target is an IP literal.
func DialSOCKS5(ctx context.Context, proxyAddr, user, pass, targetAddr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		} else {
			_ = conn.SetDeadline(time.Time{})
		}
	}()

	// Method negotiation
	methods := []byte{0x00}
	if user != "" || pass != "" {
		methods = []byte{0x00, 0x02}
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return nil, fmt.Errorf("write greeting: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return nil, fmt.Errorf("read method selection: %w", err)
	}
	if resp[0] != 0x05 {
		return nil, fmt.Errorf("unexpected SOCKS version %d", resp[0])
	}
	switch resp[1] {
	case 0x00:
		// no auth
	case 0x02:
		if len(user) > 255 || len(pass) > 255 {
			return nil, errors.New("SOCKS5 credentials too long")
		}
		authReq := make([]byte, 0, 3+len(user)+len(pass))
		authReq = append(authReq, 0x01, byte(len(user)))
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)
		if _, err := conn.Write(authReq); err != nil {
			return nil, fmt.Errorf("write auth: %w", err)
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return nil, fmt.Errorf("read auth reply: %w", err)
		}
		if authResp[1] != 0x00 {
			return nil, errors.New("SOCKS5 authentication rejected")
		}
	case 0xff:
		return nil, errors.New("no acceptable SOCKS5 auth method")
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 auth method 0x%02x", resp[1])
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("split target %q: %w", targetAddr, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	req := make([]byte, 0, 10+len(host))
	req = append(req, 0x05, 0x01, 0x00) // VER=5, CMD=CONNECT, RSV=0
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			a4 := ip.As4()
			req = append(req, 0x01)
			req = append(req, a4[:]...)
		} else {
			a16 := ip.As16()
			req = append(req, 0x04)
			req = append(req, a16[:]...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("target domain exceeds 255 bytes")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(portNum))
	req = append(req, portBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("read CONNECT reply: %w", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed with code 0x%02x", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		var discard [6]byte
		_, err = io.ReadFull(conn, discard[:])
	case 0x04:
		var discard [18]byte
		_, err = io.ReadFull(conn, discard[:])
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err == nil {
			discard := make([]byte, int(l[0])+2)
			_, err = io.ReadFull(conn, discard)
		}
	default:
		return nil, fmt.Errorf("unknown ATYP 0x%02x", hdr[3])
	}
	if err != nil {
		return nil, fmt.Errorf("drain bind addr: %w", err)
	}

	success = true
	return conn, nil
}

// ProbeProfile performs an HTTP/HTTPS trace probe through a SOCKS5 server.
func ProbeProfile(ctx context.Context, proxyHost string, proxyPort int, user, pass string, testURLs []string) (*ProbeResult, error) {
	if len(testURLs) == 0 {
		testURLs = []string{
			"https://www.cloudflare.com/cdn-cgi/trace",
			"https://api.ip.sb/ip",
		}
	}
	proxyAddr := state.FormatEndpoint(proxyHost, proxyPort)
	tr := &http.Transport{
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, fmt.Errorf("unsupported network %q", network)
			}
			return DialSOCKS5(dialCtx, proxyAddr, user, pass, addr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}

	var lastErr error
	for _, u := range testURLs {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		latency := time.Since(start)
		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("status %d err=%v", resp.StatusCode, readErr)
			continue
		}
		ip, loc := parseTraceOutput(string(body))
		if ip == "" {
			lastErr = fmt.Errorf("no IP parsed from %s", u)
			continue
		}
		return &ProbeResult{
			StatusCode: resp.StatusCode,
			ExitIP:     ip,
			Location:   loc,
			Latency:    latency,
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("probe failed")
	}
	return nil, lastErr
}

func parseTraceOutput(body string) (ip string, loc string) {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		} else if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimSpace(strings.TrimPrefix(line, "loc="))
		}
	}
	if ip == "" {
		for _, line := range lines {
			f := strings.Fields(line)
			if len(f) > 0 {
				ip = f[0]
				break
			}
		}
	}
	return ip, loc
}
