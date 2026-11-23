package doh

import (
	"context"
	"encoding/base64"
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
)

const (
	maxDNSWireBytes      = 4096
	defaultMaxConcurrent = 128
)

// Config configures the built-in RFC 8484 DoH forwarding server.
type Config struct {
	ListenAddr    string
	Path          string
	Upstreams     []string
	Timeout       time.Duration
	MaxConcurrent int
}

// Handler implements RFC 8484 DNS-over-HTTPS (GET ?dns= and POST application/dns-message).
type Handler struct {
	Path          string
	Upstreams     []string
	Timeout       time.Duration
	MaxConcurrent int
	sem           chan struct{}
}

// NewHandler creates a DoH HTTP handler with sane defaults.
func NewHandler(cfg Config) *Handler {
	path := cfg.Path
	if path == "" {
		path = "/dq"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	ups := cfg.Upstreams
	if len(ups) == 0 {
		ups = []string{"1.1.1.1:53", "8.8.8.8:53", "127.0.0.53:53", "127.0.0.1:53"}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	maxConc := cfg.MaxConcurrent
	if maxConc <= 0 {
		maxConc = defaultMaxConcurrent
	}
	return &Handler{
		Path:          path,
		Upstreams:     ups,
		Timeout:       timeout,
		MaxConcurrent: maxConc,
		sem:           make(chan struct{}, maxConc),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.Path {
		http.NotFound(w, r)
		return
	}
	if h.sem != nil {
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		default:
			http.Error(w, "too many concurrent requests", http.StatusServiceUnavailable)
			return
		}
	}

	var wireReq []byte
	switch r.Method {
	case http.MethodGet:
		b64 := strings.TrimSpace(r.URL.Query().Get("dns"))
		if b64 == "" {
			http.Error(w, "missing dns query parameter", http.StatusBadRequest)
			return
		}
		var err error
		wireReq, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "="))
		if err != nil {
			http.Error(w, "invalid base64url dns payload", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
		if ct != "application/dns-message" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxDNSWireBytes+1))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if len(b) > maxDNSWireBytes {
			http.Error(w, "dns message too large", http.StatusRequestEntityTooLarge)
			return
		}
		wireReq = b
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(wireReq) < 12 || len(wireReq) > maxDNSWireBytes {
		http.Error(w, "invalid DNS message length", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.Timeout)
	defer cancel()

	wireResp, err := h.exchange(ctx, wireReq)
	if err != nil {
		http.Error(w, "upstream DNS failure", http.StatusBadGateway)
		return
	}

	minTTL := parseMinTTL(wireResp)
	w.Header().Set("Content-Type", "application/dns-message")
	if minTTL > 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(minTTL), 10))
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wireResp)
}

func (h *Handler) exchange(ctx context.Context, req []byte) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok && h.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.Timeout)
		defer cancel()
	}
	var lastErr error
	for i, upstream := range h.Upstreams {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		tryCtx := ctx
		var cancel context.CancelFunc
		remainingCount := len(h.Upstreams) - i
		if remainingCount > 1 {
			if dl, ok := ctx.Deadline(); ok {
				rem := time.Until(dl)
				if rem <= 0 {
					if lastErr != nil {
						return nil, lastErr
					}
					return nil, context.DeadlineExceeded
				}
				var perTry time.Duration
				if h.Timeout > 0 && h.Timeout < 1200*time.Millisecond {
					perTry = rem / time.Duration(remainingCount)
				} else {
					total := h.Timeout
					if total <= 0 {
						total = rem
					}
					perTry = total / time.Duration(len(h.Upstreams))
					if perTry < 1200*time.Millisecond {
						perTry = 1200 * time.Millisecond
					}
					if perTry > rem {
						perTry = rem
					}
				}
				if perTry > 0 && perTry < rem {
					tryCtx, cancel = context.WithTimeout(ctx, perTry)
				}
			}
		}
		resp, err := exchangeSingle(tryCtx, upstream, req)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no upstreams configured")
	}
	return nil, lastErr
}

func normalizeUpstreamAddr(upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if ip, err := netip.ParseAddr(strings.Trim(upstream, "[]")); err == nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	if host, port, err := net.SplitHostPort(upstream); err == nil {
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	if !strings.Contains(upstream, ":") {
		return net.JoinHostPort(upstream, "53")
	}
	return upstream
}

func exchangeSingle(ctx context.Context, upstream string, req []byte) ([]byte, error) {
	upstream = normalizeUpstreamAddr(upstream)
	resp, truncated, err := exchangeUDP(ctx, upstream, req)
	if err == nil && !truncated {
		return resp, nil
	}
	return exchangeTCP(ctx, upstream, req)
}

func exchangeUDP(ctx context.Context, addr string, req []byte) ([]byte, bool, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(req); err != nil {
		return nil, false, err
	}
	buf := make([]byte, maxDNSWireBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, errors.New("short UDP DNS response")
	}
	if binary.BigEndian.Uint16(buf[:2]) != binary.BigEndian.Uint16(req[:2]) {
		return nil, false, errors.New("DNS transaction ID mismatch")
	}
	tc := (buf[2] & 0x02) != 0
	return buf[:n], tc, nil
}

func exchangeTCP(ctx context.Context, addr string, req []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	pkt := make([]byte, 2+len(req))
	binary.BigEndian.PutUint16(pkt[:2], uint16(len(req)))
	copy(pkt[2:], req)
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("invalid TCP DNS response length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(resp[:2]) != binary.BigEndian.Uint16(req[:2]) {
		return nil, errors.New("DNS transaction ID mismatch")
	}
	return resp, nil
}

func skipDNSName(msg []byte, off int) (int, bool) {
	jumps := 0
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			return off + 1, true
		}
		if (l & 0xC0) == 0xC0 {
			if off+1 >= len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		if l > 63 {
			return 0, false
		}
		off += 1 + l
		jumps++
		if jumps > 128 {
			return 0, false
		}
	}
	return 0, false
}

func parseMinTTL(msg []byte) uint32 {
	if len(msg) < 12 {
		return 0
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))

	off := 12
	var ok bool
	for i := 0; i < qd; i++ {
		off, ok = skipDNSName(msg, off)
		if !ok || off+4 > len(msg) {
			return 0
		}
		off += 4
	}

	totalRR := an + ns + ar
	var minTTL uint32
	hasTTL := false
	for i := 0; i < totalRR; i++ {
		off, ok = skipDNSName(msg, off)
		if !ok || off+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			break
		}
		off += rdlen
		if rtype == 41 { // OPT pseudo-RR
			continue
		}
		if !hasTTL || ttl < minTTL {
			minTTL = ttl
			hasTTL = true
		}
	}
	return minTTL
}

// ListenAndServe runs the standalone DoH HTTP server until ctx is cancelled.
func ListenAndServe(ctx context.Context, cfg Config) error {
	addr := cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:9853"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
