package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func buildTestDNSQuery(id uint16, qname string) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, id)
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD=1
	_ = binary.Write(&b, binary.BigEndian, uint16(1))      // QDCOUNT=1
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	for _, lbl := range bytes.Split([]byte(qname), []byte(".")) {
		if len(lbl) == 0 {
			continue
		}
		b.WriteByte(byte(len(lbl)))
		b.Write(lbl)
	}
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // A
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // IN
	return b.Bytes()
}

func buildTestDNSResponse(req []byte, ttl uint32, truncated bool) []byte {
	var b bytes.Buffer
	b.Write(req[:2]) // ID
	flags := uint16(0x8180)
	if truncated {
		flags |= 0x0200
	}
	_ = binary.Write(&b, binary.BigEndian, flags)
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // QD
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // AN
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	b.Write(req[12:]) // question verbatim
	// Answer: pointer to offset 12 (0xC00C)
	b.Write([]byte{0xC0, 0x0C})
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // A
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // IN
	_ = binary.Write(&b, binary.BigEndian, ttl)       // TTL
	_ = binary.Write(&b, binary.BigEndian, uint16(4)) // RDLENGTH
	b.Write([]byte{203, 0, 113, 42})                  // 203.0.113.42
	return b.Bytes()
}

func TestDoHGetPostAndTCPFallback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()

	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()

	var forceTruncated atomic.Bool
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildTestDNSResponse(buf[:n], 120, forceTruncated.Load())
			_, _ = pc.WriteTo(resp, raddr)
		}
	}()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var lb [2]byte
				if _, err := io.ReadFull(conn, lb[:]); err != nil {
					return
				}
				l := int(binary.BigEndian.Uint16(lb[:]))
				req := make([]byte, l)
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				resp := buildTestDNSResponse(req, 300, false)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = conn.Write(out)
			}(c)
		}
	}()

	h := NewHandler(Config{Path: "/dq", Upstreams: []string{addr}})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// 1. POST application/dns-message via UDP
	q1 := buildTestDNSQuery(0x1234, "example.com")
	resp1, err := http.Post(srv.URL+"/dq", "application/dns-message", bytes.NewReader(q1))
	if err != nil {
		t.Fatalf("POST /dq: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != 200 || resp1.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("unexpected POST response status=%d ct=%s", resp1.StatusCode, resp1.Header.Get("Content-Type"))
	}
	if resp1.Header.Get("Cache-Control") != "max-age=120" {
		t.Fatalf("Cache-Control = %q, want max-age=120", resp1.Header.Get("Cache-Control"))
	}
	if binary.BigEndian.Uint16(body1[:2]) != 0x1234 {
		t.Fatalf("transaction ID mismatch")
	}

	// 2. GET ?dns=... with TC=1 fallback to TCP (TTL 300)
	forceTruncated.Store(true)
	q2 := buildTestDNSQuery(0xABCD, "tcpfallback.example")
	resp2, err := http.Get(srv.URL + "/dq?dns=" + base64.RawURLEncoding.EncodeToString(q2))
	if err != nil {
		t.Fatalf("GET /dq: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != 200 || resp2.Header.Get("Cache-Control") != "max-age=300" {
		t.Fatalf("expected TCP fallback TTL 300, got status=%d cc=%s", resp2.StatusCode, resp2.Header.Get("Cache-Control"))
	}
	if binary.BigEndian.Uint16(body2[:2]) != 0xABCD {
		t.Fatalf("transaction ID mismatch on GET")
	}

	// 3. Reject invalid media type and bad payload
	respBad, err := http.Post(srv.URL+"/dq", "application/json", bytes.NewReader(q1))
	if err != nil {
		t.Fatalf("POST invalid media type: %v", err)
	}
	_ = respBad.Body.Close()
	if respBad.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", respBad.StatusCode)
	}
}

func TestDoHConcurrencyLimitReturns503(t *testing.T) {
	// Upstream UDP socket that intentionally never replies so requests block until timeout/cancel
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	tcpLn, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()

	h := NewHandler(Config{
		Path:          "/dq",
		Upstreams:     []string{pc.LocalAddr().String()},
		Timeout:       300 * time.Millisecond,
		MaxConcurrent: 2,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	q := buildTestDNSQuery(0x2222, "slow.example")
	inFlightDone := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			r, err := http.Post(srv.URL+"/dq", "application/dns-message", bytes.NewReader(q))
			if err == nil {
				_ = r.Body.Close()
			}
			inFlightDone <- struct{}{}
		}()
	}

	// Wait until both semaphore slots are occupied
	deadline := time.Now().Add(time.Second)
	for len(h.sem) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(h.sem) != 2 {
		t.Fatalf("expected 2 occupied concurrency slots, got %d", len(h.sem))
	}

	resp503, err := http.Post(srv.URL+"/dq", "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatalf("3rd concurrent request error: %v", err)
	}
	_ = resp503.Body.Close()
	if resp503.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable when MaxConcurrent reached, got %d", resp503.StatusCode)
	}

	<-inFlightDone
	<-inFlightDone
}
