package reconcile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuinxo/dex/internal/fsutil"
)

const fallbackPublicDNS = "nameserver 223.5.5.5\nnameserver 1.1.1.1\n"

func probeLocalDNS(ctx context.Context, addr string) error {
	// Minimal DNS A query for "localhost." with TXID 0x4458 ("DX")
	var pkt []byte
	pkt = binary.BigEndian.AppendUint16(pkt, 0x4458)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0100) // RD=1
	pkt = binary.BigEndian.AppendUint16(pkt, 1)      // QDCOUNT=1
	pkt = append(pkt, 0, 0, 0, 0, 0, 0)
	pkt = append(pkt, 9)
	pkt = append(pkt, []byte("localhost")...)
	pkt = append(pkt, 0, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN

	dctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(buf[:2]) != 0x4458 {
		return fmt.Errorf("invalid DNS probe reply (%d bytes)", n)
	}
	return nil
}

func hasNonLoopbackNameserver(content []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ns := strings.Trim(strings.TrimSpace(fields[1]), "[]")
			if ns == "127.0.0.1" || ns == "127.0.0.53" || ns == "::1" {
				continue
			}
			if ip, err := netip.ParseAddr(ns); err == nil && ip.IsLoopback() {
				continue
			}
			if ns != "" {
				return true
			}
		}
	}
	return false
}

func readOriginalResolvConf(rootPrefix string) []byte {
	resolvPath := fsutil.MapRootPrefix(rootPrefix, "/etc/resolv.conf")
	if b, err := os.ReadFile(resolvPath); err == nil && hasNonLoopbackNameserver(b) {
		return b
	}
	runResolvePath := fsutil.MapRootPrefix(rootPrefix, "/run/systemd/resolve/resolv.conf")
	if rb, err := os.ReadFile(runResolvePath); err == nil && hasNonLoopbackNameserver(rb) {
		return rb
	}
	return nil
}

func switchToLocalResolvConf(ctx context.Context, rootPrefix, stateDir string, backupResolvBytes []byte) error {
	var probeErr error
	for attempt := 0; attempt < 4; attempt++ {
		if probeErr = probeLocalDNS(ctx, "127.0.0.1:53"); probeErr == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if probeErr != nil {
		return fmt.Errorf("local DNS 127.0.0.1:53 readiness probe failed: %w", probeErr)
	}

	resolvPath := fsutil.MapRootPrefix(rootPrefix, "/etc/resolv.conf")
	origPath := filepath.Join(stateDir, "resolv.conf.orig")
	curResolvBytes, readResolvErr := os.ReadFile(resolvPath)
	curResolvLink, linkErr := os.Readlink(resolvPath)
	existingOrig, existingOrigErr := os.ReadFile(origPath)
	if existingOrigErr != nil || !hasNonLoopbackNameserver(existingOrig) {
		if len(backupResolvBytes) > 0 {
			_ = writeBytesExact(origPath, backupResolvBytes, 0o644)
		} else if readResolvErr == nil && hasNonLoopbackNameserver(curResolvBytes) {
			_ = writeBytesExact(origPath, curResolvBytes, 0o644)
		}
	}
	if linkErr == nil {
		_ = os.Remove(resolvPath)
	}
	if werr := writeBytesExact(resolvPath, []byte("nameserver 127.0.0.1\n"), 0o644); werr != nil {
		// Best-effort restore before returning failure
		if linkErr == nil && curResolvLink != "" {
			_ = os.Remove(resolvPath)
			_ = os.Symlink(curResolvLink, resolvPath)
		} else if readResolvErr == nil {
			_ = writeBytesExact(resolvPath, curResolvBytes, 0o644)
		}
		return fmt.Errorf("update /etc/resolv.conf: %w", werr)
	}
	return nil
}

func restoreResolvConfIfNeeded(resolvPath, origPath string) error {
	curBytes, err := os.ReadFile(resolvPath)
	if err != nil {
		return nil
	}
	if strings.TrimSpace(string(curBytes)) != "nameserver 127.0.0.1" {
		return nil
	}
	origBytes, err := os.ReadFile(origPath)
	if err != nil || len(bytes.TrimSpace(origBytes)) == 0 || !hasNonLoopbackNameserver(origBytes) {
		return writeBytesExact(resolvPath, []byte(fallbackPublicDNS), 0o644)
	}
	return writeBytesExact(resolvPath, origBytes, 0o644)
}
