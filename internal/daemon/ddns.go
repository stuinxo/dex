package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudflareDDNS keeps Cloudflare A/AAAA DNS records synchronized with the host's public IP.
type CloudflareDDNS struct {
	BaseURL      string
	HTTPClient   *http.Client
	FetchPublic4 func(ctx context.Context) (string, error)
	FetchPublic6 func(ctx context.Context) (string, error)
	Hub          *TaskHub

	mu        sync.Mutex
	lastIP4   map[string]string // normalized domain -> last IPv4
	lastIP6   map[string]string // normalized domain -> last IPv6
	zoneCache map[string]string // domain -> zoneID
	recCache4 map[string]string // domain -> recordID
	recCache6 map[string]string // domain -> recordID
}

var (
	cnPublicIPv4URLs = []string{
		"https://myip.ipip.net/s",
		"http://members.3322.org/dyndns/getip",
		"http://ip.3322.net",
		"https://4.ipw.cn",
		"https://api-ipv4.ip.sb/ip",
	}
	cnPublicIPv6URLs = []string{
		"https://6.ipw.cn",
		"https://api6.ipify.org",
		"https://ifconfig.me",
	}
	globalPublicIPv4URLs = []string{
		"https://api.ipify.org",
		"https://ip.sb",
		"https://ifconfig.me",
	}
)

func newDirectHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:       newDirectDialer().DialContext,
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,
		},
	}
}

// ConnectivityCheck reports HTTP reachability and latency for a target probe path.
type ConnectivityCheck struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

func probeHTTPTargets(ctx context.Context, client *http.Client, urls []string) ConnectivityCheck {
	var last ConnectivityCheck
	for _, u := range urls {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			last = ConnectivityCheck{Error: err.Error(), LatencyMS: time.Since(start).Milliseconds()}
			continue
		}
		resp, err := client.Do(req)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			last = ConnectivityCheck{Error: err.Error(), LatencyMS: lat}
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return ConnectivityCheck{OK: true, StatusCode: resp.StatusCode, LatencyMS: lat}
		}
		last = ConnectivityCheck{StatusCode: resp.StatusCode, LatencyMS: lat, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return last
}

// ProbeConnectivity tests domestic direct (SO_MARK=0xff) and global outbound proxy connectivity.
func ProbeConnectivity(ctx context.Context) (cn ConnectivityCheck, global ConnectivityCheck) {
	cDirect := newDirectHTTPClient()
	cDirect.Timeout = 6 * time.Second
	cGlobal := &http.Client{Timeout: 6 * time.Second}
	cn = probeHTTPTargets(ctx, cDirect, []string{"https://www.baidu.com", "http://connect.rom.miui.com/generate_204"})
	global = probeHTTPTargets(ctx, cGlobal, []string{"https://www.google.com/generate_204", "https://cp.cloudflare.com/generate_204"})
	return cn, global
}

// FetchCNPublicIP probes the host's direct domestic WAN IPv4 using SO_MARK=0xff to bypass local TPROXY.
func FetchCNPublicIP(ctx context.Context) (string, error) {
	return fetchPublicIP(ctx, newDirectHTTPClient(), cnPublicIPv4URLs, false)
}

// FetchGlobalPublicIP probes the outbound proxy/global public IPv4 through the active routing path.
func FetchGlobalPublicIP(ctx context.Context) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second}
	return fetchPublicIP(ctx, c, globalPublicIPv4URLs, false)
}

// NewCloudflareDDNS constructs a CloudflareDDNS updater.
func NewCloudflareDDNS(hub *TaskHub) *CloudflareDDNS {
	c := &http.Client{Timeout: 10 * time.Second}
	directClient := newDirectHTTPClient()
	d := &CloudflareDDNS{
		BaseURL:    "https://api.cloudflare.com/client/v4",
		HTTPClient: c,
		Hub:        hub,
		lastIP4:    make(map[string]string),
		lastIP6:    make(map[string]string),
		zoneCache:  make(map[string]string),
		recCache4:  make(map[string]string),
		recCache6:  make(map[string]string),
	}
	d.FetchPublic4 = func(ctx context.Context) (string, error) {
		return fetchPublicIP(ctx, directClient, cnPublicIPv4URLs, false)
	}
	d.FetchPublic6 = func(ctx context.Context) (string, error) {
		return fetchPublicIP(ctx, directClient, cnPublicIPv6URLs, true)
	}
	return d
}

func fetchPublicIP(ctx context.Context, client *http.Client, urls []string, wantV6 bool) (string, error) {
	for _, u := range urls {
		reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		cancel()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		cand := strings.TrimSpace(string(b))
		if ip, err := netip.ParseAddr(cand); err == nil {
			if wantV6 && ip.Is6() {
				return ip.String(), nil
			}
			if !wantV6 && ip.Is4() {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("unable to determine public IP")
}

// SyncResult describes what changed in a DDNS sync run.
type SyncResult struct {
	Domain   string `json:"domain"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Updated4 bool   `json:"updated4"`
	Updated6 bool   `json:"updated6"`
}

// SyncOnce checks public IPv4 (and IPv6 if enableIPv6) and updates Cloudflare if changed or forced.
func (d *CloudflareDDNS) SyncOnce(ctx context.Context, domain, cfToken string, enableIPv6, force bool) (*SyncResult, error) {
	return d.SyncOnceWithEmail(ctx, domain, cfToken, "", enableIPv6, force)
}

func normalizeDDNSDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// SyncOnceWithEmail checks public IPv4/IPv6 and updates Cloudflare using Bearer API Token
// or Global API Key (X-Auth-Email + X-Auth-Key) when cfEmail is non-empty.
func (d *CloudflareDDNS) SyncOnceWithEmail(ctx context.Context, domain, cfToken, cfEmail string, enableIPv6, force bool) (*SyncResult, error) {
	domain = normalizeDDNSDomain(domain)
	cfToken = strings.TrimSpace(cfToken)
	cfEmail = strings.TrimSpace(cfEmail)
	if domain == "" || cfToken == "" {
		return nil, errors.New("missing DDNS domain or Cloudflare token")
	}

	res := &SyncResult{Domain: domain}
	ip4, err4 := d.FetchPublic4(ctx)
	if err4 != nil {
		return nil, err4
	}
	res.IPv4 = ip4

	d.mu.Lock()
	if d.lastIP4 == nil {
		d.lastIP4 = make(map[string]string)
	}
	need4 := force || ip4 != d.lastIP4[domain]
	d.mu.Unlock()
	if need4 {
		if err := d.upsertRecord(ctx, domain, cfToken, cfEmail, "A", ip4); err != nil {
			return nil, fmt.Errorf("update A record: %w", err)
		}
		d.mu.Lock()
		d.lastIP4[domain] = ip4
		d.mu.Unlock()
		res.Updated4 = true
		if d.Hub != nil {
			d.Hub.Log("INFO", "ddns", fmt.Sprintf("updated A %s -> %s", domain, ip4))
		}
	}

	if enableIPv6 {
		if ip6, err6 := d.FetchPublic6(ctx); err6 == nil && ip6 != "" {
			res.IPv6 = ip6
			d.mu.Lock()
			if d.lastIP6 == nil {
				d.lastIP6 = make(map[string]string)
			}
			need6 := force || ip6 != d.lastIP6[domain]
			d.mu.Unlock()
			if need6 {
				if err := d.upsertRecord(ctx, domain, cfToken, cfEmail, "AAAA", ip6); err != nil {
					return res, fmt.Errorf("update AAAA record: %w", err)
				}
				d.mu.Lock()
				d.lastIP6[domain] = ip6
				d.mu.Unlock()
				res.Updated6 = true
				if d.Hub != nil {
					d.Hub.Log("INFO", "ddns", fmt.Sprintf("updated AAAA %s -> %s", domain, ip6))
				}
			}
		}
	}
	return res, nil
}

func (d *CloudflareDDNS) cfRequest(ctx context.Context, method, path, token, email string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(d.BaseURL, "/")+path, bodyReader)
	if err != nil {
		return err
	}
	if strings.TrimSpace(email) != "" {
		req.Header.Set("X-Auth-Email", strings.TrimSpace(email))
		req.Header.Set("X-Auth-Key", token)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var env struct {
		Success bool            `json:"success"`
		Errors  []any           `json:"errors"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("cloudflare HTTP %d invalid JSON: %w", resp.StatusCode, err)
	}
	if resp.StatusCode >= 400 || !env.Success {
		return fmt.Errorf("cloudflare API error (status=%d): %v", resp.StatusCode, env.Errors)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (d *CloudflareDDNS) findZoneID(ctx context.Context, domain, token, email string) (string, error) {
	domain = normalizeDDNSDomain(domain)
	d.mu.Lock()
	zid := d.zoneCache[domain]
	d.mu.Unlock()
	if zid != "" {
		return zid, nil
	}

	type cfZone struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	normDom := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	pickBestZone := func(zones []cfZone) string {
		bestLen := -1
		bestID := ""
		for _, z := range zones {
			zn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".")
			if zn == "" {
				continue
			}
			if normDom == zn || strings.HasSuffix(normDom, "."+zn) {
				if len(zn) > bestLen {
					bestLen = len(zn)
					bestID = z.ID
				}
			}
		}
		return bestID
	}

	var lastErr error
	labels := strings.Split(normDom, ".")
	for i := 0; i <= len(labels)-2; i++ {
		cand := strings.Join(labels[i:], ".")
		var zones []cfZone
		if err := d.cfRequest(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(cand), token, email, nil, &zones); err != nil {
			lastErr = err
			continue
		}
		if id := pickBestZone(zones); id != "" {
			zid = id
			break
		}
	}

	if zid == "" {
		var zones []cfZone
		if err := d.cfRequest(ctx, http.MethodGet, "/zones?per_page=50", token, email, nil, &zones); err != nil {
			if lastErr != nil {
				return "", lastErr
			}
			return "", err
		}
		zid = pickBestZone(zones)
	}
	if zid == "" {
		return "", fmt.Errorf("no matching Cloudflare zone for %q", domain)
	}
	d.mu.Lock()
	d.zoneCache[domain] = zid
	d.mu.Unlock()
	return zid, nil
}

func (d *CloudflareDDNS) lookupRecord(ctx context.Context, zoneID, domain, token, email, recType string) (recID string, content string, err error) {
	var recs []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	q := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recType, url.QueryEscape(domain))
	if err := d.cfRequest(ctx, http.MethodGet, q, token, email, nil, &recs); err != nil {
		return "", "", err
	}
	for _, r := range recs {
		if strings.EqualFold(r.Name, domain) {
			return r.ID, r.Content, nil
		}
	}
	return "", "", nil
}

func (d *CloudflareDDNS) upsertRecord(ctx context.Context, domain, token, email, recType, ip string) error {
	domain = normalizeDDNSDomain(domain)
	zoneID, err := d.findZoneID(ctx, domain, token, email)
	if err != nil {
		return err
	}

	d.mu.Lock()
	cache := d.recCache4
	if recType == "AAAA" {
		cache = d.recCache6
	}
	recID := cache[domain]
	d.mu.Unlock()

	payload := map[string]any{
		"type":    recType,
		"name":    domain,
		"content": ip,
		"ttl":     1,
		"proxied": false,
	}

	if recID != "" {
		if err := d.cfRequest(ctx, http.MethodPut, fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recID), token, email, payload, nil); err == nil {
			return nil
		}
		// Stale or deleted record ID in cache: clear cache and re-query once.
		d.mu.Lock()
		delete(cache, domain)
		d.mu.Unlock()
		recID = ""
	}

	lookedID, existingContent, err := d.lookupRecord(ctx, zoneID, domain, token, email, recType)
	if err != nil {
		d.mu.Lock()
		delete(d.zoneCache, domain)
		d.mu.Unlock()
		return err
	}
	if lookedID != "" {
		recID = lookedID
		d.mu.Lock()
		cache[domain] = recID
		d.mu.Unlock()
		if existingContent == ip {
			return nil // already matches remote record
		}
		if err := d.cfRequest(ctx, http.MethodPut, fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recID), token, email, payload, nil); err != nil {
			d.mu.Lock()
			delete(cache, domain)
			delete(d.zoneCache, domain)
			d.mu.Unlock()
			return err
		}
		return nil
	}

	var created struct {
		ID string `json:"id"`
	}
	if err := d.cfRequest(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", zoneID), token, email, payload, &created); err != nil {
		d.mu.Lock()
		delete(d.zoneCache, domain)
		d.mu.Unlock()
		return err
	}
	if created.ID != "" {
		d.mu.Lock()
		cache[domain] = created.ID
		d.mu.Unlock()
	}
	return nil
}
