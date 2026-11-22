package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/socks5out"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// ProbeNodeResult reports reachability and RTT for a single OutboundNode.
type ProbeNodeResult struct {
	NodeID     string `json:"node_id"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

// ProbeNodeHealth tests reachability of a node by connecting TCP to node.Address:node.Port
// while enforcing TLS ServerName = node.EffectiveSNI() (fixing v2's relay IP vs SNI bug).
func ProbeNodeHealth(ctx context.Context, n state.OutboundNode, timeout time.Duration, insecureSkipVerifyForTest bool) ProbeNodeResult {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	port := n.Port
	if port <= 0 {
		port = 443
	}
	targetTCP := net.JoinHostPort(n.Address, strconv.Itoa(port))
	start := time.Now()

	switch n.Protocol {
	case "socks5":
		conn, err := socks5out.DialSOCKS5(ctx, targetTCP, n.Username, n.Password, "1.1.1.1:443")
		lat := time.Since(start).Milliseconds()
		if err != nil {
			return ProbeNodeResult{NodeID: n.ID, Healthy: false, LatencyMS: lat, Error: err.Error()}
		}
		_ = conn.Close()
		return ProbeNodeResult{NodeID: n.ID, Healthy: true, LatencyMS: lat}

	case "vless-reality", "vmess-tcp":
		var d net.Dialer
		d.Timeout = timeout
		conn, err := d.DialContext(ctx, "tcp", targetTCP)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			return ProbeNodeResult{NodeID: n.ID, Healthy: false, LatencyMS: lat, Error: err.Error()}
		}
		_ = conn.Close()
		return ProbeNodeResult{NodeID: n.ID, Healthy: true, LatencyMS: lat}

	default: // vless-xhttp, vless-ws, vmess-ws (HTTPS/TLS, supports HTTP/2 & HTTP/1.1 ALPN)
		sni := n.EffectiveSNI()
		path := render.NormalizePath(n.Path, n.UUID)
		tr := &http.Transport{
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				ServerName:         sni,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: insecureSkipVerifyForTest,
			},
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dialCtx, "tcp", targetTCP)
			},
		}
		defer tr.CloseIdleConnections()

		client := &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		reqURL := fmt.Sprintf("https://%s%s", net.JoinHostPort(strings.Trim(sni, "[]"), strconv.Itoa(port)), path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return ProbeNodeResult{NodeID: n.ID, Healthy: false, Error: err.Error()}
		}
		resp, err := client.Do(req)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			return ProbeNodeResult{NodeID: n.ID, Healthy: false, LatencyMS: lat, Error: err.Error()}
		}
		_ = resp.Body.Close()
		healthy := resp.StatusCode == 200 || resp.StatusCode == 204 ||
			resp.StatusCode == 301 || resp.StatusCode == 302 ||
			resp.StatusCode == 400 || resp.StatusCode == 404
		return ProbeNodeResult{
			NodeID:     n.ID,
			Healthy:    healthy,
			StatusCode: resp.StatusCode,
			LatencyMS:  lat,
		}
	}
}

// DefaultEgressProbe checks live proxy egress connectivity over HTTPS.
func DefaultEgressProbe(ctx context.Context) bool {
	targets := []string{
		"https://www.cloudflare.com/cdn-cgi/trace",
		"https://1.1.1.1",
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, u := range targets {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 405 {
			return true
		}
	}
	return false
}

// FailoverController implements sequential priority failover and failback.
type FailoverController struct {
	FailThreshold    int
	RecoverThreshold int
	ProbeEgress      func(ctx context.Context) bool
	ProbeNode        func(ctx context.Context, n state.OutboundNode) ProbeNodeResult
	SwitchNode       func(ctx context.Context, nodeID string) error
	Hub              *TaskHub

	failCount          int
	recoverCounts      map[string]int
	autoSwitchedNodeID string
}

// NewFailoverController creates a FailoverController with standard 3-strike thresholds.
func NewFailoverController(hub *TaskHub, switcher func(context.Context, string) error) *FailoverController {
	return &FailoverController{
		FailThreshold:    3,
		RecoverThreshold: 3,
		ProbeEgress:      DefaultEgressProbe,
		ProbeNode: func(ctx context.Context, n state.OutboundNode) ProbeNodeResult {
			return ProbeNodeHealth(ctx, n, 4500*time.Millisecond, false)
		},
		SwitchNode:    switcher,
		Hub:           hub,
		recoverCounts: make(map[string]int),
	}
}

func (f *FailoverController) log(level, msg string) {
	if f.Hub != nil {
		f.Hub.Log(level, "failover", msg)
	}
}

// Step runs one inspection cycle against the current state snapshot.
func (f *FailoverController) Step(ctx context.Context, st *state.State) {
	if st == nil || st.Role != state.RoleClient || !st.Client.FailoverEnabled || len(st.Client.Nodes) < 2 {
		f.failCount = 0
		f.autoSwitchedNodeID = ""
		for k := range f.recoverCounts {
			delete(f.recoverCounts, k)
		}
		return
	}

	active := st.Client.ActiveNode()
	if active == nil {
		return
	}
	if f.autoSwitchedNodeID != "" && active.ID != f.autoSwitchedNodeID {
		f.autoSwitchedNodeID = ""
	}
	// Pause automatic switching when manual Reality node is active (matches v2 ui-failover).
	if active.Protocol == "vless-reality" && f.autoSwitchedNodeID != active.ID {
		f.failCount = 0
		for k := range f.recoverCounts {
			delete(f.recoverCounts, k)
		}
		return
	}

	activeIdx := 0
	for i, n := range st.Client.Nodes {
		if n.ID == active.ID {
			activeIdx = i
			break
		}
	}

	// 1. Failback: check higher-priority nodes (0 .. activeIdx-1)
	if activeIdx > 0 {
		for i := 0; i < activeIdx; i++ {
			cand := st.Client.Nodes[i]
			res := f.ProbeNode(ctx, cand)
			if res.Healthy {
				f.recoverCounts[cand.ID]++
				f.log("INFO", fmt.Sprintf("higher-priority node [%s] %s healthy (%d/%d)",
					cand.ID, cand.Name, f.recoverCounts[cand.ID], f.RecoverThreshold))
				if f.recoverCounts[cand.ID] >= f.RecoverThreshold {
					if err := f.SwitchNode(ctx, cand.ID); err != nil {
						f.log("ERROR", fmt.Sprintf("failback switch to %s failed: %v", cand.ID, err))
					} else {
						f.log("INFO", fmt.Sprintf("FAILBACK switched active node to [%s] %s", cand.ID, cand.Name))
						if cand.Protocol == "vless-reality" {
							f.autoSwitchedNodeID = cand.ID
						} else {
							f.autoSwitchedNodeID = ""
						}
						f.failCount = 0
						for k := range f.recoverCounts {
							delete(f.recoverCounts, k)
						}
						return
					}
				}
			} else {
				f.recoverCounts[cand.ID] = 0
			}
		}
	}

	// 2. Active egress health check
	if f.ProbeEgress(ctx) {
		if f.failCount > 0 {
			f.log("INFO", fmt.Sprintf("active node [%s] %s egress recovered", active.ID, active.Name))
		}
		f.failCount = 0
		return
	}

	f.failCount++
	f.log("WARN", fmt.Sprintf("active node [%s] %s egress failed (%d/%d)",
		active.ID, active.Name, f.failCount, f.FailThreshold))
	if f.failCount < f.FailThreshold {
		return
	}

	// 3. Failover to next healthy node in priority order
	for _, cand := range st.Client.Nodes {
		if cand.ID == active.ID {
			continue
		}
		res := f.ProbeNode(ctx, cand)
		if !res.Healthy {
			f.log("WARN", fmt.Sprintf("backup node [%s] %s unreachable", cand.ID, cand.Name))
			continue
		}
		if err := f.SwitchNode(ctx, cand.ID); err != nil {
			f.log("ERROR", fmt.Sprintf("failover switch to %s failed: %v", cand.ID, err))
			continue
		}
		f.log("WARN", fmt.Sprintf("FAILOVER switched active node from [%s] to [%s] %s", active.ID, cand.ID, cand.Name))
		if cand.Protocol == "vless-reality" {
			f.autoSwitchedNodeID = cand.ID
		} else {
			f.autoSwitchedNodeID = ""
		}
		f.failCount = 0
		for k := range f.recoverCounts {
			delete(f.recoverCounts, k)
		}
		return
	}
	f.log("ERROR", "all backup nodes unreachable; retaining current active node")
}
