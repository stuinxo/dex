package render

import (
	"fmt"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// RenderNginx generates a single declarative Nginx config (/etc/nginx/conf.d/dex-server.conf)
// without sed block slicing.
func RenderNginx(s *state.State, opts RenderOptions) (data []byte, needed bool, err error) {
	opts = opts.WithDefaults()
	hasMainNginx := s.Role == state.RoleServer && s.Server.TLSMode == "nginx"
	var extraViaNginx []state.ExtraInbound
	for _, ex := range s.ExtraInbounds {
		if ex.ViaNginx {
			extraViaNginx = append(extraViaNginx, ex)
		}
	}
	if !hasMainNginx && len(extraViaNginx) == 0 {
		return nil, false, nil
	}

	var b strings.Builder
	b.WriteString("# Managed declaratively by dex v3. Do not edit manually.\n\n")

	if hasMainNginx {
		domain := s.Server.Domain
		port := s.Server.ListenPort
		if port <= 0 {
			port = 443
		}
		firstUUID := ""
		if len(s.Server.UUIDs) > 0 {
			firstUUID = s.Server.UUIDs[0]
		}
		xhttpPath := NormalizePath(s.Server.Path, firstUUID)
		webRoot := s.Server.CamouflageDir
		if strings.TrimSpace(webRoot) == "" {
			webRoot = "/var/www/html"
		}

		if port == 443 {
			fmt.Fprintf(&b, `server {
  listen 80;
  server_name %s;
  return 301 https://$server_name$request_uri;
}

`, domain)
		}

		b.WriteString(`upstream dex_xray {
  server 127.0.0.1:9890;
  keepalive 32;
}

`)
		fmt.Fprintf(&b, `server {
  listen %d ssl;
  http2 on;
  server_name %s;
  root %s;
  index index.html index.htm;
  error_page 497 https://$host:%d$request_uri;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "origin" always;

  ssl_certificate %s;
  ssl_certificate_key %s;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_ecdh_curve X25519:secp384r1;
  ssl_session_tickets off;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 6h;
  ssl_buffer_size 4k;
  ssl_early_data on;

`, port, domain, webRoot, port, opts.CertFile, opts.KeyFile)

		if s.Server.EnableDoH {
			b.WriteString(`  location /dq {
    proxy_pass                  http://127.0.0.1:9853/dq;
    proxy_http_version          1.1;
    proxy_set_header            Host $host;
    proxy_set_header            X-Real-IP $remote_addr;
    proxy_connect_timeout       60s;
    proxy_read_timeout          60s;
    proxy_send_timeout          60s;
    chunked_transfer_encoding   off;
    proxy_redirect              off;
    proxy_store                 off;
    proxy_cache                 off;
    proxy_buffering             off;
    add_header Cache-Control    no-cache;
  }

`)
		}

		fmt.Fprintf(&b, `  location %s {
    proxy_pass                  http://dex_xray;
    proxy_http_version          1.1;
    proxy_set_header            Connection "";
    proxy_set_header            Host $host;
    proxy_set_header            X-Real-IP $remote_addr;
    proxy_set_header            X-Real-PORT $remote_port;
    proxy_set_header            X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header            Early-Data $ssl_early_data;
    proxy_redirect              off;
    proxy_buffering             off;
    proxy_request_buffering     off;
    client_max_body_size        0;
    proxy_connect_timeout       600s;
    proxy_read_timeout          600s;
    proxy_send_timeout          600s;
  }
}
`, xhttpPath)
	}

	for _, ex := range extraViaNginx {
		dom := ex.Domain
		if dom == "" {
			dom = s.Server.Domain
		}
		path := NormalizePath(ex.Path, ex.UUID)
		wsHeaders := `    proxy_set_header Connection "";`
		if ex.Protocol == "vless-ws" || ex.Protocol == "vmess-ws" {
			wsHeaders = `    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";`
		}
		fmt.Fprintf(&b, `
server {
  listen %d ssl;
  http2 on;
  server_name %s;
  ssl_certificate %s;
  ssl_certificate_key %s;
  ssl_protocols TLSv1.2 TLSv1.3;

  location %s {
    proxy_pass http://127.0.0.1:%d;
    proxy_http_version 1.1;
%s
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
    proxy_request_buffering off;
    client_max_body_size 0;
    proxy_read_timeout 600s;
  }
}
`, ex.ListenPort, dom, opts.CertFile, opts.KeyFile, path, ExtraInternalPort(ex.ListenPort), wsHeaders)
	}

	return []byte(b.String()), true, nil
}
