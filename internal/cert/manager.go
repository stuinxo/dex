package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ACMEConfig configures ACME certificate issuance via acme.sh (DNS-01 or HTTP-01).
type ACMEConfig struct {
	Domain    string
	CFToken   string
	CFEmail   string
	Webroot   string
	ListenV6  bool
	AutoRenew bool
	AcmeBin   string
	AcmeHome  string
	CertPath  string
	KeyPath   string
	ReloadCmd string
}

// ACMERunner executes acme.sh invocations (replaceable in tests).
type ACMERunner interface {
	Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
}

type osACMERunner struct{}

func (osACMERunner) Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.CombinedOutput()
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cert.tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// EnsureSelfSigned creates a 10-year ECDSA P-256 self-signed cert/key pair in pure Go
// if either file is missing or unreadable.
func EnsureSelfSigned(certPath, keyPath, cn string) error {
	if certB, err1 := os.ReadFile(certPath); err1 == nil {
		if keyB, err2 := os.ReadFile(keyPath); err2 == nil {
			if _, err := InspectPair(certB, keyB); err == nil {
				return nil
			}
		}
	}
	return generateAndWriteSelfSigned(certPath, keyPath, cn)
}

// ForceSelfSigned unconditionally generates and writes a new 10-year ECDSA P-256 self-signed cert/key pair.
func ForceSelfSigned(certPath, keyPath, cn string) error {
	return generateAndWriteSelfSigned(certPath, keyPath, cn)
}

func generateAndWriteSelfSigned(certPath, keyPath, cn string) error {
	if cn == "" {
		cn = "localhost"
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ECDSA key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().Add(-1 * time.Hour)
	dnsNames := []string{"localhost"}
	ipAddrs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(cn), "[]")); err == nil {
		stdIP := net.IP(ip.AsSlice())
		dup := false
		for _, existing := range ipAddrs {
			if existing.Equal(stdIP) {
				dup = true
				break
			}
		}
		if !dup {
			ipAddrs = append(ipAddrs, stdIP)
		}
	} else if !strings.EqualFold(cn, "localhost") && !strings.ContainsAny(cn, " \t\r\n") {
		dnsNames = append(dnsNames, cn)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"dex"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create self-signed certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(certPath, certPEM, 0o644)
}

// ImportPair validates a certificate/key pair, skips identical rewrites, and atomically installs them.
func ImportPair(srcCert, srcKey, dstCert, dstKey string, allowSelfSigned bool, checkDomains []string) (*CertReport, bool, error) {
	certPEM, err := os.ReadFile(srcCert)
	if err != nil {
		return nil, false, fmt.Errorf("read certificate %s: %w", srcCert, err)
	}
	keyPEM, err := os.ReadFile(srcKey)
	if err != nil {
		return nil, false, fmt.Errorf("read private key %s: %w", srcKey, err)
	}

	report, err := InspectPair(certPEM, keyPEM)
	if err != nil {
		return nil, false, err
	}
	if report.SelfSigned && !allowSelfSigned {
		return report, false, errors.New("self-signed certificates are rejected when allowSelfSigned=false")
	}
	for _, d := range checkDomains {
		d = strings.TrimSpace(d)
		if d != "" && !CoversDomain(report, d) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("certificate does not cover configured domain %s", d))
		}
	}

	oldCert, err1 := os.ReadFile(dstCert)
	oldKey, err2 := os.ReadFile(dstKey)
	if err1 == nil && err2 == nil && bytes.Equal(oldCert, certPEM) && bytes.Equal(oldKey, keyPEM) {
		return report, false, nil
	}

	if err := writeFileAtomic(dstKey, keyPEM, 0o600); err != nil {
		return report, false, fmt.Errorf("install private key: %w", err)
	}
	if err := writeFileAtomic(dstCert, certPEM, 0o644); err != nil {
		return report, false, fmt.Errorf("install certificate: %w", err)
	}
	return report, true, nil
}

func normalizeACMEConfig(cfg *ACMEConfig) ACMERunner {
	if cfg.AcmeBin == "" {
		cfg.AcmeBin = "/root/.acme.sh/acme.sh"
	}
	if cfg.AcmeHome == "" {
		cfg.AcmeHome = filepath.Dir(cfg.AcmeBin)
	}
	return osACMERunner{}
}

func ensureACMESh(ctx context.Context, runner ACMERunner, acmeBin, acmeHome, email string) error {
	if _, isOS := runner.(osACMERunner); !isOS {
		return nil
	}
	if _, statErr := os.Stat(acmeBin); !os.IsNotExist(statErr) {
		return nil
	}
	out, ierr := runner.Run(ctx, nil, "sh", "-c",
		`curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s -- --install-online --force --home "$1" --email "$2"`,
		"sh", acmeHome, email,
	)
	if ierr != nil {
		return fmt.Errorf("auto-install acme.sh failed: %w (%s)", ierr, strings.TrimSpace(string(out)))
	}
	if _, postErr := os.Stat(acmeBin); postErr != nil {
		return fmt.Errorf("acme.sh binary missing after install at %s: %w (%s)", acmeBin, postErr, strings.TrimSpace(string(out)))
	}
	return nil
}

func stageAndInstallACMECert(ctx context.Context, runner ACMERunner, env []string, cfg ACMEConfig, mainDomain string) (*CertReport, error) {
	acmeSrc := filepath.Join(cfg.AcmeHome, mainDomain+"_ecc")
	stagedCert := filepath.Join(acmeSrc, "fullchain.cer")
	stagedKey := filepath.Join(acmeSrc, mainDomain+".key")

	certPEM, err := os.ReadFile(stagedCert)
	if err != nil {
		return nil, fmt.Errorf("read issued cert %s: %w", stagedCert, err)
	}
	keyPEM, err := os.ReadFile(stagedKey)
	if err != nil {
		return nil, fmt.Errorf("read issued key %s: %w", stagedKey, err)
	}
	report, err := inspectPairAt(certPEM, keyPEM, time.Now(), nil)
	if err != nil {
		return nil, fmt.Errorf("issued certificate failed validation (existing cert untouched): %w", err)
	}

	if err := writeFileAtomic(cfg.KeyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := writeFileAtomic(cfg.CertPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}

	installArgs := []string{
		"--home", cfg.AcmeHome, "--install-cert", "-d", mainDomain, "--ecc",
		"--key-file", cfg.KeyPath,
		"--fullchain-file", cfg.CertPath,
	}
	if cfg.ReloadCmd != "" {
		installArgs = append(installArgs, "--reloadcmd", cfg.ReloadCmd)
	}
	if out, err := runner.Run(ctx, env, cfg.AcmeBin, installArgs...); err != nil {
		return nil, fmt.Errorf("acme install-cert failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return report, nil
}

// IssueCloudflareACME issues an EC-256 wildcard certificate via acme.sh DNS-01, stages and validates it,
// preserves previous certificates on failure, and scrubs CF credentials if AutoRenew is false.
func IssueCloudflareACME(ctx context.Context, runner ACMERunner, cfg ACMEConfig) (*CertReport, error) {
	defaultRunner := normalizeACMEConfig(&cfg)
	if runner == nil {
		runner = defaultRunner
	}
	if strings.TrimSpace(cfg.CFToken) == "" {
		return nil, errors.New("Cloudflare API Token is required")
	}
	mainDomain, sans, err := BuildWildcardSANs(cfg.Domain)
	if err != nil {
		return nil, err
	}
	if err := ensureACMESh(ctx, runner, cfg.AcmeBin, cfg.AcmeHome, "admin@"+mainDomain); err != nil {
		return nil, err
	}

	accountConf := filepath.Join(cfg.AcmeHome, "account.conf")
	scrubLegacyKeys(accountConf)
	if !cfg.AutoRenew {
		defer scrubTokenFromAccountConf(accountConf)
	}

	env := []string{"CF_Token=" + strings.TrimSpace(cfg.CFToken)}
	if strings.TrimSpace(cfg.CFEmail) != "" {
		env = []string{
			"CF_Key=" + strings.TrimSpace(cfg.CFToken),
			"CF_Email=" + strings.TrimSpace(cfg.CFEmail),
		}
	}
	if _, err := runner.Run(ctx, env, cfg.AcmeBin, "--home", cfg.AcmeHome, "--set-default-ca", "--server", "letsencrypt"); err != nil {
		return nil, fmt.Errorf("acme set-default-ca: %w", err)
	}

	args := []string{"--home", cfg.AcmeHome, "--force", "--issue", "--dns", "dns_cf", "--dnssleep", "45"}
	for _, s := range sans {
		args = append(args, "-d", s)
	}
	args = append(args, "-k", "ec-256")
	if out, err := runner.Run(ctx, env, cfg.AcmeBin, args...); err != nil {
		return nil, fmt.Errorf("acme issue failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	report, err := stageAndInstallACMECert(ctx, runner, env, cfg, mainDomain)
	if err != nil {
		return nil, err
	}
	return report, nil
}

// IssueHTTPACME issues a single-domain EC-256 certificate via acme.sh HTTP-01 (--webroot or --standalone).
func IssueHTTPACME(ctx context.Context, runner ACMERunner, cfg ACMEConfig) (*CertReport, error) {
	defaultRunner := normalizeACMEConfig(&cfg)
	if runner == nil {
		runner = defaultRunner
	}
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(cfg.Domain, ".")))
	if _, ipErr := netip.ParseAddr(d); ipErr == nil {
		return nil, fmt.Errorf("ACME HTTP-01 certificates require a domain name, got IP %q", cfg.Domain)
	}
	if !domainSyntaxRe.MatchString(d) {
		return nil, fmt.Errorf("invalid domain %q", cfg.Domain)
	}
	if err := ensureACMESh(ctx, runner, cfg.AcmeBin, cfg.AcmeHome, "admin@"+d); err != nil {
		return nil, err
	}
	if _, err := runner.Run(ctx, nil, cfg.AcmeBin, "--home", cfg.AcmeHome, "--set-default-ca", "--server", "letsencrypt"); err != nil {
		return nil, fmt.Errorf("acme set-default-ca: %w", err)
	}

	args := []string{"--home", cfg.AcmeHome, "--force", "--issue", "-d", d}
	if wr := strings.TrimSpace(cfg.Webroot); wr != "" {
		if strings.HasPrefix(wr, "-") || !filepath.IsAbs(wr) {
			return nil, fmt.Errorf("invalid webroot %q: must be an absolute path", cfg.Webroot)
		}
		for _, r := range wr {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("invalid webroot %q: control character not allowed", cfg.Webroot)
			}
		}
		args = append(args, "--webroot", wr)
	} else {
		args = append(args, "--standalone")
		if cfg.ListenV6 {
			args = append(args, "--listen-v6")
		}
	}
	args = append(args, "-k", "ec-256")
	if out, err := runner.Run(ctx, nil, cfg.AcmeBin, args...); err != nil {
		return nil, fmt.Errorf("acme http issue failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return stageAndInstallACMECert(ctx, runner, nil, cfg, d)
}

func scrubLegacyKeys(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	var kept []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.Contains(t, "CF_Token") || strings.Contains(t, "CF_Key") || strings.Contains(t, "CF_Email") || strings.Contains(t, "example.com") {
			continue
		}
		kept = append(kept, l)
	}
	_ = writeFileAtomic(path, []byte(strings.Join(kept, "\n")), 0o600)
}

func scrubTokenFromAccountConf(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	var kept []string
	for _, l := range lines {
		if strings.Contains(l, "CF_Token") || strings.Contains(l, "CF_Key") || strings.Contains(l, "CF_Email") {
			continue
		}
		kept = append(kept, l)
	}
	_ = writeFileAtomic(path, []byte(strings.Join(kept, "\n")), 0o600)
}
