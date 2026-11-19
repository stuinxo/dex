package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// CertReport summarizes the inspection of a certificate + private key PEM pair.
type CertReport struct {
	CommonName       string    `json:"common_name"`
	SANs             []string  `json:"sans"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	SelfSigned       bool      `json:"self_signed"`
	ChainValid       bool      `json:"chain_valid"`
	ExpiringSoon     bool      `json:"expiring_soon"`
	Warnings         []string  `json:"warnings,omitempty"`
	IntermediateCount int      `json:"intermediate_count"`
}

var (
	domainSyntaxRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)
	multiLevelPSLs = []string{
		".co.uk", ".org.uk", ".gov.uk", ".ac.uk", ".net.uk", ".me.uk", ".plc.uk", ".ltd.uk",
		".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn", ".ac.cn",
		".com.hk", ".net.hk", ".org.hk", ".edu.hk", ".gov.hk",
		".com.tw", ".net.tw", ".org.tw", ".edu.tw", ".gov.tw",
		".com.au", ".net.au", ".org.au", ".edu.au", ".gov.au",
		".co.jp", ".or.jp", ".ne.jp", ".ac.jp", ".go.jp",
		".co.kr", ".or.kr", ".ne.kr",
		".com.sg", ".com.br", ".com.mx", ".com.tr",
		".co.za", ".co.in", ".co.nz",
		".eu.org",
	}
)

// ParsePrivateKey parses a PEM-encoded unencrypted private key (PKCS8, EC SEC1, or PKCS1 RSA).
func ParsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	var block *pem.Block
	rest := keyPEM
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no private key PEM block found")
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			break
		}
	}
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // detect legacy encrypted PEMs cleanly
		return nil, errors.New("encrypted private keys are not supported")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported PKCS8 key type")
		}
		return signer, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unable to parse private key (expected PKCS8, EC, or RSA PEM)")
}

func publicKeysEqual(pubA, pubB crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	if eq, ok := pubA.(equaler); ok {
		return eq.Equal(pubB)
	}
	switch a := pubA.(type) {
	case *rsa.PublicKey:
		b, ok := pubB.(*rsa.PublicKey)
		return ok && a.Equal(b)
	case *ecdsa.PublicKey:
		b, ok := pubB.(*ecdsa.PublicKey)
		return ok && a.Equal(b)
	case ed25519.PublicKey:
		b, ok := pubB.(ed25519.PublicKey)
		return ok && a.Equal(b)
	default:
		return false
	}
}

// InspectPair parses and validates a PEM certificate chain and matching private key.
func InspectPair(certPEM, keyPEM []byte) (*CertReport, error) {
	return inspectPairAt(certPEM, keyPEM, time.Now(), nil)
}

func inspectPairAt(certPEM, keyPEM []byte, now time.Time, customRoots *x509.CertPool) (*CertReport, error) {
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE PEM block found")
	}

	signer, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	leaf := certs[0]
	if !publicKeysEqual(leaf.PublicKey, signer.Public()) {
		return nil, errors.New("certificate public key does not match private key")
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}

	seenSAN := make(map[string]struct{})
	var sans []string
	addSAN := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		lower := strings.ToLower(name)
		if _, ok := seenSAN[lower]; ok {
			return
		}
		seenSAN[lower] = struct{}{}
		sans = append(sans, name)
	}
	for _, d := range leaf.DNSNames {
		addSAN(d)
	}
	if leaf.Subject.CommonName != "" {
		addSAN(leaf.Subject.CommonName)
	}

	selfSigned := bytes.Equal(leaf.RawSubject, leaf.RawIssuer) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	report := &CertReport{
		CommonName:        leaf.Subject.CommonName,
		SANs:              sans,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		SelfSigned:        selfSigned,
		IntermediateCount: len(certs) - 1,
	}

	if leaf.NotAfter.Sub(now) < 14*24*time.Hour {
		report.ExpiringSoon = true
		report.Warnings = append(report.Warnings, fmt.Sprintf("certificate expires within 14 days (%s)", leaf.NotAfter.Format("2006-01-02")))
	}

	if selfSigned {
		report.Warnings = append(report.Warnings, "certificate is self-signed; clients with allowInsecure=false will reject it")
		report.ChainValid = false
	} else {
		inter := x509.NewCertPool()
		for _, ic := range certs[1:] {
			inter.AddCert(ic)
		}
		opts := x509.VerifyOptions{
			Intermediates: inter,
			Roots:         customRoots,
			CurrentTime:   now,
		}
		if _, err := leaf.Verify(opts); err == nil {
			report.ChainValid = true
		} else {
			report.ChainValid = false
			report.Warnings = append(report.Warnings, fmt.Sprintf("certificate chain verification warning: %v", err))
		}
	}

	return report, nil
}

// CoversDomain reports whether the certificate covers domain (exact or single-level wildcard *.parent).
func CoversDomain(report *CertReport, domain string) bool {
	if report == nil {
		return false
	}
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}
	for _, san := range report.SANs {
		s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(san), "."))
		if s == d {
			return true
		}
		if strings.HasPrefix(s, "*.") {
			suffix := strings.TrimPrefix(s, "*.")
			if idx := strings.IndexByte(d, '.'); idx > 0 && d[idx+1:] == suffix {
				return true
			}
		}
	}
	return false
}

// BuildWildcardSANs computes the ACME main domain and wildcard SAN set matching v2 ui-installCER,
// avoiding redundant exact subdomain entries that Let's Encrypt Boulder rejects (400).
func BuildWildcardSANs(domain string) (mainDomain string, sans []string, err error) {
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if _, ipErr := netip.ParseAddr(d); ipErr == nil {
		return "", nil, fmt.Errorf("ACME wildcard certificates require a domain name, got IP %q", domain)
	}
	if !domainSyntaxRe.MatchString(d) {
		return "", nil, fmt.Errorf("invalid domain %q", domain)
	}

	isMultiLevelPSL := false
	for _, suf := range multiLevelPSLs {
		if strings.HasSuffix(d, suf) {
			isMultiLevelPSL = true
			break
		}
	}

	labels := strings.Split(d, ".")
	minApexLabels := 2
	if isMultiLevelPSL {
		minApexLabels = 3
	}

	if len(labels) <= minApexLabels {
		return d, []string{d, "*." + d}, nil
	}

	parent := strings.Join(labels[1:], ".")
	return parent, []string{parent, "*." + parent, "*." + d}, nil
}
