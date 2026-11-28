package state

import (
	"path/filepath"
	"testing"
)

func TestActiveCertPaths(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "custom-state"))
	for _, tc := range []struct {
		name, mode, cert, key string
		external              bool
	}{
		{"managed", "self_signed", "", "", false},
		{"acme", "acme_cf", "/external/cert", "/external/key", false},
		{"imported", "imported", "/external/cert", "/external/key", true},
		{"imported managed", "imported", store.DefaultCert(), store.DefaultKey(), false},
		{"missing key", "imported", "/external/cert", "", false},
		{"missing cert", "imported", "", "/external/key", false},
		{"empty imported", "imported", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := NewDefaultState(RoleClient)
			st.Cert.Mode, st.Cert.CertFile, st.Cert.KeyFile = tc.mode, tc.cert, tc.key
			wantCert, wantKey := store.DefaultCert(), store.DefaultKey()
			if tc.mode == "imported" && tc.cert != "" && tc.key != "" {
				wantCert, wantKey = tc.cert, tc.key
			}
			gotCert, gotKey := store.ActiveCertPaths(st)
			if gotCert != wantCert || gotKey != wantKey {
				t.Fatalf("ActiveCertPaths = (%q, %q), want (%q, %q)", gotCert, gotKey, wantCert, wantKey)
			}
			if gotExt := store.HasCustomExternalCert(st); gotExt != tc.external {
				t.Fatalf("HasCustomExternalCert = %v, want %v", gotExt, tc.external)
			}
		})
	}
	cert, key := store.ActiveCertPaths(nil)
	if cert != store.DefaultCert() || key != store.DefaultKey() {
		t.Fatal("nil state must resolve to managed pair")
	}
	if store.HasCustomExternalCert(nil) {
		t.Fatal("nil state cannot have custom external cert")
	}
}
