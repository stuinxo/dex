package state

import "testing"

func TestCertificateModeTransitions(t *testing.T) {
	original := CertConfig{
		Mode: "imported", Domain: "previous.example.com",
		CertFile: "/external/cert", KeyFile: "/external/key",
		CFToken: "previous-token", CFEmail: "previous-email", AutoRenew: true,
	}
	t.Run("self signed", func(t *testing.T) {
		got := original
		got.UseSelfSigned()
		want := original
		want.Mode, want.CertFile, want.KeyFile = "self_signed", "", ""
		if got != want {
			t.Fatal("self-signed transition changed unrelated fields")
		}
	})
	t.Run("import", func(t *testing.T) {
		got := original
		got.Mode = "acme_cf"
		got.UseImported("/managed/cert", "/managed/key")
		want := original
		want.Mode = "imported"
		want.CertFile, want.KeyFile = "/managed/cert", "/managed/key"
		if got != want {
			t.Fatal("import transition changed unrelated fields")
		}
	})
	for _, mode := range []string{"acme_cf", "acme_http"} {
		for _, renew := range []bool{false, true} {
			got := original
			got.UseACME(mode, "issued.example.com", renew, "issued-token", "issued-email")
			want := original
			want.Mode, want.Domain = mode, "issued.example.com"
			want.CertFile, want.KeyFile, want.AutoRenew = "", "", renew
			if mode == "acme_cf" {
				want.CFToken, want.CFEmail = "", ""
				if renew {
					want.CFToken, want.CFEmail = "issued-token", "issued-email"
				}
			}
			if got != want {
				t.Fatalf("incorrect credential/path policy for mode %s, renew %v", mode, renew)
			}
		}
	}
}
