package cryptoext

import (
	"regexp"
	"testing"
)

func TestUUIDAndPath(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	u1, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}
	u2, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}
	if !re.MatchString(u1) || !re.MatchString(u2) || u1 == u2 {
		t.Fatalf("unexpected UUIDs: %q, %q", u1, u2)
	}
	if got := UUIDToDefaultPath("12345678-aaaa-4bbb-8ccc-1234567890ab"); got != "/12345678" {
		t.Fatalf("UUIDToDefaultPath = %q, want /12345678", got)
	}
}

func TestInitialPasswordAndTokens(t *testing.T) {
	pw1, err := GenerateInitialPassword()
	if err != nil {
		t.Fatalf("GenerateInitialPassword: %v", err)
	}
	pw2, err := GenerateInitialPassword()
	if err != nil {
		t.Fatalf("GenerateInitialPassword: %v", err)
	}
	if len(pw1) != 16 || len(pw2) != 16 || pw1 == pw2 {
		t.Fatalf("unexpected passwords: %q, %q", pw1, pw2)
	}
	tok, err := GenerateHexToken(16)
	if err != nil || len(tok) != 32 {
		t.Fatalf("GenerateHexToken(16) = %q, err=%v", tok, err)
	}
}

func TestWireGuardAndRealityKeypairs(t *testing.T) {
	wgPriv, wgPub, err := GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair: %v", err)
	}
	if len(wgPriv) != 44 || len(wgPub) != 44 {
		t.Fatalf("unexpected WG key lengths: %d, %d", len(wgPriv), len(wgPub))
	}
	derivedWG, err := DeriveWireGuardPublicKey(wgPriv)
	if err != nil || derivedWG != wgPub {
		t.Fatalf("DeriveWireGuardPublicKey = %q (err=%v), want %q", derivedWG, err, wgPub)
	}

	rPriv, rPub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	if len(rPriv) != 43 || len(rPub) != 43 {
		t.Fatalf("unexpected Reality key lengths: %d, %d", len(rPriv), len(rPub))
	}
	derivedR, err := DeriveRealityPublicKey(rPriv)
	if err != nil || derivedR != rPub {
		t.Fatalf("DeriveRealityPublicKey = %q (err=%v), want %q", derivedR, err, rPub)
	}
}

func TestPasswordHashAndLegacyUpgrade(t *testing.T) {
	h, err := HashPassword("S3cur3-Pass!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !IsValidStoredHash(h) {
		t.Fatalf("expected valid hash: %q", h)
	}
	ok, rehash := VerifyPassword(h, "S3cur3-Pass!")
	if !ok || rehash {
		t.Fatalf("VerifyPassword valid = (%v, %v), want (true, false)", ok, rehash)
	}
	if ok, _ := VerifyPassword(h, "wrong"); ok {
		t.Fatalf("VerifyPassword accepted wrong password")
	}

	legacyRaw := LegacyV2Digest("myOldV2Pass")
	legacyFormatted, err := FormatLegacyV2Hash(legacyRaw)
	if err != nil {
		t.Fatalf("FormatLegacyV2Hash: %v", err)
	}
	ok, rehash = VerifyPassword(legacyFormatted, "myOldV2Pass")
	if !ok || !rehash {
		t.Fatalf("VerifyPassword legacy = (%v, %v), want (true, true)", ok, rehash)
	}
	if ok, _ := VerifyPassword(legacyFormatted, "other"); ok {
		t.Fatalf("VerifyPassword legacy accepted wrong password")
	}
	if ok, _ := VerifyPassword("", "any"); ok {
		t.Fatalf("VerifyPassword empty hash must fail closed")
	}
}
