package cryptoext

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// GenerateUUID returns a cryptographically random RFC 4122 version 4 UUID.
func GenerateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// UUIDToDefaultPath extracts the first segment of a UUID prefixed with "/"
// (matching v2 xray-common uuid_to_path behavior).
func UUIDToDefaultPath(uuid string) string {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return "/dex"
	}
	first := uuid
	if idx := strings.IndexByte(uuid, '-'); idx > 0 {
		first = uuid[:idx]
	}
	return "/" + first
}

// GenerateInitialPassword generates a 16-character alphanumeric random password
// using rejection sampling for uniform distribution.
func GenerateInitialPassword() (string, error) {
	const length = 16
	const alphabetLen = len(passwordAlphabet)
	const maxByte = 256 - (256 % alphabetLen)

	out := make([]byte, 0, length)
	buf := make([]byte, 64)
	for len(out) < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, v := range buf {
			if int(v) >= maxByte {
				continue
			}
			out = append(out, passwordAlphabet[int(v)%alphabetLen])
			if len(out) == length {
				break
			}
		}
	}
	return string(out), nil
}

// GenerateHexToken returns a lowercase hex string from byteLen random bytes.
func GenerateHexToken(byteLen int) (string, error) {
	if byteLen <= 0 {
		return "", errors.New("byteLen must be positive")
	}
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func generateClampedX25519Raw() ([]byte, []byte, error) {
	var scalar [32]byte
	if _, err := rand.Read(scalar[:]); err != nil {
		return nil, nil, fmt.Errorf("read random bytes: %w", err)
	}
	// RFC 7748 scalar clamping so both `wg pubkey` and `xray x25519` derive the exact same public key.
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	priv, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return nil, nil, fmt.Errorf("new x25519 private key: %w", err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// GenerateWireGuardKeypair generates a Curve25519 keypair encoded in standard padded Base64 (44 chars).
func GenerateWireGuardKeypair() (privStdB64, pubStdB64 string, err error) {
	priv, pub, err := generateClampedX25519Raw()
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// DeriveWireGuardPublicKey derives the standard Base64 public key from a standard Base64 private key.
func DeriveWireGuardPublicKey(privStdB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privStdB64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard private key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid X25519 key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// GenerateRealityKeypair generates an X25519 keypair encoded in unpadded URL-safe Base64 (43 chars)
// matching `xray x25519`.
func GenerateRealityKeypair() (privRawURL, pubRawURL string, err error) {
	priv, pub, err := generateClampedX25519Raw()
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv), base64.RawURLEncoding.EncodeToString(pub), nil
}

// DeriveRealityPublicKey derives the URL-safe unpadded Base64 public key from a Reality private key.
func DeriveRealityPublicKey(privRawURL string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privRawURL))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid Reality private key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid X25519 key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
