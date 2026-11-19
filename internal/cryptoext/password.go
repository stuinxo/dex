package cryptoext

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	PBKDF2Scheme       = "pbkdf2-sha256"
	LegacyV2Scheme     = "legacy-sha256d"
	DefaultPBKDF2Iters = 210000
	pbkdf2SaltLen      = 16
	pbkdf2KeyLen       = 32
)

// HashPassword hashes a plaintext password with PBKDF2-HMAC-SHA256.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, plain, salt, DefaultPBKDF2Iters, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2 derive: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		PBKDF2Scheme,
		DefaultPBKDF2Iters,
		hex.EncodeToString(salt),
		hex.EncodeToString(dk),
	), nil
}

// LegacyV2Digest computes sha256(hex(sha256(plain))) in lowercase hex, matching v2 auth.php / gwd_pw_hash.
func LegacyV2Digest(plain string) string {
	first := sha256.Sum256([]byte(plain))
	firstHex := hex.EncodeToString(first[:])
	second := sha256.Sum256([]byte(firstHex))
	return hex.EncodeToString(second[:])
}

// FormatLegacyV2Hash validates a 64-hex v2 password hash and prefixes it with legacy-sha256d$.
func FormatLegacyV2Hash(hex64 string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(hex64))
	if len(clean) != 64 {
		return "", errors.New("legacy v2 hash must be 64 hex characters")
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return "", errors.New("legacy v2 hash contains non-hex characters")
	}
	return LegacyV2Scheme + "$" + clean, nil
}

// IsValidStoredHash checks whether storedHash is a syntactically valid non-empty v3 or legacy-v2 password hash.
func IsValidStoredHash(storedHash string) bool {
	storedHash = strings.TrimSpace(storedHash)
	if strings.HasPrefix(storedHash, PBKDF2Scheme+"$") {
		parts := strings.Split(storedHash, "$")
		if len(parts) != 4 {
			return false
		}
		iters, err := strconv.Atoi(parts[1])
		if err != nil || iters < 10000 || iters > 5000000 {
			return false
		}
		salt, err1 := hex.DecodeString(parts[2])
		dk, err2 := hex.DecodeString(parts[3])
		return err1 == nil && err2 == nil && len(salt) >= 8 && len(dk) == pbkdf2KeyLen
	}
	if strings.HasPrefix(storedHash, LegacyV2Scheme+"$") {
		raw := strings.TrimPrefix(storedHash, LegacyV2Scheme+"$")
		_, err := FormatLegacyV2Hash(raw)
		return err == nil
	}
	return false
}

// VerifyPassword checks plain against storedHash in constant time.
// When ok && needsRehash is true, callers should re-hash plain via HashPassword and persist it.
func VerifyPassword(storedHash, plain string) (ok bool, needsRehash bool) {
	storedHash = strings.TrimSpace(storedHash)
	if storedHash == "" || plain == "" {
		return false, false
	}

	if strings.HasPrefix(storedHash, PBKDF2Scheme+"$") {
		parts := strings.Split(storedHash, "$")
		if len(parts) != 4 {
			return false, false
		}
		iters, err := strconv.Atoi(parts[1])
		if err != nil || iters < 10000 || iters > 5000000 {
			return false, false
		}
		salt, err := hex.DecodeString(parts[2])
		if err != nil || len(salt) < 8 {
			return false, false
		}
		expectedDK, err := hex.DecodeString(parts[3])
		if err != nil || len(expectedDK) != pbkdf2KeyLen {
			return false, false
		}
		actualDK, err := pbkdf2.Key(sha256.New, plain, salt, iters, len(expectedDK))
		if err != nil {
			return false, false
		}
		if subtle.ConstantTimeCompare(expectedDK, actualDK) == 1 {
			return true, iters < DefaultPBKDF2Iters
		}
		return false, false
	}

	if strings.HasPrefix(storedHash, LegacyV2Scheme+"$") {
		expectedHex := strings.ToLower(strings.TrimPrefix(storedHash, LegacyV2Scheme+"$"))
		if len(expectedHex) != 64 {
			return false, false
		}
		if _, err := hex.DecodeString(expectedHex); err != nil {
			return false, false
		}
		actualHex := LegacyV2Digest(plain)
		if subtle.ConstantTimeCompare([]byte(expectedHex), []byte(actualHex)) == 1 {
			return true, true
		}
		return false, false
	}

	return false, false
}
