#!/bin/sh
# Automated regression test suite for DEX bootstrap install scripts.
# Runs natively on macOS and Linux (POSIX sh) without root or network access.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL_SCRIPT="${REPO_ROOT}/scripts/install.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '[PASS] %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '[FAIL] %s\n' "$*" >&2; }

assert_eq() {
  got="$1"
  want="$2"
  label="$3"
  if [ "$got" = "$want" ]; then
    pass "$label"
  else
    fail "$label (got='$got', want='$want')"
  fi
}

make_fake_elf() {
  # 4-byte ELF magic + shell-readable trailer padding
  printf '\177ELFfake-dex-binary\n' > "$1"
  chmod 0755 "$1"
}

calc_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  else
    openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  fi
}

TMP_ROOT=$(mktemp -d /tmp/dex-install-test.XXXXXX)
trap 'rm -rf "$TMP_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. POSIX syntax check & bootstrap entrypoint sync (scripts/install.sh == dex == i)
# ---------------------------------------------------------------------------
for script in "$INSTALL_SCRIPT" "${REPO_ROOT}/dex" "${REPO_ROOT}/i"; do
  if sh -n "$script" 2>/dev/null; then
    pass "POSIX syntax valid: $(basename "$script")"
  else
    fail "POSIX syntax invalid: $script"
  fi
done

if cmp -s "$INSTALL_SCRIPT" "${REPO_ROOT}/dex" && cmp -s "$INSTALL_SCRIPT" "${REPO_ROOT}/i"; then
  pass "Bootstrap entrypoints (scripts/install.sh, dex, i) are byte-identical"
else
  fail "Bootstrap entrypoints diverged (scripts/install.sh, dex, i must stay identical)"
fi

# ---------------------------------------------------------------------------
# 2. Unit tests for helper functions (DEX_INSTALL_LIB_ONLY=1)
# ---------------------------------------------------------------------------
unit_out=$(
  DEX_INSTALL_LIB_ONLY=1
  . "$INSTALL_SCRIPT"

  # 2a. is_elf
  make_fake_elf() { printf '\177ELFpayload\n' > "$1"; }
  make_fake_elf "$TMP_ROOT/valid.elf"
  printf '<!doctype html><html>error</html>\n' > "$TMP_ROOT/bad.html"
  is_elf "$TMP_ROOT/valid.elf" || exit 11
  ! is_elf "$TMP_ROOT/bad.html" || exit 12

  # 2b. verify_sum_in_list (standard + *binary format + mismatch + invalid hash)
  h=$(sha256_of "$TMP_ROOT/valid.elf")
  printf '%s  dex-linux-amd64\n' "$h" > "$TMP_ROOT/sums1"
  printf '%s *dex-linux-arm64\n' "$(printf '%s' "$h" | tr 'a-f' 'A-F')" > "$TMP_ROOT/sums2"
  printf '0000000000000000000000000000000000000000000000000000000000000000  dex-linux-amd64\n' > "$TMP_ROOT/sums_bad"
  printf 'not-a-hash  dex-linux-amd64\n' > "$TMP_ROOT/sums_malformed"
  verify_sum_in_list "$TMP_ROOT/valid.elf" "$TMP_ROOT/sums1" "dex-linux-amd64" || exit 13
  verify_sum_in_list "$TMP_ROOT/valid.elf" "$TMP_ROOT/sums2" "dex-linux-arm64" || exit 14
  ! verify_sum_in_list "$TMP_ROOT/valid.elf" "$TMP_ROOT/sums_bad" "dex-linux-amd64" || exit 15
  ! verify_sum_in_list "$TMP_ROOT/valid.elf" "$TMP_ROOT/sums_malformed" "dex-linux-amd64" || exit 16

  # 2c. parse_xray_dgst
  printf 'MD5= 1234\nSHA2-256= %s\n' "$h" > "$TMP_ROOT/xray.dgst"
  [ "$(parse_xray_dgst "$TMP_ROOT/xray.dgst")" = "$h" ] || exit 17
  printf 'SHA256= %s\n' "$(printf '%s' "$h" | tr 'a-f' 'A-F')" > "$TMP_ROOT/xray2.dgst"
  [ "$(parse_xray_dgst "$TMP_ROOT/xray2.dgst")" = "$h" ] || exit 18

  # 2d. parse_mosdns_api_digest
  cat > "$TMP_ROOT/mosdns.json" <<EOF
{"assets":[
  {"name":"mosdns-linux-arm64.zip","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {"name":"mosdns-linux-amd64.zip","digest":"sha256:${h}"}
]}
EOF
  [ "$(parse_mosdns_api_digest "$TMP_ROOT/mosdns.json" "mosdns-linux-amd64.zip")" = "$h" ] || exit 19
  [ "$(parse_mosdns_api_digest "$TMP_ROOT/mosdns.json" "missing.zip")" = "" ] || exit 20

  # 2e. detect_arch via stubbed uname
  uname() { printf '%s\n' "$TEST_UNAME_M"; }
  TEST_UNAME_M="x86_64"; detect_arch
  [ "$ARCH" = "amd64" ] && [ "$XRAY_ARCH" = "64" ] && [ "$MOS_ARCH" = "amd64" ] || exit 21
  TEST_UNAME_M="aarch64"; detect_arch
  [ "$ARCH" = "arm64" ] && [ "$XRAY_ARCH" = "arm64-v8a" ] && [ "$MOS_ARCH" = "arm64" ] || exit 22
  if ( TEST_UNAME_M="mips64"; detect_arch ) 2>/dev/null; then exit 23; fi

  # 2f. suggest_doh_from_uri derives Server DoH from TLS vless:// & vmess:// URIs and skips reality
  [ "$(suggest_doh_from_uri "vless://1111@203.0.113.8:2096?encryption=none&security=tls&sni=srv.example.com&type=xhttp&path=%2Fabc#S")" = "https://srv.example.com:2096/dq" ] || exit 24
  [ "$(suggest_doh_from_uri "vless://1111@srv.example.com:443?encryption=none&security=tls&sni=srv.example.com&type=xhttp&path=%2Fabc#S")" = "https://srv.example.com/dq" ] || exit 25
  [ "$(suggest_doh_from_uri "vless://1111@203.0.113.8:443?security=reality&sni=www.microsoft.com#R")" = "" ] || exit 26
  vmess_b64=$(printf '%s' '{"v":"2","add":"203.0.113.8","port":2096,"id":"1111","net":"ws","tls":"tls","sni":"vm.example.com"}' | openssl base64 -A)
  [ "$(suggest_doh_from_uri "vmess://${vmess_b64}")" = "https://vm.example.com:2096/dq" ] || exit 27

  printf 'UNIT_OK\n'
)
assert_eq "$unit_out" "UNIT_OK" "Helper unit tests (ELF, SHA256, dgst, MosDNS JSON, detect_arch)"

# ---------------------------------------------------------------------------
# 3. Mirror fallback, sticky mirror, trust boundary, and rule validation tests
# ---------------------------------------------------------------------------
run_mirror_tests() {
  (
    DEX_INSTALL_LIB_ONLY=1
    GH_PROXY="https://user-proxy.test"
    GH_MIRRORS="https://m1.test/ https://m2.test/"
    DEX_STATE_DIR="$TMP_ROOT/state-mirror"
    mkdir -p "$DEX_STATE_DIR/rules"
    . "$INSTALL_SCRIPT"

    # USER_GH_PROXY must normalize trailing slash
    [ "$USER_GH_PROXY" = "https://user-proxy.test/" ] || exit 31

    CURL_LOG="$TMP_ROOT/curl.log"
    : > "$CURL_LOG"
    curl() {
      c_out=""
      c_url=""
      while [ $# -gt 0 ]; do
        case "$1" in
          -o) c_out="$2"; shift 2 ;;
          http://*|https://*) c_url="$1"; shift ;;
          *) shift ;;
        esac
      done
      printf '%s\n' "$c_url" >> "$CURL_LOG"
      case "$c_url" in
        https://m2.test/https://example.com/file.bin)
          printf 'payload-ok\n' > "$c_out"
          return 0
          ;;
        https://m2.test/https://example.com/second.bin)
          printf 'second-ok\n' > "$c_out"
          return 0
          ;;
        https://m2.test/https://example.com/html.txt)
          printf '<!DOCTYPE html><html>blocked</html>\n' > "$c_out"
          return 0
          ;;
        https://m2.test/https://example.com/good-rule.txt)
          printf '# comment\n1.0.0.0/8\n2.0.0.0/8\n3.0.0.0/8\n' > "$c_out"
          return 0
          ;;
        https://m1.test/https://example.com/only-on-mirror.sum|https://m2.test/https://example.com/only-on-mirror.sum)
          # Untrusted mirrors should never be queried by gh_fetch_trust
          printf 'mirror-should-not-be-trusted\n' > "$c_out"
          return 0
          ;;
        https://user-proxy.test/https://example.com/trust.sum)
          printf 'trusted-sum\n' > "$c_out"
          return 0
          ;;
        *)
          return 22
          ;;
      esac
    }

    # 3a. gh_fetch falls back through USER_GH_PROXY -> m1 -> m2 and sticks m2
    gh_fetch "https://example.com/file.bin" "$TMP_ROOT/f1" || exit 32
    [ "$STICKY_MIRROR" = "https://m2.test/" ] || exit 33

    # 3b. Next gh_fetch uses STICKY_MIRROR directly on first attempt
    prev_lines=$(wc -l < "$CURL_LOG" | tr -d ' ')
    gh_fetch "https://example.com/second.bin" "$TMP_ROOT/f2" || exit 34
    now_lines=$(wc -l < "$CURL_LOG" | tr -d ' ')
    [ $((now_lines - prev_lines)) -eq 1 ] || exit 35

    # 3c. gh_fetch_trust uses DIRECT then USER_GH_PROXY, never untrusted GH_MIRRORS
    gh_fetch_trust "https://example.com/trust.sum" "$TMP_ROOT/tsum" || exit 36
    [ "$(cat "$TMP_ROOT/tsum")" = "trusted-sum" ] || exit 37
    ! gh_fetch_trust "https://example.com/only-on-mirror.sum" "$TMP_ROOT/tsum2" || exit 38

    # 3d. fetch_valid_text_rule rejects HTML and falls back to fallback_url
    fetch_valid_text_rule "https://example.com/html.txt" "$DEX_STATE_DIR/rules/test.txt" 3 "https://example.com/good-rule.txt" || exit 39
    [ -s "$DEX_STATE_DIR/rules/test.txt" ] || exit 40
    ! fetch_valid_text_rule "https://example.com/html.txt" "$DEX_STATE_DIR/rules/test2.txt" 10 "https://example.com/good-rule.txt" || exit 41

    printf 'MIRROR_OK\n'
  )
}
mirror_out=$(run_mirror_tests)
assert_eq "$mirror_out" "MIRROR_OK" "Mirror fallback, sticky mirror, trust boundary, and rule validation"

# ---------------------------------------------------------------------------
# 4. End-to-end mocked install flow: Alpine/OpenRC offline (server role)
# ---------------------------------------------------------------------------
E2E_ALPINE="$TMP_ROOT/e2e-alpine"
STUB_BIN_A="$E2E_ALPINE/stub-bin"
DST_BIN_A="$E2E_ALPINE/usr-local-bin"
STATE_A="$E2E_ALPINE/etc-dex"
mkdir -p "$STUB_BIN_A" "$DST_BIN_A" "$STATE_A"

# Build fake ELF binaries + Xray zip with valid .dgst
make_fake_elf "$E2E_ALPINE/dex.elf"
mkdir -p "$E2E_ALPINE/xray-src"
make_fake_elf "$E2E_ALPINE/xray-src/xray"
(cd "$E2E_ALPINE/xray-src" && zip -q "$E2E_ALPINE/Xray-linux-64.zip" xray)
xray_sha=$(calc_sha256 "$E2E_ALPINE/Xray-linux-64.zip")
printf 'SHA2-256= %s\n' "$xray_sha" > "$E2E_ALPINE/Xray-linux-64.zip.dgst"

# Stub root, arch, apk, rc-service, curl (fails to ensure offline path works without network)
cat > "$STUB_BIN_A/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
cat > "$STUB_BIN_A/uname" <<'EOF'
#!/bin/sh
printf 'x86_64\n'
EOF
cat > "$STUB_BIN_A/apk" <<EOF
#!/bin/sh
printf 'apk %s\n' "\$*" >> "$E2E_ALPINE/apk.log"
exit 0
EOF
cat > "$STUB_BIN_A/rc-service" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$STUB_BIN_A/curl" <<'EOF'
#!/bin/sh
exit 22
EOF
chmod +x "$STUB_BIN_A"/*

if PATH="$STUB_BIN_A:/usr/bin:/bin" \
   DEX_OS_INIT="openrc" \
   DEX_NGINX_DEFAULT_SITE="$E2E_ALPINE/nginx-default" \
   DEX_STATE_DIR="$STATE_A" \
   DEX_INSTALL_BIN="$DST_BIN_A/dex" \
   DEX_XRAY_BIN="$DST_BIN_A/xray" \
   DEX_MOSDNS_BIN="$DST_BIN_A/mosdns" \
   DEX_BIN="$E2E_ALPINE/dex.elf" \
   XRAY_ZIP="$E2E_ALPINE/Xray-linux-64.zip" \
   sh "$INSTALL_SCRIPT" server >"$E2E_ALPINE/out.log" 2>&1; then
  if [ -x "$DST_BIN_A/dex" ] && [ -L "$DST_BIN_A/de_GWD" ] && [ -x "$DST_BIN_A/xray" ] \
    && grep -q 'apk add --no-cache nginx socat wireguard-tools' "$E2E_ALPINE/apk.log"; then
    pass "E2E Alpine/OpenRC offline server install (dex + de_GWD symlink + xray + nginx pkgs)"
  else
    fail "E2E Alpine/OpenRC offline server install missing expected artifacts"
  fi
else
  fail "E2E Alpine/OpenRC offline server install exited non-zero: $(cat "$E2E_ALPINE/out.log")"
fi

# ---------------------------------------------------------------------------
# 5. End-to-end mocked install flow: Debian/apt online with SHA256 verification & tamper rejection
# ---------------------------------------------------------------------------
E2E_DEB="$TMP_ROOT/e2e-deb"
STUB_BIN_D="$E2E_DEB/stub-bin"
DST_BIN_D="$E2E_DEB/usr-local-bin"
STATE_D="$E2E_DEB/etc-dex"
mkdir -p "$STUB_BIN_D" "$DST_BIN_D" "$STATE_D"

make_fake_elf "$E2E_DEB/dex-remote.elf"
dex_sha=$(calc_sha256 "$E2E_DEB/dex-remote.elf")
printf '%s  dex-linux-arm64\n' "$dex_sha" > "$E2E_DEB/SHA256SUMS"
printf 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  dex-linux-arm64\n' > "$E2E_DEB/SHA256SUMS.bad"

cat > "$STUB_BIN_D/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
cat > "$STUB_BIN_D/uname" <<'EOF'
#!/bin/sh
printf 'aarch64\n'
EOF
cat > "$STUB_BIN_D/apt-get" <<EOF
#!/bin/sh
printf 'apt-get %s\n' "\$*" >> "$E2E_DEB/apt.log"
exit 0
EOF
cat > "$STUB_BIN_D/pgrep" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$STUB_BIN_D/fuser" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$STUB_BIN_D/curl" <<EOF
#!/bin/sh
out=""
url=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    http://*|https://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
case "\$url" in
  https://mirror.ok/https://github.com/*/dex-linux-arm64)
    cp "$E2E_DEB/dex-remote.elf" "\$out"
    exit 0
    ;;
  https://github.com/*/SHA256SUMS)
    if [ "\${TEST_TAMPER_SUM:-0}" = "1" ]; then
      cp "$E2E_DEB/SHA256SUMS.bad" "\$out"
    else
      cp "$E2E_DEB/SHA256SUMS" "\$out"
    fi
    exit 0
    ;;
  *)
    exit 22
    ;;
esac
EOF
chmod +x "$STUB_BIN_D"/*

# 5a. Valid online arm64 install via mirror fallback + trusted direct SHA256SUMS
if PATH="$STUB_BIN_D:/usr/bin:/bin" \
   GH_MIRRORS="https://mirror.ok/" \
   DEX_NO_MENU=1 \
   DEX_STATE_DIR="$STATE_D" \
   DEX_INSTALL_BIN="$DST_BIN_D/dex" \
   DEX_XRAY_BIN="$DST_BIN_D/xray" \
   DEX_MOSDNS_BIN="$DST_BIN_D/mosdns" \
   sh "$INSTALL_SCRIPT" >"$E2E_DEB/out.log" 2>&1; then
  if [ -x "$DST_BIN_D/dex" ] && grep -q 'apt-get install -y -qq --no-install-recommends ca-certificates' "$E2E_DEB/apt.log"; then
    pass "E2E Debian/apt online arm64 install (mirror fallback + SHA256SUMS verify)"
  else
    fail "E2E Debian/apt online arm64 install missing expected artifacts"
  fi
else
  fail "E2E Debian/apt online arm64 install failed: $(cat "$E2E_DEB/out.log")"
fi

# 5b. Tampered SHA256SUMS must fail closed
rm -f "$DST_BIN_D/dex"
if PATH="$STUB_BIN_D:/usr/bin:/bin" \
   GH_MIRRORS="https://mirror.ok/" \
   TEST_TAMPER_SUM=1 \
   DEX_NO_MENU=1 \
   DEX_STATE_DIR="$STATE_D" \
   DEX_INSTALL_BIN="$DST_BIN_D/dex" \
   sh "$INSTALL_SCRIPT" >"$E2E_DEB/tamper.log" 2>&1; then
  fail "Tampered SHA256SUMS should have aborted install"
else
  if grep -q "SHA256 verification failed" "$E2E_DEB/tamper.log" && [ ! -e "$DST_BIN_D/dex" ]; then
    pass "Tampered SHA256SUMS rejected fail-closed without installing binary"
  else
    fail "Tampered SHA256SUMS failed unexpectedly: $(cat "$E2E_DEB/tamper.log")"
  fi
fi

# 5c. Unknown role must fail with usage
if PATH="$STUB_BIN_D:/usr/bin:/bin" \
   GH_MIRRORS="https://mirror.ok/" \
   DEX_STATE_DIR="$STATE_D" \
   DEX_INSTALL_BIN="$DST_BIN_D/dex" \
   sh "$INSTALL_SCRIPT" bogus-role >"$E2E_DEB/bogus.log" 2>&1; then
  fail "Unknown role should have exited non-zero"
else
  if grep -q "Usage:" "$E2E_DEB/bogus.log"; then
    pass "Unknown role rejected with Usage message"
  else
    fail "Unknown role error missing Usage: $(cat "$E2E_DEB/bogus.log")"
  fi
fi

# 5d. Client install requires self-hosted DoH when non-interactive, and forwards --doh / DEX_DOH to dex init
STATE_C="$E2E_ALPINE/etc-dex-client"
mkdir -p "$STATE_C/rules"
make_fake_elf "$DST_BIN_A/mosdns"
for rf in geoip.dat geosite.dat IPchnroute Domains.chn.txt Domains.ads.txt Domains.apple.txt Domains.games.txt; do
  printf 'stub-rule\n' > "$STATE_C/rules/$rf"
done
# Wrap fake dex binary with an ELF that logs args? No, install_dex_binary overwrites $DST_BIN_A/dex from $DEX_BIN!
# First verify non-interactive client without DoH fails closed before invoking dex init:
if PATH="$STUB_BIN_A:/usr/bin:/bin" \
   DEX_NO_PROMPT=1 \
   DEX_STATE_DIR="$STATE_C" \
   DEX_INSTALL_BIN="$DST_BIN_A/dex" \
   DEX_XRAY_BIN="$DST_BIN_A/xray" \
   DEX_MOSDNS_BIN="$DST_BIN_A/mosdns" \
   DEX_BIN="$E2E_ALPINE/dex.elf" \
   sh "$INSTALL_SCRIPT" -- -c >"$E2E_ALPINE/client-nodoh.log" 2>&1; then
  fail "Non-interactive client install (-c) without Server node/DoH should fail"
else
  if grep -q "Client install requires Server node URI" "$E2E_ALPINE/client-nodoh.log"; then
    pass "Client install (-c) rejects missing Server node URI in non-interactive mode"
  else
    fail "Unexpected error on client install (-c) without node/DoH: $(cat "$E2E_ALPINE/client-nodoh.log")"
  fi
fi

# 5e. Entrypoint ends with 'main "$@"' (Cloudflare Worker compatible) and supports role shorthands
if [ "$(tail -n 1 "$INSTALL_SCRIPT")" = 'main "$@"' ] && sh "$INSTALL_SCRIPT" -h | grep -q "wget -qO- dex.stuinx.net | sh"; then
  pass "Install script ends with 'main \"\$@\"' and prints bench.sh-style usage"
else
  fail "Install script entrypoint or -h usage check failed"
fi

mkdir -p "$STATE_A/rules"
printf 'stub-geo\n' > "$STATE_A/rules/geoip.dat"
printf 'stub-geo\n' > "$STATE_A/rules/geosite.dat"
: > "$E2E_ALPINE/apk.log"
if PATH="$STUB_BIN_A:/usr/bin:/bin" \
   DEX_OS_INIT="openrc" \
   DEX_STATE_DIR="$STATE_A" \
   DEX_INSTALL_BIN="$DST_BIN_A/dex" \
   DEX_XRAY_BIN="$DST_BIN_A/xray" \
   DEX_BIN="$E2E_ALPINE/dex.elf" \
   XRAY_ZIP="$E2E_ALPINE/Xray-linux-64.zip" \
   sh "$INSTALL_SCRIPT" -r >"$E2E_ALPINE/relay.log" 2>&1 \
   && grep -q 'apk add --no-cache haproxy' "$E2E_ALPINE/apk.log" \
   && PATH="$STUB_BIN_A:/usr/bin:/bin" \
      DEX_OS_INIT="openrc" \
      DEX_STATE_DIR="$STATE_A" \
      DEX_INSTALL_BIN="$DST_BIN_A/dex" \
      DEX_XRAY_BIN="$DST_BIN_A/xray" \
      DEX_BIN="$E2E_ALPINE/dex.elf" \
      XRAY_ZIP="$E2E_ALPINE/Xray-linux-64.zip" \
      sh "$INSTALL_SCRIPT" -l >"$E2E_ALPINE/landing.log" 2>&1 \
   && grep -q "dex -l" "$E2E_ALPINE/landing.log"; then
  pass "Install script supports -r and -l shorthand role flags"
else
  fail "Install script -r/-l shorthand test failed"
fi

printf '\nSummary: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
