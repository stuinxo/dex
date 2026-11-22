#!/bin/sh
# DEX v3 Bootstrap Installer (POSIX sh)
# Supports Debian 12/13, Ubuntu (apt + systemd), and Alpine 3.x (apk + OpenRC) on amd64/arm64.
set -eu

DEX_REPO="${DEX_REPO:-stuinxo/de_GWD}"
DEX_VERSION="${DEX_VERSION:-latest}"
DEX_BIN="${DEX_BIN:-}"
XRAY_ZIP="${XRAY_ZIP:-}"
MOSDNS_ZIP="${MOSDNS_ZIP:-}"
GH_PROXY="${GH_PROXY:-}"
GH_MIRRORS="${GH_MIRRORS:-https://gh-proxy.com/ https://ghproxy.net/ https://ghfast.top/}"
STATE_DIR="${DEX_STATE_DIR:-/etc/dex}"
INSTALL_BIN="/usr/local/bin/dex"
XRAY_BIN="/usr/local/bin/xray"
MOSDNS_BIN="/usr/local/bin/mosdns"

say()  { printf '%s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" -eq 0 ] || die "Root privileges required."
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64"; XRAY_ARCH="64"; MOS_ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64"; XRAY_ARCH="arm64-v8a"; MOS_ARCH="arm64" ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
}

detect_os() {
  if command -v apk >/dev/null 2>&1; then
    OS_PKG="apk"
  elif command -v apt-get >/dev/null 2>&1; then
    OS_PKG="apt"
  else
    die "Unsupported OS: requires apt (Debian/Ubuntu) or apk (Alpine)."
  fi

  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    OS_INIT="systemd"
  elif command -v rc-service >/dev/null 2>&1; then
    OS_INIT="openrc"
  else
    OS_INIT="unknown"
  fi
}

wait_apt_lock() {
  waited=0
  while (command -v fuser >/dev/null 2>&1 && fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1) \
    || pgrep -x 'apt|apt-get|dpkg' >/dev/null 2>&1; do
    [ "$waited" -ge 120 ] && die "Timed out waiting for apt/dpkg lock."
    sleep 2
    waited=$((waited + 2))
  done
}

install_base_pkgs() {
  say "[*] Checking base dependencies ($OS_PKG / $OS_INIT)..."
  case "$OS_PKG" in
    apk)
      apk update >/dev/null 2>&1 || true
      apk add --no-cache ca-certificates curl openssl unzip iproute2 nftables >/dev/null 2>&1 \
        || die "Failed to install base Alpine packages."
      apk add --no-cache libqrencode-tools >/dev/null 2>&1 || true
      ;;
    apt)
      export DEBIAN_FRONTEND=noninteractive
      wait_apt_lock
      apt-get update -qq >/dev/null 2>&1 || true
      wait_apt_lock
      apt-get install -y -qq --no-install-recommends ca-certificates curl openssl unzip iproute2 nftables procps psmisc >/dev/null 2>&1 \
        || die "Failed to install base Debian/Ubuntu packages."
      apt-get install -y -qq --no-install-recommends qrencode >/dev/null 2>&1 || true
      ;;
  esac
}

is_elf() {
  [ -f "$1" ] || return 1
  magic=$(dd if="$1" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  [ "$magic" = "7f454c46" ]
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  else
    openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  fi
}

gh_fetch() {
  url="$1"
  out="$2"
  for prefix in ${GH_PROXY:-DIRECT} $GH_MIRRORS; do
    [ "$prefix" = "DIRECT" ] && prefix=""
    if curl -fsSL --connect-timeout 8 --speed-limit 10240 --speed-time 15 --max-time 600 -o "$out" "${prefix}${url}" 2>/dev/null && [ -s "$out" ]; then
      GH_PROXY="$prefix"
      return 0
    fi
  done
  rm -f "$out"
  return 1
}

verify_sum_in_list() {
  file="$1"
  sumlist="$2"
  name="$3"
  expected=$(awk -v f="$name" '$2 == f || $2 == ("*" f) {print tolower($1); exit}' "$sumlist")
  [ -n "$expected" ] || return 1
  printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || return 1
  actual=$(sha256_of "$file")
  [ "$actual" = "$expected" ]
}

install_dex_binary() {
  local_cand=""
  if [ -n "$DEX_BIN" ] && [ -f "$DEX_BIN" ]; then
    local_cand="$DEX_BIN"
  else
    for p in "./dex-linux-${ARCH}" "./dex" "/root/dex-linux-${ARCH}" "/root/dex" "/tmp/dex-linux-${ARCH}" "/tmp/dex"; do
      if [ -f "$p" ]; then
        local_cand="$p"
        break
      fi
    done
  fi

  tmp_bin=$(mktemp /tmp/dex-bin.XXXXXX)
  trap 'rm -f "$tmp_bin"' EXIT

  if [ -n "$local_cand" ]; then
    say "[*] Using local dex binary: $local_cand"
    cp -f "$local_cand" "$tmp_bin"
  else
    if [ "$DEX_VERSION" = "latest" ]; then
      base_url="https://github.com/${DEX_REPO}/releases/latest/download"
    else
      base_url="https://github.com/${DEX_REPO}/releases/download/${DEX_VERSION}"
    fi
    asset="dex-linux-${ARCH}"
    sum_tmp=$(mktemp /tmp/dex-sum.XXXXXX)
    say "[*] Downloading ${asset} from ${DEX_REPO} (${DEX_VERSION})..."
    gh_fetch "${base_url}/${asset}" "$tmp_bin" || { rm -f "$sum_tmp"; die "Failed to download ${asset}"; }
    gh_fetch "${base_url}/SHA256SUMS" "$sum_tmp" || { rm -f "$sum_tmp"; die "Failed to download SHA256SUMS"; }
    verify_sum_in_list "$tmp_bin" "$sum_tmp" "$asset" || { rm -f "$sum_tmp"; die "SHA256 verification failed for ${asset}"; }
    rm -f "$sum_tmp"
  fi

  is_elf "$tmp_bin" || die "Downloaded dex binary is not a valid Linux ELF executable."
  chmod 0755 "$tmp_bin"
  mv -f "$tmp_bin" "$INSTALL_BIN"
  ln -sf "$INSTALL_BIN" /usr/local/bin/de_GWD
  trap - EXIT
  say "[+] Installed dex to $INSTALL_BIN"
}

parse_xray_dgst() {
  awk '/^(SHA2-256|SHA256)=/ {sub(/^(SHA2-256|SHA256)=[[:space:]]*/, ""); print tolower($1); exit}' "$1"
}

fetch_api_json() {
  url="$1"
  out="$2"
  for prefix in DIRECT ${GH_PROXY:-} $GH_MIRRORS; do
    [ "$prefix" = "DIRECT" ] && prefix=""
    if curl -fsSL --connect-timeout 8 --max-time 30 -H "Accept: application/vnd.github+json" -o "$out" "${prefix}${url}" 2>/dev/null \
      && [ -s "$out" ] \
      && grep -q '"assets"' "$out"; then
      return 0
    fi
    rm -f "$out"
  done
  return 1
}

parse_mosdns_api_digest() {
  api_json="$1"
  asset_name="$2"
  tr -d '\r\n' < "$api_json" | awk -v asset="$asset_name" '
    {
      gsub(/"name"[[:space:]]*:/, "\n\"name\":")
      n = split($0, parts, "\n")
      for (i = 1; i <= n; i++) {
        if (index(parts[i], "\"" asset "\"") > 0 && match(parts[i], /"digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-fA-F]+"/)) {
          s = substr(parts[i], RSTART, RLENGTH)
          sub(/^.*"sha256:/, "", s)
          sub(/".*$/, "", s)
          print tolower(s)
          exit
        }
      }
    }
  '
}

fetch_verified_rule_dat() {
  name="$1"
  url="$2"
  dst="$3"
  [ -s "$dst" ] && return 0
  tmp_dat=$(mktemp "${STATE_DIR}/rules/.${name}.XXXXXX")
  tmp_sum=$(mktemp "${STATE_DIR}/rules/.${name}.sum.XXXXXX")
  if gh_fetch "$url" "$tmp_dat" \
    && gh_fetch "${url}.sha256sum" "$tmp_sum" \
    && verify_sum_in_list "$tmp_dat" "$tmp_sum" "$name"; then
    chmod 0644 "$tmp_dat"
    mv -f "$tmp_dat" "$dst"
    rm -f "$tmp_sum"
    return 0
  fi
  rm -f "$tmp_dat" "$tmp_sum" "$dst"
  warn "Failed to fetch or verify SHA256 for ${name}"
  return 0
}

install_xray_core() {
  [ -x "$XRAY_BIN" ] && return 0
  zip_name="Xray-linux-${XRAY_ARCH}.zip"
  local_zip=""
  if [ -n "$XRAY_ZIP" ] && [ -f "$XRAY_ZIP" ]; then
    local_zip="$XRAY_ZIP"
  else
    for p in "./${zip_name}" "/root/${zip_name}" "/tmp/${zip_name}"; do
      if [ -f "$p" ]; then
        local_zip="$p"
        break
      fi
    done
  fi

  work_dir=$(mktemp -d /tmp/dex-xray.XXXXXX)
  trap 'rm -rf "$work_dir"' EXIT

  if [ -n "$local_zip" ]; then
    say "[*] Installing Xray from local archive: $local_zip"
    cp -f "$local_zip" "$work_dir/${zip_name}"
    if [ -f "${local_zip}.dgst" ]; then
      expected=$(parse_xray_dgst "${local_zip}.dgst")
      [ -n "$expected" ] && [ "$(sha256_of "$work_dir/${zip_name}")" = "$expected" ] || { rm -rf "$work_dir"; die "Xray offline SHA256 mismatch"; }
    fi
  else
    url="https://github.com/XTLS/Xray-core/releases/latest/download/${zip_name}"
    say "[*] Downloading Xray-core (${XRAY_ARCH})..."
    gh_fetch "$url" "$work_dir/${zip_name}" || { rm -rf "$work_dir"; die "Failed to download Xray"; }
    gh_fetch "${url}.dgst" "$work_dir/${zip_name}.dgst" || { rm -rf "$work_dir"; die "Failed to download Xray .dgst"; }
    expected=$(parse_xray_dgst "$work_dir/${zip_name}.dgst")
    [ -n "$expected" ] && [ "$(sha256_of "$work_dir/${zip_name}")" = "$expected" ] || { rm -rf "$work_dir"; die "Xray SHA256 verification failed"; }
  fi

  unzip -oqj "$work_dir/${zip_name}" xray -d "$work_dir" || die "Failed to extract xray binary"
  is_elf "$work_dir/xray" || die "Extracted xray is not an ELF binary"
  chmod 0755 "$work_dir/xray"
  mv -f "$work_dir/xray" "$XRAY_BIN"
  rm -rf "$work_dir"
  trap - EXIT
  say "[+] Installed Xray core to $XRAY_BIN"
}

install_mosdns_and_rules() {
  mkdir -p "${STATE_DIR}/rules"
  if [ ! -x "$MOSDNS_BIN" ]; then
    zip_name="mosdns-linux-${MOS_ARCH}.zip"
    local_zip=""
    if [ -n "$MOSDNS_ZIP" ] && [ -f "$MOSDNS_ZIP" ]; then
      local_zip="$MOSDNS_ZIP"
    else
      for p in "./${zip_name}" "/root/${zip_name}" "/tmp/${zip_name}"; do
        if [ -f "$p" ]; then
          local_zip="$p"
          break
        fi
      done
    fi
    work_dir=$(mktemp -d /tmp/dex-mos.XXXXXX)
    if [ -n "$local_zip" ]; then
      cp -f "$local_zip" "$work_dir/${zip_name}"
      if [ -f "${local_zip}.sha256sum" ]; then
        verify_sum_in_list "$work_dir/${zip_name}" "${local_zip}.sha256sum" "$zip_name" \
          || { rm -rf "$work_dir"; die "MosDNS offline SHA256 mismatch"; }
      fi
    else
      say "[*] Downloading MosDNS (${MOS_ARCH})..."
      gh_fetch "https://github.com/IrineSistiana/mosdns/releases/latest/download/${zip_name}" "$work_dir/${zip_name}" \
        || { rm -rf "$work_dir"; die "Failed to download MosDNS"; }
      fetch_api_json "https://api.github.com/repos/IrineSistiana/mosdns/releases/latest" "$work_dir/mosdns-release.json" \
        || { rm -rf "$work_dir"; die "Failed to fetch MosDNS release metadata for SHA256 verification"; }
      expected=$(parse_mosdns_api_digest "$work_dir/mosdns-release.json" "$zip_name")
      printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' \
        || { rm -rf "$work_dir"; die "Missing valid MosDNS SHA256 digest in release metadata"; }
      [ "$(sha256_of "$work_dir/${zip_name}")" = "$expected" ] \
        || { rm -rf "$work_dir"; die "MosDNS SHA256 verification failed"; }
    fi
    unzip -oqj "$work_dir/${zip_name}" mosdns -d "$work_dir" || { rm -rf "$work_dir"; die "Failed to extract mosdns"; }
    is_elf "$work_dir/mosdns" || { rm -rf "$work_dir"; die "Extracted mosdns is not ELF"; }
    chmod 0755 "$work_dir/mosdns"
    mv -f "$work_dir/mosdns" "$MOSDNS_BIN"
    rm -rf "$work_dir"
    say "[+] Installed MosDNS to $MOSDNS_BIN"
  fi

  fetch_verified_rule_dat "geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" "${STATE_DIR}/rules/geoip.dat"
  fetch_verified_rule_dat "geosite.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" "${STATE_DIR}/rules/geosite.dat"
  if [ ! -s "${STATE_DIR}/rules/IPchnroute" ]; then
    gh_fetch "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt" "${STATE_DIR}/rules/IPchnroute" || warn "Failed to fetch IPchnroute"
  fi
  if [ ! -s "${STATE_DIR}/rules/Domains.chn.txt" ]; then
    gh_fetch "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt" "${STATE_DIR}/rules/Domains.chn.txt" || warn "Failed to fetch Domains.chn.txt"
  fi
  if [ ! -s "${STATE_DIR}/rules/Domains.ads.txt" ]; then
    gh_fetch "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt" "${STATE_DIR}/rules/Domains.ads.txt" || warn "Failed to fetch Domains.ads.txt"
  fi
  if [ ! -s "${STATE_DIR}/rules/Domains.apple.txt" ]; then
    gh_fetch "https://raw.githubusercontent.com/stuinxo/de_GWD/main/resource/chnroute/mosdns_chnlist/Domains.apple.txt" "${STATE_DIR}/rules/Domains.apple.txt" \
      || gh_fetch "https://raw.githubusercontent.com/jacyl4/chnroute/main/mosdns_chnlist/Domains.apple.txt" "${STATE_DIR}/rules/Domains.apple.txt" \
      || warn "Failed to fetch Domains.apple.txt"
  fi
  if [ ! -s "${STATE_DIR}/rules/Domains.games.txt" ]; then
    gh_fetch "https://raw.githubusercontent.com/stuinxo/de_GWD/main/resource/chnroute/mosdns_chnlist/Domains.games.txt" "${STATE_DIR}/rules/Domains.games.txt" \
      || gh_fetch "https://raw.githubusercontent.com/jacyl4/chnroute/main/mosdns_chnlist/Domains.games.txt" "${STATE_DIR}/rules/Domains.games.txt" \
      || warn "Failed to fetch Domains.games.txt"
  fi
}

ensure_ntp() {
  case "$OS_INIT" in
    systemd)
      if systemctl is-active --quiet systemd-timesyncd 2>/dev/null \
        || systemctl is-active --quiet chrony 2>/dev/null \
        || systemctl is-active --quiet chronyd 2>/dev/null \
        || systemctl is-active --quiet ntp 2>/dev/null; then
        return 0
      fi
      if [ "$OS_PKG" = "apt" ]; then
        wait_apt_lock
        if apt-get install -y -qq --no-install-recommends systemd-timesyncd >/dev/null 2>&1; then
          systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
          return 0
        fi
        wait_apt_lock
        if apt-get install -y -qq --no-install-recommends chrony >/dev/null 2>&1; then
          systemctl enable --now chrony >/dev/null 2>&1 || true
        fi
      fi
      ;;
    openrc)
      if rc-service chronyd status >/dev/null 2>&1 || rc-service ntpd status >/dev/null 2>&1; then
        return 0
      fi
      if [ "$OS_PKG" = "apk" ]; then
        apk add --no-cache chrony >/dev/null 2>&1 || true
        rc-update add chronyd default >/dev/null 2>&1 || true
        rc-service chronyd start >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

main() {
  need_root
  detect_arch
  detect_os
  install_base_pkgs
  install_dex_binary

  role="${1:-}"
  case "$role" in
    client)
      case "$OS_PKG" in
        apk) apk add --no-cache wireguard-tools >/dev/null 2>&1 || true ;;
        apt)
          wait_apt_lock
          apt-get install -y -qq --no-install-recommends wireguard-tools >/dev/null 2>&1 || true
          ;;
      esac
      ensure_ntp
      install_xray_core
      install_mosdns_and_rules
      "$INSTALL_BIN" init --role client --apply
      say "[+] Client Web UI listening on :443 (HTTPS) with :80 -> HTTPS redirect."
      ;;
    server|landing)
      if [ "$role" = "server" ]; then
        say "[*] Installing server packages (nginx, socat, wireguard-tools)..."
        case "$OS_PKG" in
          apk)
            apk add --no-cache nginx socat wireguard-tools >/dev/null 2>&1 \
              || die "Failed to install server Alpine packages."
            ;;
          apt)
            wait_apt_lock
            apt-get install -y -qq --no-install-recommends nginx socat wireguard-tools >/dev/null 2>&1 \
              || die "Failed to install server Debian/Ubuntu packages."
            ;;
        esac
        rm -f /etc/nginx/sites-enabled/default
        ensure_ntp
      fi
      install_xray_core
      say "[+] Ready. Run 'dex init --role $role --domain <dom> --apply' or 'dex' for interactive menu."
      ;;
    relay)
      say "[*] Installing relay packages (haproxy)..."
      case "$OS_PKG" in
        apk)
          apk add --no-cache haproxy >/dev/null 2>&1 || true
          ;;
        apt)
          wait_apt_lock
          apt-get install -y -qq --no-install-recommends haproxy >/dev/null 2>&1 || true
          ;;
      esac
      say "[+] Ready. Run 'dex init --role relay --apply' or 'dex' for interactive menu."
      ;;
    "")
      say "[+] DEX v3 installed. Run 'dex' to open menu, or re-run with: install.sh [client|server|landing|relay]"
      ;;
    *)
      die "Usage: $0 [client|server|landing|relay]"
      ;;
  esac
}

main "$@"
