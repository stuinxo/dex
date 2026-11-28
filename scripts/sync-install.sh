#!/bin/sh
# scripts/install.sh is the editable source; dex and i are published copies.
set -eu

mode="${1:-}"
case "$mode" in
  ""|--check) ;;
  *) printf 'Usage: %s [--check]\n' "$0" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf 'Too many arguments\n' >&2; exit 2; }

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_script="$repo_root/scripts/install.sh"
sh -n "$source_script"
staged=""
trap '[ -z "$staged" ] || rm -f "$staged"' EXIT

for name in dex i; do
  target="$repo_root/$name"
  if cmp -s "$source_script" "$target" && [ -x "$target" ]; then
    continue
  fi
  if [ "$mode" = "--check" ]; then
    printf '%s is stale; run sh scripts/sync-install.sh\n' "$name" >&2
    exit 1
  fi
  staged=$(mktemp "$repo_root/.install-entry.XXXXXX")
  cat "$source_script" > "$staged"
  chmod 0755 "$staged"
  mv -f "$staged" "$target"
  staged=""
done
