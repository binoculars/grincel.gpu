#!/usr/bin/env bash
# Run grincel, then check every keypair file it wrote with solana-keygen.
#
#   scripts/check-keys.sh <grincel> <pattern>[:<count>] [grincel options...]
#
# Passes when grincel wrote <count> keypair files and each one:
#   - loads in solana-keygen and derives the address in its file name,
#   - passes `solana-keygen verify`,
#   - matches the pattern,
#   - agrees with the address and private key grincel printed.
# Runs without --cpu must also include at least one key the GPU found.
set -eo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <grincel> <pattern>[:<count>] [grincel options...]" >&2
  exit 2
fi

grincel="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
spec=$2
shift 2

pattern=${spec%:*}
count=1
if [ "$pattern" != "$spec" ]; then
  count=${spec##*:}
fi
case $count in
  '' | *[!0-9]* | 0)
    echo "count must be a positive integer: $spec" >&2
    exit 2
    ;;
esac

mode=prefix
ignore_case=1
use_gpu=1
for arg in "$@"; do
  case $arg in
    --prefix | --start) mode=prefix ;;
    --suffix | --end) mode=suffix ;;
    --anywhere | --contains) mode=anywhere ;;
    -s | --case-sensitive) ignore_case=0 ;;
    -i | --ignore-case) ignore_case=1 ;;
    --cpu) use_gpu=0 ;;
  esac
done

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

matches() {
  local address=$1 want=$pattern
  if [ "$ignore_case" = 1 ]; then
    address=$(lower "$address")
    want=$(lower "$want")
  fi
  # $want stays unquoted so grincel's `?` wildcard matches any one character.
  case $mode in
    prefix) [[ $address == $want* ]] ;;
    suffix) [[ $address == *$want ]] ;;
    anywhere) [[ $address == *$want* ]] ;;
  esac
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

unset CASE_SENSITIVE MATCH_MODE
"$grincel" "$spec" "$@" 2>&1 | tee grincel.log || fail "grincel exited with an error"
echo

shopt -s nullglob
files=(*.json)
[ "${#files[@]}" = "$count" ] || fail "expected $count keypair files, found ${#files[@]}"
grep -q "^Done! Found $count matching address" grincel.log || fail "grincel did not report $count matches"

for file in "${files[@]}"; do
  address=${file%.json}
  derived=$(solana-keygen pubkey "$file") || fail "solana-keygen could not load $file"
  [ "$derived" = "$address" ] || fail "$file derives $derived, not $address"
  solana-keygen verify "$address" "$file" || fail "solana-keygen verify rejected $file"
  matches "$address" || fail "$address does not match '$pattern' ($mode)"
done

printed=$(sed -n 's/^Address: //p' grincel.log | sort)
saved=$(for file in "${files[@]}"; do echo "${file%.json}"; done | sort)
[ "$printed" = "$saved" ] || fail "printed addresses do not match the saved keypair files"

python3 - grincel.log <<'EOF' || fail "printed private keys do not match the saved keypair files"
import json
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text):
    n = 0
    for c in text:
        n = n * 58 + ALPHABET.index(c)
    zeros = len(text) - len(text.lstrip("1"))
    return bytes(zeros) + n.to_bytes((n.bit_length() + 7) // 8, "big")


address = None
for line in open(sys.argv[1]):
    line = line.strip()
    if line.startswith("Address: "):
        address = line.split(": ", 1)[1]
    elif line.startswith("Private Key (Base58): "):
        printed = b58decode(line.split(": ", 1)[1])
        with open(address + ".json") as f:
            saved = bytes(json.load(f))
        if printed != saved:
            sys.exit(f"{address}: printed private key differs from {address}.json")
EOF

gpu_keys=$(grep -c '^Found by: GPU$' grincel.log || true)
cpu_keys=$(grep -c '^Found by: CPU$' grincel.log || true)
if [ "$use_gpu" = 1 ]; then
  [ "$gpu_keys" -gt 0 ] || fail "no key came from the GPU"
else
  [ "$gpu_keys" = 0 ] || fail "a --cpu run reported GPU keys"
fi

echo "PASS: $count keypair files ($gpu_keys GPU, $cpu_keys CPU) verified with $(solana-keygen --version)"
