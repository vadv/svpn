#!/bin/sh
# EPIC-020 sticky-asn: update the DB-IP ASN Lite CSV that geo-db points to.
# Source: https://download.db-ip.com/free/ (CC BY 4.0), monthly, ~400k IPv4
# rows. svpn reads plain CSV and has no hot reload: the base applies at the
# next start, so the tail restarts the service when systemd manages it.
# The last working base is kept next to the target as *.prev.
# dash-compatible (/bin/sh on Debian/Ubuntu): no pipefail.
set -eu

TARGET=${SVPN_ASN_DB:-/etc/svpn/asn.csv}
URL=${SVPN_ASN_URL:-https://download.db-ip.com/free/dbip-asn-lite-$(date +%Y-%m).csv.gz}
UA='Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0'
MIN_ROWS=100000
# Sanity bounds for the unpacked CSV: a real base is tens of MB.
MIN_BYTES=1000000
MAX_BYTES=500000000

work=$(mktemp -d)
staging=""
cleanup() { rm -rf "$work"; [ -z "$staging" ] || rm -f "$staging"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

csv="$work/asn.csv"
curl -fsSL -m 120 --max-filesize 104857600 -A "$UA" -o "$work/asn.csv.gz" "$URL"
gunzip "$work/asn.csv.gz"

bytes=$(wc -c < "$csv")
[ "$bytes" -ge "$MIN_BYTES" ] && [ "$bytes" -le "$MAX_BYTES" ] ||
    { echo "update-asn-db: $URL: $bytes bytes outside $MIN_BYTES..$MAX_BYTES, keeping $TARGET" >&2
      exit 1; }

# Mirror geo.rs: dotted IPv4 ranges, numeric ASN, sorted and non-overlapping —
# the daemon rejects overlaps and degrades to balance, so reject them here.
rows=$(awk -F, '
    function ip2n(s, a) {
        split(s, a, ".")
        if (a[1] > 255 || a[2] > 255 || a[3] > 255 || a[4] > 255) return -1
        return a[1] * 16777216 + a[2] * 65536 + a[3] * 256 + a[4]
    }
    BEGIN { prev = -1 }
    { gsub(/"/, "") }
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ &&
    $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        from = ip2n($1); to = ip2n($2)
        if (from < 0 || to < 0 || from > to || from <= prev) bad++
        prev = to
        n++
    }
    END { print (bad > 0 ? -bad : n) }' "$csv")[ "$rows" -ge "$MIN_ROWS" ] ||
    { echo "update-asn-db: $URL: invalid or too few IPv4 rows ($rows, need >= $MIN_ROWS), keeping $TARGET" >&2
      exit 1; }
chmod 600 "$csv"

# mv is atomic only within one filesystem: stage next to the target first.
# The staging name is per-process so parallel runs cannot rename each
# other's half-written file.
dir=$(dirname "$TARGET")
mkdir -p "$dir"
staging="$TARGET.tmp.$$"
cp "$csv" "$staging"
chmod 600 "$staging"
if [ -f "$TARGET" ]; then cp -p "$TARGET" "$TARGET.prev"; fi
mv -f "$staging" "$TARGET"
staging=""

echo "update-asn-db: $TARGET: $rows IPv4 rows (previous base: $TARGET.prev)"
systemctl try-reload-or-restart svpn.service || true
