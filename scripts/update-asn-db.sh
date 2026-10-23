#!/bin/sh
# EPIC-020 sticky-asn: update the DB-IP ASN Lite CSV that geo-db points to.
# Source: https://download.db-ip.com/free/ (CC BY 4.0), monthly, ~400k IPv4
# rows. svpn reads plain CSV and has no hot reload: the base applies at the
# next start, so the tail restarts the service when systemd manages it.
# The last working base is kept next to the target as *.prev.
set -euo pipefail

TARGET=${SVPN_ASN_DB:-/etc/svpn/asn.csv}
URL=${SVPN_ASN_URL:-https://download.db-ip.com/free/dbip-asn-lite-$(date +%Y-%m).csv.gz}
UA='Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0'
MIN_ROWS=100000

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

csv="$work/asn.csv"
curl -fsSL -m 120 -A "$UA" -o "$work/asn.csv.gz" "$URL"
gunzip "$work/asn.csv.gz"

# Sanity floor mirroring geo.rs (MIN_ROWS): count IPv4 rows only; the daemon
# re-validates overlaps and sorting when it loads the file.
rows=$(awk -F, '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ &&
    $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $3 ~ /^[0-9]+$/ { n++ }
    END { print n + 0 }' "$csv")
[ "$rows" -ge "$MIN_ROWS" ] ||
    { echo "update-asn-db: $URL: $rows IPv4 rows < $MIN_ROWS, keeping $TARGET" >&2
      exit 1; }
chmod 600 "$csv"

# mv is atomic only within one filesystem: stage next to the target first.
dir=$(dirname "$TARGET")
mkdir -p "$dir"
if [ -f "$TARGET" ]; then cp -p "$TARGET" "$TARGET.prev"; fi
cp "$csv" "$TARGET.tmp"
chmod 600 "$TARGET.tmp"
mv -f "$TARGET.tmp" "$TARGET"

echo "update-asn-db: $TARGET: $rows IPv4 rows (previous base: $TARGET.prev)"
systemctl try-reload-or-restart svpn.service || true
