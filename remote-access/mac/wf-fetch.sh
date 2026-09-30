#!/bin/sh
# wf-fetch.sh: bring one finished bundle from the PC's outbox to the Mac and verify it.
#
#   sh remote-access/mac/wf-fetch.sh <bundle dir> [--out <directory>] [--extract]
#
# <bundle dir> is the directory name "collect-<name>" and "list-bundles" report as bundle_dir.
# The forced command on the PC blocks scp and sftp, so the bundle arrives on the standard output
# of the "fetch-<bundle dir>" verb, framed like this (remote-access/README.md, "Transfer"):
#   WF-BUNDLE-BEGIN v1 dir=<bundle dir> bytes=<n> sha256=<hex>
#   <base64 of a zip>
#   WF-BUNDLE-END v1 dir=<bundle dir>
# The zip is kept only if its size and SHA-256 equal the header. What comes back is data from
# another machine: it is never run, and --extract refuses any entry that would land outside
# <directory>/<bundle dir>/ and any symbolic link entry. WF_UNZIP names another unzip.
# Exit codes: 0 ok, 1 usage or transport failure, 3 integrity failure (nothing is kept).
set -eu
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

bundle_dir=""
out_dir="$HOME/win-forensics-bundles"
extract=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) out_dir="${2:-}"; shift 2 ;;
        --extract) extract=1; shift ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        -*) wf_die "unknown option: $1" ;;
        *) [ -z "$bundle_dir" ] || wf_die "give exactly one bundle directory name"; bundle_dir="$1"; shift ;;
    esac
done
[ -n "$bundle_dir" ] || wf_die "give a bundle directory name (see: ssh $WF_HOST_ALIAS list-bundles)"
unzip_cmd="${WF_UNZIP:-unzip}"
if [ "$extract" -eq 1 ] && ! command -v "$unzip_cmd" >/dev/null 2>&1; then
    wf_die "--extract needs the unzip command, which is not available; fetch without --extract and unpack the zip another way"
fi
printf '%s\n' "$bundle_dir" | grep -Eq "$WF_BUNDLE_DIR_RE" || wf_die "'$bundle_dir' is not a bundle directory name (<yyyymmddThhmmssZ>_<collector>_<8 hex>)"

integrity_fail() {
    printf 'INTEGRITY FAILURE: %s\nNothing was kept.\n' "$*" >&2
    exit 3
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rc=0
wf_verb "fetch-$bundle_dir" >"$work/stream" 2>"$work/stderr" || rc=$?
if [ "$rc" -ne 0 ]; then
    cat "$work/stderr" >&2
    wf_die "the PC answered with exit code $rc (66 means no such bundle, 255 means ssh could not connect)"
fi
tr -d '\r' <"$work/stream" >"$work/clean"
header="$(sed -n '1p' "$work/clean")"
footer="$(sed -n '$p' "$work/clean")"
printf '%s\n' "$header" | grep -Eq "^WF-BUNDLE-BEGIN v1 dir=$bundle_dir bytes=[0-9]+ sha256=[0-9a-f]{64}\$" || integrity_fail "unexpected first line from the PC"
[ "$footer" = "WF-BUNDLE-END v1 dir=$bundle_dir" ] || integrity_fail "the stream is cut short (no end marker)"
want_bytes="$(printf '%s\n' "$header" | sed -E 's/.* bytes=([0-9]+) .*/\1/')"
want_sha="$(printf '%s\n' "$header" | sed -E 's/.* sha256=([0-9a-f]{64})$/\1/')"

sed '1d;$d' "$work/clean" >"$work/body"
if grep -Eqv '^[A-Za-z0-9+/]*={0,2}$' "$work/body"; then
    integrity_fail "the body is not base64"
fi
wf_base64_decode <"$work/body" >"$work/bundle.zip" 2>/dev/null || integrity_fail "the body could not be decoded"
got_bytes="$(wc -c <"$work/bundle.zip" | tr -d ' ')"
got_sha="$(wf_sha256 "$work/bundle.zip")"
[ "$got_bytes" = "$want_bytes" ] || integrity_fail "size is $got_bytes bytes, the PC said $want_bytes"
[ "$got_sha" = "$want_sha" ] || integrity_fail "SHA-256 is $got_sha, the PC said $want_sha"

mkdir -p "$out_dir"
zip_path="$out_dir/$bundle_dir.zip"
if [ "$extract" -eq 1 ]; then
    [ ! -e "$out_dir/$bundle_dir" ] || wf_die "$out_dir/$bundle_dir already exists; move it away first"
    # Every entry must sit under <bundle dir>/, must not climb out of it, and must be a plain
    # file or directory: a symbolic link inside an archive from another machine is refused.
    "$unzip_cmd" -Z "$work/bundle.zip" >"$work/listing" 2>/dev/null || integrity_fail "the zip cannot be listed"
    if grep -Eq '^l' "$work/listing"; then
        integrity_fail "the zip holds a symbolic link entry: $(grep -E '^l' "$work/listing" | head -n 1)"
    fi
    "$unzip_cmd" -Z1 "$work/bundle.zip" >"$work/names" 2>/dev/null || integrity_fail "the zip cannot be listed"
    while IFS= read -r name; do
        case "$name" in
            "$bundle_dir"/*) ;;
            *) integrity_fail "zip entry outside the bundle directory: $name" ;;
        esac
        case "$name" in
            */../*|*/..|*\\*) integrity_fail "zip entry with an unsafe path: $name" ;;
        esac
    done <"$work/names"
fi
cp "$work/bundle.zip" "$zip_path"
printf 'OK %s\n   %s bytes, SHA-256 %s (matches the PC)\n' "$zip_path" "$got_bytes" "$got_sha"
if [ "$extract" -eq 1 ]; then
    "$unzip_cmd" -q "$zip_path" -d "$out_dir"
    printf '   extracted to %s/%s\n' "$out_dir" "$bundle_dir"
fi
