#!/bin/bash
# Stage Apple's Metal Shader Converter iOS library for an independent build.
# The source tag already pins this exact Apple-signed iOS dylib hash. The
# Apple Developer download portal requires an interactive account, so CI uses
# a content-addressed mirror of the original payload and verifies both the
# mirror archive and Apple's embedded code signature before use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build-out/evidence"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/bcd-msc.XXXXXXXX")"
trap 'rm -rf "$TMP"' EXIT

URL="https://github.com/intraducine/iridium/releases/download/deps-metal-shader-converter-4.0-beta2/metal-shader-converter-4.0-beta2-apple.tar.gz"
ARCHIVE_SHA256="f61c5bf4eadb993430642bb32c5642b1ddf2479a97b22ac307564967a4ff69d4"
APPLE_IOS_DYLIB_SHA256="073f903be98e973ff38f4d79f2c48d61ef938754a77b1caedda79c9f05a068c2"
MIRROR_COMMIT="31ca8f113b842d4c995474438f14c04ef50b7110"
ARCHIVE="$TMP/metal-shader-converter-4.0-beta2-apple.tar.gz"
COMMIT_JSON="$TMP/mirror-commit.json"

# The release payload is pinned by its own SHA-256. Also verify that the public
# mirror anchor is the exact GitHub-verified signed commit recorded in the lock.
COMMIT_URL="https://api.github.com/repos/intraducine/iridium/commits/$MIRROR_COMMIT"
ASSET_URL="https://api.github.com/repos/intraducine/iridium/releases/assets/591229297"

fetch() {
  local label="$1" seconds="$2" dest="$3"
  shift 3
  echo "Fetching $label"
  curl --disable --fail --location --silent --show-error --retry 3 --retry-delay 2 \
    --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time "$seconds" \
    -o "$dest" "$@"
}

fetch_api() {
  local label="$1" seconds="$2" dest="$3" accept="$4" api_url="$5"
  [[ "$api_url" == https://api.github.com/repos/intraducine/iridium/* ]] || return 1
  if [[ -n "${BCD_MSC_GITHUB_TOKEN:-}" ]]; then
    if fetch "$label (GitHub Actions API)" "$seconds" "$dest" \
        -H "Authorization: Bearer $BCD_MSC_GITHUB_TOKEN" -H "Accept: $accept" "$api_url"; then
      return 0
    fi
    echo "::warning::Authenticated $label endpoint failed; retrying the same endpoint anonymously"
  fi
  fetch "$label (anonymous GitHub API)" "$seconds" "$dest" -H "Accept: $accept" "$api_url"
}

fetch_api "pinned Metal Shader Converter mirror commit" 60 "$COMMIT_JSON" 'application/vnd.github+json' "$COMMIT_URL"
python3 - "$COMMIT_JSON" "$MIRROR_COMMIT" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
if data.get("sha") != sys.argv[2] or data.get("commit", {}).get("verification", {}).get("verified") is not True:
    raise SystemExit("Metal Shader Converter mirror anchor is not the expected GitHub-verified commit")
PY

TRANSPORT_URL="$URL"
if ! fetch "pinned Metal Shader Converter release archive" 300 "$ARCHIVE" "$URL"; then
  echo "::warning::Direct release download failed; trying the same pinned asset via GitHub's release API"
  TRANSPORT_URL="$ASSET_URL"
  fetch_api "pinned Metal Shader Converter release asset" 300 "$ARCHIVE" 'application/octet-stream' "$ASSET_URL"
fi
unset BCD_MSC_GITHUB_TOKEN
printf '%s  %s\n' "$ARCHIVE_SHA256" "$ARCHIVE" | shasum -a 256 -c -

# Refuse path traversal and link entries before extraction. The whole archive
# is content-pinned, but the checks also make the extraction rule explicit.
python3 - "$ARCHIVE" <<'PY'
import sys, tarfile
archive = sys.argv[1]
prefix = "metal-shader-converter-4.0-beta2/"
with tarfile.open(archive, "r:gz") as tf:
    for member in tf.getmembers():
        parts = member.name.split("/")
        if (not member.name.startswith(prefix) or ".." in parts
                or not (member.isfile() or member.isdir())):
            raise SystemExit(f"refusing unsafe MSC archive member: {member.name!r}")
PY

tar -xzf "$ARCHIVE" -C "$TMP"
PAYLOAD="$TMP/metal-shader-converter-4.0-beta2/MetalShaderConverter.pkg/Payload/usr/local"
cd "$TMP/metal-shader-converter-4.0-beta2"
shasum -a 256 -c SHA256SUMS

IOS_LIB="$PAYLOAD/lib_iOS/libmetalirconverter.dylib"
[[ -f "$IOS_LIB" ]] || { echo "Apple iOS converter library is missing" >&2; exit 1; }
got="$(shasum -a 256 "$IOS_LIB" | awk '{print $1}')"
[[ "$got" == "$APPLE_IOS_DYLIB_SHA256" ]] || {
  echo "Apple iOS converter hash mismatch: $got" >&2
  exit 1
}

codesign --verify --strict --verbose=2 "$IOS_LIB"
codesign -d --verbose=4 "$IOS_LIB" 2> "$TMP/codesign.txt"
grep -q '^Authority=.*Apple' "$TMP/codesign.txt" || {
  echo "Metal Shader Converter signature is not chained to an Apple authority" >&2
  cat "$TMP/codesign.txt" >&2
  exit 1
}

VENDORED_HEADERS="$ROOT/madeira-d3d12/third_party/metal-shader-converter/include"
[[ -d "$VENDORED_HEADERS" ]] || { echo "pinned Apple converter headers are missing" >&2; exit 1; }
diff -qr "$PAYLOAD/include" "$VENDORED_HEADERS" >/dev/null || {
  echo "downloaded Apple converter headers do not match the v0.1.712 vendored headers" >&2
  exit 1
}

DEST="$ROOT/app/Madeira/d3d12"
mkdir -p "$DEST" "$OUT"
install -m 0644 "$IOS_LIB" "$DEST/libmetalirconverter.dylib"

cat > "$OUT/msc-origin.json" <<EOF
{
  "name": "Apple Metal Shader Converter",
  "version": "4.0 beta 2",
  "publisher": "Apple Inc.",
  "source_url": "$URL",
  "download_transport_url": "$TRANSPORT_URL",
  "mirror_source_commit": "$MIRROR_COMMIT",
  "mirror_commit_signature_verified_by_github": true,
  "mirror_archive_sha256": "$ARCHIVE_SHA256",
  "original_apple_ios_dylib_sha256": "$APPLE_IOS_DYLIB_SHA256",
  "apple_code_signature_verified": true,
  "baseline_headers_match": true,
  "notes": "The library is the Apple-signed binary whose SHA-256 is pinned by the v0.1.712 source. The mirror archive is used because Apple's developer download portal requires interactive sign-in; no Apple ID is used in CI."
}
EOF

bash "$ROOT/build/stage-licenses.sh"
echo "Staged Apple-signed Metal Shader Converter iOS dylib ($got)"
