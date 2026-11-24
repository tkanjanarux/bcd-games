#!/bin/bash
# Install the Mesa build tools only from the hash-locked wheels in the repository.
set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${1:-$ROOT/toolchains/mesa-venv}"
LOCK="$ROOT/build/mesa-ios/requirements.lock"
LOCK_SHA="$(shasum -a 256 "$LOCK" | awk '{print $1}')"
MARKER="$VENV/.bcd-requirements-sha256"

expected() {
    "$VENV/bin/python" - <<'PY'
from importlib.metadata import version
names = ("meson", "mako", "markupsafe", "pyyaml", "packaging", "ninja")
for name in names:
    print(f"{name}=={version(name)}")
PY
}

if [ -x "$VENV/bin/python" ] && [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$LOCK_SHA" ]; then
    if expected | diff -u <(printf '%s\n' \
        'meson==1.12.1' 'mako==1.4.3' 'markupsafe==3.0.4' \
        'pyyaml==6.0.4' 'packaging==26.4' 'ninja==1.13.2') -; then
        exit 0
    fi
fi

rm -rf "$VENV"
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --disable-pip-version-check --no-deps --require-hashes -r "$LOCK"
"$VENV/bin/python" -m pip check
expected | diff -u <(printf '%s\n' \
    'meson==1.12.1' 'mako==1.4.3' 'markupsafe==3.0.4' \
    'pyyaml==6.0.4' 'packaging==26.4' 'ninja==1.13.2') -
printf '%s\n' "$LOCK_SHA" > "$MARKER"
