#!/bin/bash
# Fetch only a locked source, without persisting credentials or a failed checkout.
# If a tag is supplied, keep it for git describe but verify its peeled commit.
bcd_fetch_pinned_source() (
    set -eu
    local dest="$1" url="$2" commit="$3" tag="${4:-}" parent temp fetchspec pause fetched
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ "$url" == https://github.com/* ]] || return 1
    parent="$(dirname "$dest")"
    mkdir -p "$parent"
    temp="$(mktemp -d "$parent/.bcd-pinned-src.XXXXXXXX")"
    trap 'rm -rf "$temp"' EXIT
    export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false
    git init -q "$temp"
    git -C "$temp" remote add origin "$url"
    fetchspec="$commit"
    if [[ -n "$tag" ]]; then fetchspec="refs/tags/$tag:refs/tags/$tag"; fi
    fetched=0
    for pause in 0 4 8 16; do
        if [[ "$pause" != 0 ]]; then sleep "$pause"; fi
        if git -C "$temp" -c credential.helper= -c http.extraHeader= \
            -c http.https://github.com/.extraHeader= -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=35 \
            fetch --no-tags --depth 1 origin "$fetchspec"; then
            fetched=1
            break
        fi
        echo "Pinned source fetch failed: $url ($commit)" >&2
    done
    [[ "$fetched" == 1 ]] || return 1
    if [[ -n "$tag" ]] && [[ "$(git -C "$temp" rev-parse "refs/tags/$tag^{commit}")" != "$commit" ]]; then
        echo "Tag $tag does not resolve to the locked commit $commit" >&2
        return 1
    fi
    git -C "$temp" checkout -q --detach "$commit"
    [[ "$(git -C "$temp" rev-parse HEAD)" == "$commit" ]] || return 1
    if [[ -e "$dest" || -L "$dest" ]]; then
        [[ ! -L "$dest" ]] && rmdir "$dest" || return 1
    fi
    mv "$temp" "$dest"
)
