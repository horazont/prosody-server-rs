#!/bin/bash
set -euo pipefail
codedir="$(mktemp -d)"
head=""
pid=""

function cleanup() {
    rm -rf "$codedir"
    if [ -n "$head" ]; then
        git checkout "$head" >&2
    fi
    if [ -n "$pid" ]; then
        kill "$pid"
    fi
}

trap cleanup EXIT

src="$(dirname "$0")"
cp "$src/multibench.sh" "$src/bench.sh" "$src/fullbench.sh" "$codedir"

head=$(git rev-parse --abbrev-ref HEAD)
while IFS=' ' read -r commitid label; do
    git checkout -q "$commitid"
    printf 'Now processing %s (%s)\n' "$commitid" "$label" >&2
    set +e
    value=$(bash "$codedir/fullbench.sh")
    status="$?"
    set -e
    if [ "$status" != '0' ]; then
        printf '%s %s %s\n' "$commitid" "errored" "$label"
    else
        printf '%s %s %s\n' "$commitid" "$value" "$label"
    fi
    printf '%s done\n\n' "$commitid" >&2
done
