#!/bin/bash
set -euo pipefail
codedir="$(dirname "$0")"
pid=""

function cleanup() {
    if [ -n "$pid" ]; then
        kill "$pid"
    fi
}

trap cleanup EXIT

# cargo build >/dev/null
cargo build --release >/dev/null
lua5.2 testecho.lua rust release >&2 &
pid=$!
sleep 0.1
value="$(bash "$codedir/multibench.sh")"
kill $pid
pid=""
wait
echo "$value"
