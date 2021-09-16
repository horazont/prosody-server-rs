#!/bin/bash
set -euo pipefail
#benchinfo=$(dd if=/dev/zero bs=1k count=256k 2>/dev/null | openssl s_client -quiet -no_ign_eof -servername localhost -connect 127.0.0.1:1234 2>/dev/null | pv --size 4294967296 --numeric --bytes --timer 2>&1 >/dev/null | tail -n1)
benchinfo=$(dd if=/dev/zero bs=1k count=256k 2>/dev/null | ncat 127.0.0.1 1234 | pv --size 4294967296 --numeric --bytes --timer 2>&1 >/dev/null | tail -n1)
time=$(cut -d' ' -f1 <<<"$benchinfo")
bytes=$(cut -d' ' -f2 <<<"$benchinfo")
mib_per_second=$(bc <<<"scale=2; $bytes/$time / (1024*1024)")
echo "$mib_per_second"
