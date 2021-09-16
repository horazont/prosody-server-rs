#!/bin/bash
set -euo pipefail
benchtool="bash $(dirname "$0")/bench.sh"
accum=0
n=5
$benchtool >/dev/null
for i in $(seq 1 $n); do
    v=$($benchtool)
    accum=$(bc <<< "scale=2; $accum + $v / $n")
done
echo "$accum"
