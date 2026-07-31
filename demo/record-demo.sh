#!/usr/bin/env bash
# Regenerates demo/tameng-demo.gif shown in the README.
# Run from the repo root, after building ./tameng (see README Quick Start),
# with SVALINN_GOD_KEY / SVALINN_API_KEY / SVALINN_RESERSE_USER / SVALINN_RESERSE_PASS set.
#
# Recording: asciinema rec --cols 100 --rows 20 -c 'bash demo/record-demo.sh' demo.cast
# Convert:   agg --font-size 15 --theme dracula --speed 1.3 demo.cast demo/tameng-demo.gif
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
clear

echo '$ ./tameng --config configs/svalinn.yaml &'
sleep 0.6
./tameng --config configs/svalinn.yaml 2>/dev/null &
sleep 1.3

echo
echo '$ curl http://localhost:10000/health'
sleep 0.5
curl -s -o /dev/null -w 'Normal request:      HTTP %{http_code}\n' http://localhost:10000/health
sleep 1.2

echo
echo '$ curl -X POST .../taxii/collections/default/objects  (SQLi + XSS payload)'
sleep 0.5
curl -s -o /dev/null -w 'SQL Injection + XSS: HTTP %{http_code}  <-- BLOCKED\n' \
  -X POST http://localhost:10000/taxii/collections/default/objects \
  -H 'Content-Type: application/json' \
  --data-binary @"$SCRIPT_DIR/attack-payload.json"
sleep 2.5

kill %1 2>/dev/null
