#!/usr/bin/env bash
# Generate a TEST-ONLY TLS certificate for the local LLM stand-in.
#
# Why this exists: the egress proxy is CONNECT-only (NET-J4a proves plain HTTP
# through it is refused), and the api has no direct route to the stand-in
# (NET-H4). So the only way to reach it is a CONNECT tunnel carrying TLS —
# which is exactly how the real provider is reached. Giving the stand-in a
# certificate means the test path exercises the REAL path: CONNECT, then TLS,
# then the Messages API, through the SDK.
#
# The key never leaves .lab-state/ (gitignored) and authenticates nothing but a
# container that holds no credentials and speaks to nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${LAB_STATE_DIR:-.lab-state}/standin-tls"
mkdir -p "$OUT"
if [ -f "$OUT/standin.crt" ] && [ -f "$OUT/standin.key" ]; then
  echo "already present: $OUT/standin.crt"
  openssl x509 -in "$OUT/standin.crt" -noout -subject -dates
  exit 0
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$OUT/standin.key" -out "$OUT/standin.crt" \
  -subj "/CN=llm-standin/O=VAPT lab test stand-in (NOT A REAL CA)" \
  -addext "subjectAltName=DNS:llm-standin,DNS:localhost,IP:172.30.23.70" \
  -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
# Readable by the stand-in container's unprivileged user. This key secures
# nothing: it authenticates a test double that holds no credentials.
chmod 644 "$OUT/standin.key"
chmod 644 "$OUT/standin.crt"
echo "generated $OUT/standin.crt (TEST ONLY)"
openssl x509 -in "$OUT/standin.crt" -noout -subject -dates
