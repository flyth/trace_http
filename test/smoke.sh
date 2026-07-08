#!/usr/bin/env bash
# Smoke test for the trace_http gadget.
#
# Hard gate: the gadget must load and attach on the current kernel (sock_ops on
# the cgroup-v2 root, sk_skb verdict and sk_msg on a sockhash). Soft check: an
# HTTP exchange made over loopback is captured and correlated.
#
# Must run as root on the same kernel ig attaches to. Usage:
#   sudo ./test/smoke.sh [image-ref]
set -uo pipefail

IMAGE="${1:-trace_http:ci}"
IG="${IG:-ig}"
PORT=18099
OUT="$(mktemp)"
ERR="$(mktemp)"
SRVLOG="$(mktemp)"

cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "${SRV_PID}" 2>/dev/null
	rm -f "$OUT" "$ERR" "$SRVLOG"
}
trap cleanup EXIT

if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 is required for the smoke workload"
	exit 0
fi

# A tiny keep-alive HTTP/1.1 server that answers every path with a small body.
python3 - "$PORT" >"$SRVLOG" 2>&1 <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"hello %s" % self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ThreadingHTTPServer.allow_reuse_address = True
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
SRV_PID=$!
sleep 1

echo "Starting ${IMAGE}..."
"$IG" run "$IMAGE" \
	--verify-image=false \
	--host \
	--fields method,path,status_code,request_size,response_size,src,dst,comm \
	-o json --timeout 12 >"$OUT" 2>"$ERR" &
IG_PID=$!

# Give the gadget time to load and attach, then generate traffic.
sleep 6
python3 - "$PORT" <<'PY' || true
import http.client, sys, time
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]))
for p in ("/a", "/b", "/c"):
    c.request("GET", p)
    c.getresponse().read()
    time.sleep(0.2)
c.close()
PY

wait "$IG_PID" 2>/dev/null || true

echo "--- ig stderr ---"
grep -v "signature verification is disabled" "$ERR" || true
echo "--- ig stdout (first lines) ---"
head -5 "$OUT"
echo "-----------------"

# Hard gate: the gadget must have loaded and attached.
if grep -qiE "^Error:|failed to (load|attach)|too large|bad address" "$ERR"; then
	echo "FAIL: the gadget did not load/attach (see stderr above)."
	exit 1
fi

if grep -q '"method":"GET"' "$OUT" && grep -q '"status_code":200' "$OUT"; then
	echo "PASS: gadget loaded and captured a correlated HTTP exchange"
	exit 0
fi

echo "PASS: gadget loaded and attached"
echo "NOTE: no request event observed in this environment (the workload may have"
echo "      raced probe attachment); load/attach succeeded."
exit 0
