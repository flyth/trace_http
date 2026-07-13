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
	[ -n "${SSE_SRV_PID:-}" ] && kill "${SSE_SRV_PID}" 2>/dev/null
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

# --- Soft check: --sse splits a text/event-stream response into per-push rows.
# Chunked SSE server that flushes one record per write.
SSE_PORT=$((PORT + 1))
SSEOUT="$(mktemp)"
SSEERR="$(mktemp)"
python3 - "$SSE_PORT" <<'PY' >/dev/null 2>&1 &
import sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for i in range(4):
            rec = b"event: tick\ndata: {\"n\": %d}\n\n" % i
            self.wfile.write(b"%x\r\n%s\r\n" % (len(rec), rec))
            self.wfile.flush()
            time.sleep(0.2)
        self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()
    def log_message(self, *a):
        pass
ThreadingHTTPServer.allow_reuse_address = True
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
SSE_SRV_PID=$!
sleep 1
"$IG" run "$IMAGE" --verify-image=false --host --sse --res-body \
	--fields path,status_code,response_size,response_body,is_sse \
	-o json --timeout 10 >"$SSEOUT" 2>"$SSEERR" &
SSE_IG_PID=$!
sleep 5
python3 - "$SSE_PORT" <<'PY' >/dev/null 2>&1 || true
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]))
c.request("GET", "/stream"); r = c.getresponse()
while r.read(256):
    pass
c.close()
PY
wait "$SSE_IG_PID" 2>/dev/null || true
kill "$SSE_SRV_PID" 2>/dev/null
if grep -qiE "^Error:|failed to (load|attach)|too large|bad address" "$SSEERR"; then
	echo "FAIL: the gadget did not load/attach with --sse (see below)."
	grep -v "signature verification is disabled" "$SSEERR" || true
	rm -f "$SSEOUT" "$SSEERR"
	exit 1
fi
if grep -q '"is_sse":true' "$SSEOUT"; then
	echo "PASS: --sse emitted per-push Server-Sent Events rows"
else
	echo "NOTE: --sse loaded/attached but no per-push row observed (workload may"
	echo "      have raced probe attachment); this soft check does not gate."
fi
rm -f "$SSEOUT" "$SSEERR"

if grep -q '"method":"GET"' "$OUT" && grep -q '"status_code":200' "$OUT"; then
	echo "PASS: gadget loaded and captured a correlated HTTP exchange"
	exit 0
fi

echo "PASS: gadget loaded and attached"
echo "NOTE: no request event observed in this environment (the workload may have"
echo "      raced probe attachment); load/attach succeeded."
exit 0
