// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 The Inspektor Gadget authors */

// trace_http extracts HTTP/1.x requests and responses from TCP connections and
// correlates each request with its response.
//
// It is built from three eBPF programs wired to a sockhash:
//
//   - a sock_ops program, attached to the cgroup-v2 root, adds every established
//     TCP socket to the sockhash and signals connection close;
//   - an sk_skb stream_verdict program observes the data a socket *receives*
//     (ingress);
//   - an sk_msg program observes the data a socket *sends* (egress).
//
// All three programs always pass the traffic through untouched (SK_PASS); they
// only observe it. Together, ingress + egress see both ends of a connection.
//
// De-duplication ("egress-preferred"): the egress path always captures. The
// ingress path captures a message only when the peer socket is off-node; if the
// mirrored 4-tuple is present in the sockhash the peer is local and its egress
// already captured the message, so ingress skips it. On-node traffic is thus
// captured exactly once, off-node connections show both directions.
//
// For each connection the program frames HTTP messages per direction, then
// correlates request with response entirely in the kernel: a request is stashed
// in an LRU "pending" map keyed by a canonical connection key plus a per-stream
// sequence number, and when the matching response completes the two are joined
// into a single "exchange" event carrying latency, sizes and both raw header
// blocks. On connection close, requests still awaiting a response are flushed as
// request-only rows. The accompanying WASM module only parses the header blocks
// (method/path/host/status) in place; it performs no correlation.
//
// The response-completion path (on_msg_complete) is the natural place for a later
// phase to also increment aggregated metrics in a map.

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/buffer.h>

// Pull in the socket-enricher map and helpers. This lets the gadget resolve the
// process (and therefore the container/pod) that owns each socket, and makes
// Inspektor Gadget populate the enrichment map automatically.
#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>
#include <gadget/filter.h>

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

// MAX_SCAN bounds header (and chunked-terminator) scanning, PREVIEW bounds the
// body preview, MAX_DATA bounds the forwarded event payload.
#define MAX_SCAN 1024
#define PREVIEW 1024
#define MAX_DATA (MAX_SCAN + PREVIEW)

// Per-side header+body-preview blocks stored per pending exchange, and the
// combined on-the-wire payload (request block followed by response block).
#define REQ_PREVIEW MAX_DATA
#define RESP_PREVIEW MAX_DATA
#define COMBINED_DATA (REQ_PREVIEW + RESP_PREVIEW)

// On connection close, at most this many most-recent request seqs are checked
// for still-pending (unpaired) requests to flush as request-only rows. Bounds
// the close loop; deeper in-flight pipelining than this is not enumerated.
#define FLUSH_WINDOW 64

// Body-preview parameters. Copying a body sample into user space costs a per-
// message copy and widens each event, so it is off by default. When enabled, at
// most req_body_len / resp_body_len bytes are captured (clamped to PREVIEW).
const volatile bool req_body = false;
const volatile bool res_body = false;
const volatile __u32 req_body_len = 1024;
const volatile __u32 res_body_len = 1024;
GADGET_PARAM(req_body);
GADGET_PARAM(res_body);
GADGET_PARAM(req_body_len);
GADGET_PARAM(res_body_len);

// HTTP message direction, derived from the start line.
#define HTTP_DIR_UNKNOWN 0
#define HTTP_DIR_REQUEST 1
#define HTTP_DIR_RESPONSE 2

// Capture path: which side observed the bytes. Also selects the framing-state
// slot so the two streams on one socket frame independently.
#define CAP_INGRESS 0
#define CAP_EGRESS 1

enum http_phase : __u8 {
	PH_HEADERS = 0, // expecting the start of a message
	PH_SKIP = 1, // skipping skip_remaining Content-Length body bytes
	PH_DRAIN = 2, // draining a chunked body until its terminator
	PH_PASS = 3, // pass the rest of the connection through untouched
};

// conn_key identifies a socket by its 4-tuple. It is built byte-identically by
// sock_ops, sk_skb and sk_msg (always from a struct bpf_sock) so the ingress
// mirror lookup in the sockhash matches the peer's inserted key exactly.
struct conn_key {
	__u32 local_ip4;
	__u32 remote_ip4;
	__u32 local_ip6[4];
	__u32 remote_ip6[4];
	__u16 local_port;
	__u16 remote_port;
	__u8 family;
	__u8 pad[3];
};

// state_key adds the capture direction so ingress and egress frame the two
// streams on one socket independently. It is NOT used for the sockhash.
struct state_key {
	struct conn_key conn;
	__u8 cap_dir;
	__u8 pad[3];
};

// ep is one connection endpoint in a byte-comparable form (IPv4 sits in the
// first four bytes of ip[]). canon_key orders the two endpoints so both
// mirrored captures of a connection hash to the same value.
struct ep {
	__u8 ip[16];
	__u16 port;
	__u16 pad;
};

// canon_key is a connection identity identical for a request (client->server)
// and its mirrored response (server->client): the two endpoints sorted, plus
// netns only for loopback (where distinct connections can share a 4-tuple across
// namespaces but both captures share one netns). Mirrors go/correlate.canonKey.
struct canon_key {
	struct ep lo;
	struct ep hi;
	__u32 netns; // 0 unless loopback
	__u8 family;
	__u8 pad[3];
};

// pending_key identifies one in-flight exchange: its connection plus the
// per-direction sequence number that pairs request[N] with response[N].
struct pending_key {
	struct canon_key canon;
	__u32 seq;
};

struct parse_state {
	enum http_phase phase;
	__u8 cur_dir; // HTTP direction of the in-progress message
	__u8 tail[4]; // trailing bytes carried across segments for the chunked terminator
	__u8 pad2;
	__u32 skip_remaining; // Content-Length body bytes left to skip
	__u32 total_body; // body bytes counted for the in-progress message
	__u32 cur_hdr_len; // header length of the in-progress message
	__u32 cur_seq; // sequence number of the in-progress message
	__u32 next_seq; // next sequence number to assign on this stream
	struct canon_key cur_canon; // connection key of the in-progress message
};

// combined_event is the single user-facing event: one correlated request/response
// exchange assembled in the kernel. It carries both raw header blocks (request
// then response) appended after the struct so the WASM module can parse
// method/path/host/status without any correlation logic. src/dst/proc are the
// request (client) side. WASM slices the appended data with req_data_len and
// resp_data_len (response block starts at offset req_data_len).
struct combined_event {
	gadget_timestamp timestamp_raw; // request start
	struct gadget_l4endpoint_t src; // client (request sender)
	struct gadget_l4endpoint_t dst; // server (request receiver)
	gadget_netns_id netns_id;
	struct gadget_process proc; // owning process of the request/client side
	__u32 req_hdr_len; // header length within the request block
	__u32 req_data_len; // request block length (headers + body preview)
	__u32 resp_hdr_len; // header length within the response block
	__u32 resp_data_len; // response block length (headers + body preview)
	__u32 data_len; // total appended bytes (req_data_len + resp_data_len)
	__u32 request_size; // total request bytes (headers + body)
	__u32 response_size; // total response bytes (headers + body), 0 if unknown
	__u64 latency_ttfb_ns; // request start -> first response byte
	__u64 latency_total_ns; // request start -> last response byte, 0 if unknown
	__u8 complete; // both request and full response captured
	__u8 pad[7];
};

// event_buf is the per-CPU scratch holding the combined event and its appended
// two-block payload. Its data area is also reused as the segment load buffer
// during framing (which needs only the first MAX_DATA bytes).
struct event_buf {
	struct combined_event ev;
	__u8 data[COMBINED_DATA];
};

// pending holds one in-flight exchange between the request being seen and the
// response completing. The request side (bytes, size and enrichment) is stored
// at request time because on-node the response completes on the peer socket,
// where the client's process is not available.
struct pending {
	__u64 req_ts;
	__u64 resp_first_ts;
	__u32 req_hdr_len;
	__u32 req_data_len;
	__u32 req_size;
	__u32 resp_hdr_len;
	__u32 resp_data_len;
	__u32 netns;
	__u8 req_seen;
	__u8 resp_seen;
	__u8 pad[2];
	struct gadget_l4endpoint_t src; // client (request sender)
	struct gadget_l4endpoint_t dst; // server (request receiver)
	struct gadget_process proc; // request/client owning process
	__u8 req_data[REQ_PREVIEW];
	__u8 resp_data[RESP_PREVIEW];
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, __u32);
} http_sockhash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct state_key);
	__type(value, struct parse_state);
} http_states SEC(".maps");

// http_pending holds in-flight exchanges keyed by {canonical connection, seq}.
// An LRU map bounds memory: exchanges whose response never arrives are evicted
// (and the most recent unpaired ones are also flushed on close). The value is
// large (two ~2 KB preview blocks), so max_entries is kept modest; it caps how
// many exchanges can be in flight at once and trades that for memory.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct pending_key);
	__type(value, struct pending);
} http_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_buf);
} http_scratch SEC(".maps");

// http_states_scratch holds a working parse_state for a stream not yet in
// http_states, so the (fairly large) state never lives on the BPF stack. It is
// promoted into http_states only once the stream actually starts framing HTTP.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct parse_state);
} http_states_scratch SEC(".maps");

// http_pending_seed provides a zeroed pending value to insert new entries with,
// so the large value never lives on the BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pending);
} http_pending_seed SEC(".maps");

GADGET_TRACER_MAP(events, 1 << 24);
GADGET_TRACER(http, events, combined_event);

static __always_inline __u8 to_lower(__u8 c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	return c;
}

// word4 reads the first four bytes of b as a little-endian word, lowercasing
// A-Z so method/version matching is case-insensitive.
static __always_inline __u32 word4(const __u8 *b)
{
	return (__u32)to_lower(b[0]) | ((__u32)to_lower(b[1]) << 8) |
	       ((__u32)to_lower(b[2]) << 16) | ((__u32)to_lower(b[3]) << 24);
}

#define W4(a, b, c, d)                                                    \
	((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) |            \
	 ((__u32)(d) << 24))

// classify_start_line returns the message direction from the first 4 bytes of
// the start line, or HTTP_DIR_UNKNOWN. A single word compare (no per-character
// loops) keeps verifier complexity low. b must be >= 4 bytes.
static __always_inline __u8 classify_start_line(const __u8 *b)
{
	switch (word4(b)) {
	case W4('h', 't', 't', 'p'): // "HTTP/1."
		return HTTP_DIR_RESPONSE;
	case W4('g', 'e', 't', ' '): // GET
	case W4('p', 'o', 's', 't'): // POST
	case W4('p', 'u', 't', ' '): // PUT
	case W4('h', 'e', 'a', 'd'): // HEAD
	case W4('d', 'e', 'l', 'e'): // DELETE
	case W4('o', 'p', 't', 'i'): // OPTIONS
	case W4('p', 'a', 't', 'c'): // PATCH
	case W4('c', 'o', 'n', 'n'): // CONNECT
	case W4('t', 'r', 'a', 'c'): // TRACE
		return HTTP_DIR_REQUEST;
	}
	return HTTP_DIR_UNKNOWN;
}

// The header scan runs as a bpf_loop callback, which the verifier checks once
// rather than unrolling per iteration. Each match uses a 4-byte shift register
// over the last bytes seen, which is cheap for the verifier to reason about.
struct hscan {
	const __u8 *buf;
	__u32 len;
	__u32 hdr_end; // index past CRLFCRLF, 0 if not found
	int cl_pos; // index just past a Content-Length "gth:" tail, -1 if none
	__u8 b1, b2, b3; // lowercased bytes at i-1, i-2, i-3
	__u8 chunked;
};

static long hscan_cb(__u32 i, void *ctx)
{
	struct hscan *s = ctx;
	if (i >= s->len)
		return 1;
	__u8 lc = to_lower(s->buf[i & (MAX_SCAN - 1)]);
	if (lc == '\n' && s->b1 == '\r' && s->b2 == '\n' && s->b3 == '\r') {
		s->hdr_end = i + 1;
		return 1; // end of headers
	}
	if (lc == ':' && s->b1 == 'h' && s->b2 == 't' && s->b3 == 'g')
		s->cl_pos = (int)(i + 1); // "...gth:" (Content-Length)
	if (lc == 'd' && s->b1 == 'e' && s->b2 == 'k' && s->b3 == 'n')
		s->chunked = 1; // "...nked" (chunked)
	s->b3 = s->b2;
	s->b2 = s->b1;
	s->b1 = lc;
	return 0;
}

// scan_headers finds the header-block length, the Content-Length value position
// and the chunked flag in a single pass. Matching only the 4-byte tails of the
// header names can in theory collide with a header value ending in "gth:" or
// "nked"; this is vanishingly rare and a Content-Length match is confirmed by
// parsing digits after it.
static __noinline void scan_headers(const __u8 *buf, __u32 len,
					 __u32 *hdr_end, int *cl_pos,
					 bool *chunked)
{
	struct hscan s = {};
	s.buf = buf;
	s.len = len;
	s.cl_pos = -1;
	// Variable count so the verifier does not inline the loop.
	bpf_loop(len, hscan_cb, &s, 0);
	*hdr_end = s.hdr_end;
	*cl_pos = s.cl_pos;
	*chunked = s.chunked != 0;
}

// tscan looks for the chunked terminator "0\r\n\r\n", carrying the last four
// bytes across segments so a terminator split over a segment boundary is still
// found. It is a heuristic: a body containing that exact byte sequence could
// terminate early. Upgrade path: full chunk-size parsing.
struct tscan {
	const __u8 *buf;
	__u32 len;
	__u8 t1, t2, t3, t4; // bytes at i-1, i-2, i-3, i-4
	__u8 found;
};

static long tscan_cb(__u32 i, void *ctx)
{
	struct tscan *s = ctx;
	if (i >= s->len)
		return 1;
	__u8 c = s->buf[i & (MAX_SCAN - 1)];
	if (c == '\n' && s->t1 == '\r' && s->t2 == '\n' && s->t3 == '\r' &&
	    s->t4 == '0') {
		s->found = 1;
		return 1;
	}
	s->t4 = s->t3;
	s->t3 = s->t2;
	s->t2 = s->t1;
	s->t1 = c;
	return 0;
}

// parse_uint_at reads a decimal integer at pos (skipping leading spaces) in a
// small bounded loop.
static __always_inline __u32 parse_uint_at(const __u8 *buf, __u32 pos, __u32 len,
					   bool *has)
{
	__u32 val = 0;
	*has = false;
#pragma unroll
	for (__u32 k = 0; k < 20; k++) {
		if (pos >= len)
			break;
		__u8 c = buf[pos & (MAX_SCAN - 1)];
		if (c == ' ' && !*has) {
			pos++;
			continue;
		}
		if (c < '0' || c > '9')
			break;
		val = val * 10 + (c - '0');
		*has = true;
		pos++;
	}
	return val;
}

// build_conn_key fills key from a struct bpf_sock. Using bpf_sock in all three
// programs (sk_skb's skb->sk, sk_msg's msg->sk, sock_ops's skops->sk) makes the
// keys byte-identical, which the mirror lookup depends on.
static __always_inline void build_conn_key(struct bpf_sock *sk,
					   struct conn_key *key)
{
	key->family = (__u8)sk->family;
	key->local_port = (__u16)sk->src_port; // host order
	key->remote_port = bpf_ntohs(sk->dst_port); // network -> host
	if (sk->family == AF_INET6) {
		key->local_ip6[0] = sk->src_ip6[0];
		key->local_ip6[1] = sk->src_ip6[1];
		key->local_ip6[2] = sk->src_ip6[2];
		key->local_ip6[3] = sk->src_ip6[3];
		key->remote_ip6[0] = sk->dst_ip6[0];
		key->remote_ip6[1] = sk->dst_ip6[1];
		key->remote_ip6[2] = sk->dst_ip6[2];
		key->remote_ip6[3] = sk->dst_ip6[3];
	} else {
		key->local_ip4 = sk->src_ip4;
		key->remote_ip4 = sk->dst_ip4;
	}
}

// mirror_key builds the peer socket's key by swapping local and remote. The peer
// (if on-node) inserted exactly this key into the sockhash from its own bpf_sock.
static __always_inline void mirror_key(const struct conn_key *k,
				       struct conn_key *m)
{
	m->family = k->family;
	m->local_port = k->remote_port;
	m->remote_port = k->local_port;
	m->local_ip4 = k->remote_ip4;
	m->remote_ip4 = k->local_ip4;
	m->local_ip6[0] = k->remote_ip6[0];
	m->local_ip6[1] = k->remote_ip6[1];
	m->local_ip6[2] = k->remote_ip6[2];
	m->local_ip6[3] = k->remote_ip6[3];
	m->remote_ip6[0] = k->local_ip6[0];
	m->remote_ip6[1] = k->local_ip6[1];
	m->remote_ip6[2] = k->local_ip6[2];
	m->remote_ip6[3] = k->local_ip6[3];
}

// ip6_is_loopback reports whether a 16-byte address is ::1.
static __always_inline bool ip6_is_loopback(const __u8 *ip)
{
#pragma unroll
	for (int i = 0; i < 15; i++) {
		if (ip[i] != 0)
			return false;
	}
	return ip[15] == 1;
}

// build_canon_key orders the two endpoints (smaller first) so both mirrored
// captures of a connection produce the same key, and includes netns only for
// loopback. The absolute ordering need not match user space; it only has to be
// identical for a request and its mirrored response. It writes directly into
// *out (no struct temporaries) to stay within the BPF stack budget, and is
// inlined so it does not pass caller-stack pointers across a call boundary.
static __always_inline void build_canon_key(const struct conn_key *ck,
					    __u32 netns, struct canon_key *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	out->family = ck->family;

	bool local_first, loopback;
	if (ck->family == AF_INET6) {
		const __u8 *l = (const __u8 *)ck->local_ip6;
		const __u8 *r = (const __u8 *)ck->remote_ip6;
		int c = 0;
#pragma unroll
		for (int i = 0; i < 16; i++) {
			if (l[i] != r[i]) {
				c = l[i] < r[i] ? -1 : 1;
				break;
			}
		}
		local_first = c < 0 ||
			      (c == 0 && ck->local_port <= ck->remote_port);
		loopback = ip6_is_loopback(l) || ip6_is_loopback(r);

		const __u8 *lo = local_first ? l : r;
		const __u8 *hi = local_first ? r : l;
#pragma unroll
		for (int i = 0; i < 16; i++) {
			out->lo.ip[i] = lo[i];
			out->hi.ip[i] = hi[i];
		}
	} else {
		__u32 l = bpf_ntohl(ck->local_ip4);
		__u32 r = bpf_ntohl(ck->remote_ip4);
		local_first = l < r ||
			      (l == r && ck->local_port <= ck->remote_port);
		// IPv4 in network order: the first octet is the low byte.
		loopback = (ck->local_ip4 & 0xff) == 127 ||
			   (ck->remote_ip4 & 0xff) == 127;

		__u32 lo4 = local_first ? ck->local_ip4 : ck->remote_ip4;
		__u32 hi4 = local_first ? ck->remote_ip4 : ck->local_ip4;
		__builtin_memcpy(out->lo.ip, &lo4, 4);
		__builtin_memcpy(out->hi.ip, &hi4, 4);
	}

	out->lo.port = local_first ? ck->local_port : ck->remote_port;
	out->hi.port = local_first ? ck->remote_port : ck->local_port;
	if (loopback)
		out->netns = netns;
}

// sock_ctx reads the netns from the kernel socket and reports whether the owning
// container/process passes the active filter. Used on the response side, where
// the combined event is attributed to the stored request/client instead.
static __noinline bool sock_ctx(struct bpf_sock *bsk, __u32 *netns_out)
{
	*netns_out = 0;
	if (!bsk)
		return false;
	struct sock *sk = (struct sock *)bpf_skc_to_tcp_sock(bsk);
	if (!sk)
		return false;
	__u32 netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	*netns_out = netns;
	struct gadget_socket_value *sv = gadget_socket_lookup(sk, netns);
	return !gadget_should_discard_data_by_skb(sv);
}

// fill_endpoints reads the tuple and netns from the kernel socket, assigns
// src/dst so that src is always the sender and dst the receiver (for egress the
// local socket is the sender; for ingress the remote peer is), and enriches with
// the owning process. Returns false if the socket is unavailable or the owning
// container/process is excluded by an active filter.
static __noinline bool fill_endpoints(struct bpf_sock *bsk, __u8 cap_dir,
					   struct combined_event *ev)
{
	if (!bsk)
		return false;
	struct sock *sk = (struct sock *)bpf_skc_to_tcp_sock(bsk);
	if (!sk)
		return false;

	__u32 netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	ev->netns_id = netns;

	// Read the tuple straight into the event's src/dst rather than via stack
	// temporaries: src is always the sender (for egress the local socket, for
	// ingress the remote peer), dst the receiver. Reading directly also avoids
	// a struct-to-struct copy that clang lowers to a prohibited pointer OR.
	struct gadget_l4endpoint_t *localp, *remotep;
	if (cap_dir == CAP_EGRESS) {
		localp = &ev->src; // we sent: local is the sender
		remotep = &ev->dst;
	} else {
		localp = &ev->dst; // we received: remote is the sender
		remotep = &ev->src;
	}
	localp->proto_raw = IPPROTO_TCP;
	remotep->proto_raw = IPPROTO_TCP;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	struct inet_sock *isk = (struct inet_sock *)sk;

	if (family == AF_INET6) {
		localp->version = 6;
		remotep->version = 6;
		BPF_CORE_READ_INTO(&remotep->addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&localp->addr_raw.v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	} else {
		localp->version = 4;
		remotep->version = 4;
		BPF_CORE_READ_INTO(&remotep->addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&localp->addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
	}

	__u16 dport = 0, sport = 0;
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	remotep->port = bpf_ntohs(dport);
	BPF_CORE_READ_INTO(&sport, isk, inet_sport);
	localp->port = bpf_ntohs(sport);

	struct gadget_socket_value *sv = gadget_socket_lookup(sk, netns);
	gadget_process_populate_from_socket(sv, &ev->proc);
	return !gadget_should_discard_data_by_skb(sv);
}

// clamp_len caps a block length to its per-side preview size.
static __always_inline __u32 clamp_len(__u32 len, __u32 max)
{
	return len > max ? max : len;
}

// copy_bounded copies len (capped at max) bytes between two kernel buffers.
// clang cannot inline a variable-length __builtin_memcpy, so use the helper.
static __always_inline void copy_bounded(void *dst, const void *src, __u32 len,
					 __u32 max)
{
	if (len > max)
		len = max;
	if (len == 0)
		return;
	bpf_probe_read_kernel(dst, len, src);
}

// emit_combined assembles one exchange event from a pending entry and outputs it
// on the http datasource: fixed header (attributed to the request/client side)
// followed by the request block then the response block. full=false means the
// response end is unknown (connection-close response or an unpaired request).
static __always_inline void emit_combined(void *ctx, struct event_buf *eb,
					  struct pending *p, bool full,
					  __u32 resp_size, __u64 ts_last)
{
	struct combined_event *ev = &eb->ev;
	__builtin_memset(ev, 0, sizeof(*ev));

	ev->timestamp_raw = p->req_seen ? p->req_ts : p->resp_first_ts;
	ev->src = p->src;
	ev->dst = p->dst;
	ev->netns_id = p->netns;
	ev->proc = p->proc;
	ev->req_hdr_len = p->req_hdr_len;
	ev->req_data_len = p->req_data_len;
	ev->resp_hdr_len = p->resp_hdr_len;
	ev->resp_data_len = p->resp_data_len;
	ev->request_size = p->req_size;
	ev->response_size = full ? resp_size : 0;
	if (p->req_seen && p->resp_seen)
		ev->latency_ttfb_ns = p->resp_first_ts - p->req_ts;
	if (full && p->req_seen)
		ev->latency_total_ns = ts_last - p->req_ts;
	ev->complete = full && p->req_seen && p->resp_seen;

	__u32 rq = clamp_len(p->req_data_len, REQ_PREVIEW);
	__u32 rp = clamp_len(p->resp_data_len, RESP_PREVIEW);
	ev->data_len = rq + rp;
	// Pack the response block immediately after the request block; WASM reads
	// the response at offset req_data_len. rq <= REQ_PREVIEW and
	// rp <= RESP_PREVIEW keep the writes within eb->data (COMBINED_DATA).
	copy_bounded(eb->data, p->req_data, rq, REQ_PREVIEW);
	copy_bounded(eb->data + rq, p->resp_data, rp, RESP_PREVIEW);
	gadget_output_buf(ctx, &events, eb,
			  sizeof(struct combined_event) + rq + rp);
}

// finalize emits the exchange for pk and drops it. full=false for a
// connection-close response or an unpaired request (end/size unknown).
static __always_inline void finalize(void *ctx, struct event_buf *eb,
				     struct pending_key *pk, bool full,
				     __u32 resp_size, __u64 ts_last)
{
	struct pending *p = bpf_map_lookup_elem(&http_pending, pk);
	if (!p)
		return;
	emit_combined(ctx, eb, p, full, resp_size, ts_last);
	bpf_map_delete_elem(&http_pending, pk);
}

// pending_get_or_create returns the pending entry for pk, inserting a zeroed one
// (from the per-CPU seed) if absent so the large value never lives on the stack.
static __always_inline struct pending *pending_get_or_create(struct pending_key *pk)
{
	struct pending *p = bpf_map_lookup_elem(&http_pending, pk);
	if (p)
		return p;
	__u32 zero = 0;
	struct pending *seed = bpf_map_lookup_elem(&http_pending_seed, &zero);
	if (!seed)
		return NULL;
	bpf_map_update_elem(&http_pending, pk, seed, BPF_NOEXIST);
	return bpf_map_lookup_elem(&http_pending, pk);
}

// on_msg_complete records a finished message: for a request it fills in the
// total request size on the pending entry; for a response it finalizes and emits
// the exchange (this is the response-completion hook where a later phase will
// also increment aggregated metrics).
static __always_inline void on_msg_complete(void *ctx, struct event_buf *eb,
					    struct parse_state *st)
{
	struct pending_key pk = { .canon = st->cur_canon, .seq = st->cur_seq };
	__u32 total = st->cur_hdr_len + st->total_body;
	if (st->cur_dir == HTTP_DIR_REQUEST) {
		struct pending *p = bpf_map_lookup_elem(&http_pending, &pk);
		if (p)
			p->req_size = total;
		return;
	}
	finalize(ctx, eb, &pk, true, total, bpf_ktime_get_boot_ns());
}

// load_skb loads up to `len` bytes of a received segment at offset `off` into buf.
static __always_inline __u32 load_skb(struct __sk_buff *skb, __u8 *buf,
				      __u32 off, __u32 len)
{
	if (len > MAX_DATA)
		len = MAX_DATA;
	if (len == 0)
		return 0;
	if (bpf_skb_load_bytes(skb, off, buf, len) < 0)
		return 0;
	return len;
}

// load_msg copies up to `len` bytes of an outgoing message at offset `off` into
// buf. sk_msg has no load-bytes helper, so pull the range linear and copy it in
// one shot with bpf_probe_read_kernel. A per-byte loop over the packet pointer
// explodes the verifier (per-iteration bounds tracking); a single copy stays cheap.
static __always_inline __u32 load_msg(struct sk_msg_md *msg, __u8 *buf,
				      __u32 off, __u32 len)
{
	if (len > MAX_DATA)
		len = MAX_DATA;
	if (len == 0)
		return 0;
	if (bpf_msg_pull_data(msg, off, off + len, 0) < 0)
		return 0;
	if (bpf_probe_read_kernel(buf, len, (const void *)(long)msg->data) < 0)
		return 0;
	return len;
}

static __always_inline __u32 load_at(void *ctx, bool is_skb, __u8 *buf,
				     __u32 off, __u32 len)
{
	if (is_skb)
		return load_skb((struct __sk_buff *)ctx, buf, off, len);
	return load_msg((struct sk_msg_md *)ctx, buf, off, len);
}

// scan_terminator scans buf[0..len) for the chunked terminator "0\r\n\r\n",
// seeding and updating the 4-byte carry in tail[] so a terminator split across
// segments is still found. Returns true when the terminator is seen.
static __noinline bool scan_terminator(const __u8 *buf, __u32 len,
					    __u8 tail[4])
{
	struct tscan ts = {};
	ts.buf = buf;
	ts.len = len > MAX_SCAN ? MAX_SCAN : len;
	ts.t1 = tail[0];
	ts.t2 = tail[1];
	ts.t3 = tail[2];
	ts.t4 = tail[3];
	bpf_loop(ts.len, tscan_cb, &ts, 0);
	tail[0] = ts.t1;
	tail[1] = ts.t2;
	tail[2] = ts.t3;
	tail[3] = ts.t4;
	return ts.found != 0;
}

// drain_load_scan loads the tail of the current segment (where the chunked
// terminator lives) and scans it, updating the carry. Returns true if the
// terminator was found. Loading the tail finds it even when the terminator is
// far past the first MAX_SCAN bytes of a large segment.
static __always_inline bool drain_load_scan(void *ctx, bool is_skb,
					    struct event_buf *eb, __u32 seg_len,
					    __u8 tail[4])
{
	__u32 len = seg_len > MAX_SCAN ? MAX_SCAN : seg_len;
	__u32 off = seg_len - len;
	__u32 loaded = load_at(ctx, is_skb, eb->data, off, len);
	return scan_terminator(eb->data, loaded, tail);
}

// store_message records a just-seen message (headers + body preview already in
// eb->data) into the pending map so its request can later be paired with its
// response. The connection's canonical key is computed and stashed on st for the
// completion hook. Framing continues even when the owner is filtered out; only
// the recording is skipped. ts is the message's start timestamp.
static __noinline void store_message(struct bpf_sock *bsk,
				     struct state_key *skey,
				     struct parse_state *st,
				     struct event_buf *eb, __u32 data_len)
{
	__u32 netns = 0;
	bool keep;
	__u64 ts = bpf_ktime_get_boot_ns();
	struct combined_event *ev = &eb->ev;

	if (st->cur_dir == HTTP_DIR_REQUEST) {
		// The request/client side owns the exchange's enrichment.
		keep = fill_endpoints(bsk, skey->cap_dir, ev);
		netns = ev->netns_id;
	} else {
		keep = sock_ctx(bsk, &netns);
	}

	build_canon_key(&skey->conn, netns, &st->cur_canon);
	if (!keep)
		return;

	struct pending_key pk = { .canon = st->cur_canon, .seq = st->cur_seq };
	struct pending *p = pending_get_or_create(&pk);
	if (!p)
		return;

	if (st->cur_dir == HTTP_DIR_REQUEST) {
		__u32 n = clamp_len(data_len, REQ_PREVIEW);
		p->req_seen = 1;
		p->req_ts = ts;
		p->req_hdr_len = st->cur_hdr_len;
		p->req_data_len = data_len;
		p->netns = netns;
		p->src = ev->src;
		p->dst = ev->dst;
		p->proc = ev->proc;
		copy_bounded(p->req_data, eb->data, n, REQ_PREVIEW);
	} else {
		__u32 n = clamp_len(data_len, RESP_PREVIEW);
		p->resp_seen = 1;
		p->resp_first_ts = ts;
		p->resp_hdr_len = st->cur_hdr_len;
		p->resp_data_len = data_len;
		if (netns && !p->netns)
			p->netns = netns;
		copy_bounded(p->resp_data, eb->data, n, RESP_PREVIEW);
	}
}

// capture_body captures the in-progress message's body sample from the current
// segment when the body was delivered separately from its headers (so no body
// bytes were sampled at header time). It writes a single contiguous run at
// offset hlen: with hlen <= MAX_SCAN and n <= PREVIEW the write always fits
// REQ_PREVIEW (= MAX_SCAN + PREVIEW), which is what keeps the verifier happy.
// No-op unless body capture is enabled for the direction and no body sample was
// taken yet. Captured bytes are raw stream bytes (chunked is de-chunked in WASM).
static __always_inline void capture_body(void *ctx, bool is_skb,
					 struct event_buf *eb,
					 struct parse_state *st, __u32 seg_len)
{
	__u32 maxbody = st->cur_dir == HTTP_DIR_REQUEST ?
				(req_body ? req_body_len : 0) :
				(res_body ? res_body_len : 0);
	if (maxbody > PREVIEW)
		maxbody = PREVIEW; // buffer/stack ceiling
	if (maxbody == 0 || seg_len == 0)
		return;

	struct pending_key pk = { .canon = st->cur_canon, .seq = st->cur_seq };
	struct pending *p = bpf_map_lookup_elem(&http_pending, &pk);
	if (!p)
		return;

	bool is_req = st->cur_dir == HTTP_DIR_REQUEST;
	__u32 hlen = is_req ? p->req_hdr_len : p->resp_hdr_len;
	__u32 dlen = is_req ? p->req_data_len : p->resp_data_len;
	if (dlen > hlen)
		return; // a body sample was already captured at header time

	__u32 n = seg_len < maxbody ? seg_len : maxbody;
	n = load_at(ctx, is_skb, eb->data, 0, n);
	if (n == 0)
		return;
	if (n > PREVIEW)
		n = PREVIEW;

	__u32 off = hlen > MAX_SCAN ? MAX_SCAN : hlen;
	if (is_req) {
		copy_bounded(p->req_data + off, eb->data, n, PREVIEW);
		p->req_data_len = off + n;
	} else {
		copy_bounded(p->resp_data + off, eb->data, n, PREVIEW);
		p->resp_data_len = off + n;
	}
}

// observe runs the per-stream framing state machine, loading only the bytes the
// current phase needs. seg_len is the full segment/message length; is_skb selects
// the load helper. It updates and writes back st.
static __always_inline void observe(void *ctx, struct bpf_sock *bsk,				    __u8 cap_dir, struct state_key *skey,
				    struct parse_state *st, struct event_buf *eb,
				    __u32 seg_len, bool is_skb)
{
	if (seg_len == 0)
		return;

	if (st->phase == PH_SKIP) {
		capture_body(ctx, is_skb, eb, st, seg_len);
		if ((__u64)seg_len < st->skip_remaining) {
			st->skip_remaining -= seg_len;
			st->total_body += seg_len;
		} else {
			st->total_body += st->skip_remaining;
			st->skip_remaining = 0;
			st->phase = PH_HEADERS;
			on_msg_complete(ctx, eb, st);
		}
		return;
	}

	if (st->phase == PH_DRAIN) {
		capture_body(ctx, is_skb, eb, st, seg_len);
		bool done = drain_load_scan(ctx, is_skb, eb, seg_len, st->tail);
		st->total_body += seg_len;
		if (done) {
			st->phase = PH_HEADERS;
			on_msg_complete(ctx, eb, st);
		}
		return;
	}

	// PH_HEADERS: this segment should start a new message. Load its head.
	__u32 hlen = seg_len > MAX_DATA ? MAX_DATA : seg_len;
	__u32 loaded = load_at(ctx, is_skb, eb->data, 0, hlen);
	if (loaded < 4)
		return;
	__u8 dir = classify_start_line(eb->data);
	if (dir == HTTP_DIR_UNKNOWN)
		return; // not a recognisable message start; leave state untouched

	__u32 scan = loaded > MAX_SCAN ? MAX_SCAN : loaded;
	__u32 hdr_end = 0;
	int cl_pos = -1;
	bool is_chunked = false;
	scan_headers(eb->data, scan, &hdr_end, &cl_pos, &is_chunked);
	if (hdr_end == 0)
		return; // headers not complete within this segment (ceiling)

	bool has_cl = false;
	__u32 content_length = 0;
	if (cl_pos >= 0)
		content_length =
			parse_uint_at(eb->data, cl_pos, hdr_end, &has_cl);

	__u32 body_in_seg = seg_len - hdr_end;
	__u32 body_loaded = loaded - hdr_end; // body bytes we actually have

	// Body-sample capture is opt-in per direction and length-limited. Disabled
	// -> preview 0 (headers only), so no body bytes are copied or shipped.
	__u32 maxbody;
	if (dir == HTTP_DIR_REQUEST)
		maxbody = req_body ? req_body_len : 0;
	else
		maxbody = res_body ? res_body_len : 0;
	if (maxbody > PREVIEW)
		maxbody = PREVIEW; // buffer/stack ceiling
	__u32 preview = body_loaded > maxbody ? maxbody : body_loaded;
	__u32 data_len = hdr_end + preview;
	if (data_len > MAX_DATA)
		data_len = MAX_DATA;

	// Start framing a new message.
	__u32 my_seq = st->next_seq;
	st->next_seq++;
	st->cur_seq = my_seq;
	st->cur_dir = dir;
	st->cur_hdr_len = hdr_end;
	st->total_body = body_in_seg;
	st->tail[0] = st->tail[1] = st->tail[2] = st->tail[3] = 0;

	// Record the message (request or response) into the pending map. This
	// also computes and stashes the canonical connection key on st.
	store_message(bsk, skey, st, eb, data_len);

	// Decide how to treat the rest of the body.
	if (has_cl) {
		if (content_length > body_in_seg) {
			st->phase = PH_SKIP;
			st->skip_remaining = content_length - body_in_seg;
		} else {
			st->total_body = content_length;
			st->phase = PH_HEADERS;
			on_msg_complete(ctx, eb, st);
		}
	} else if (is_chunked && dir == HTTP_DIR_RESPONSE) {
		// The chunked body (and its terminator) may already be in this
		// segment. Scan the segment tail before waiting for more: a
		// response written in a single sendmsg completes right here.
		st->phase = PH_DRAIN;
		if (drain_load_scan(ctx, is_skb, eb, seg_len, st->tail)) {
			st->phase = PH_HEADERS;
			on_msg_complete(ctx, eb, st);
		}
	} else if (dir == HTTP_DIR_RESPONSE) {
		// A response with neither Content-Length nor chunked ends only
		// when the connection closes. Emit the exchange now with an
		// unknown total/size, then pass the rest through.
		struct pending_key pk = { .canon = st->cur_canon,
					  .seq = st->cur_seq };
		finalize(ctx, eb, &pk, false, 0, 0);
		st->phase = PH_PASS;
	} else {
		st->phase = PH_HEADERS; // request without a body
		on_msg_complete(ctx, eb, st);
	}
}

// run frames one segment/message for the given capture direction. observe loads
// only the bytes the current phase needs and mutates the parse_state in place.
static __always_inline void run(void *ctx, struct bpf_sock *bsk, __u8 cap_dir,
				struct conn_key *ckey, __u32 seg_len,
				bool is_skb)
{
	struct state_key skey = {};
	skey.conn = *ckey;
	skey.cap_dir = cap_dir;

	__u32 zero = 0;
	struct parse_state *stp = bpf_map_lookup_elem(&http_states, &skey);
	struct parse_state *st = stp;
	if (!st) {
		// New stream: work in the per-CPU scratch (state is too large for
		// the BPF stack) and only promote it into http_states below if the
		// stream actually starts framing HTTP.
		st = bpf_map_lookup_elem(&http_states_scratch, &zero);
		if (!st)
			return;
		__builtin_memset(st, 0, sizeof(*st));
	}

	if (st->phase == PH_PASS)
		return;

	struct event_buf *eb = bpf_map_lookup_elem(&http_scratch, &zero);
	if (!eb)
		return;

	observe(ctx, bsk, cap_dir, &skey, st, eb, seg_len, is_skb);

	// Persist a newly-seen stream only once it has framed something, so plain
	// non-HTTP TCP traffic does not populate http_states. Existing entries are
	// mutated in place and need no write-back.
	if (!stp && (st->phase != PH_HEADERS || st->next_seq != 0))
		bpf_map_update_elem(&http_states, &skey, st, BPF_ANY);
}

SEC("sk_skb/stream_verdict")
int http_verdict(struct __sk_buff *skb)
{
	struct bpf_sock *bsk = skb->sk;
	if (!bsk)
		return SK_PASS;

	struct conn_key key = {};
	build_conn_key(bsk, &key);

	// De-duplication: if the peer socket is on this node its egress already
	// captured this message, so ingress skips it entirely. The peer inserted
	// its own (mirrored) key into the sockhash from sock_ops. A sockhash
	// lookup returns a referenced socket, so release it before returning.
	struct conn_key mirror = {};
	mirror_key(&key, &mirror);
	struct bpf_sock *peer = bpf_map_lookup_elem(&http_sockhash, &mirror);
	if (peer) {
		bpf_sk_release(peer);
		return SK_PASS;
	}

	run(skb, bsk, CAP_INGRESS, &key, skb->len, true);
	return SK_PASS;
}

SEC("sk_msg")
int http_msg(struct sk_msg_md *msg)
{
	struct bpf_sock *bsk = msg->sk;
	if (!bsk)
		return SK_PASS;

	struct conn_key key = {};
	build_conn_key(bsk, &key);

	// Egress always captures (it is the canonical side for what a socket sends).
	run(msg, bsk, CAP_EGRESS, &key, msg->size, false);
	return SK_PASS;
}

// flush_ctx carries the state a close flush needs across the bounded loop.
struct flush_ctx {
	void *ctx;
	struct event_buf *eb;
	struct canon_key canon;
	__u32 base;
};

// flush_cb emits any still-pending request at seq base+i as a request-only row
// and drops it. Finalized exchanges were already deleted, so their lookups miss.
static long flush_cb(__u32 i, void *c)
{
	struct flush_ctx *fc = c;
	struct pending_key pk = { .canon = fc->canon, .seq = fc->base + i };
	struct pending *p = bpf_map_lookup_elem(&http_pending, &pk);
	if (p && p->req_seen)
		finalize(fc->ctx, fc->eb, &pk, false, 0, 0);
	return 0;
}

// close_flush emits request-only rows for requests still awaiting a response when
// a framed connection closes. It scans only the most recent FLUSH_WINDOW request
// seqs (in-flight requests are recent) and then drops the framing state.
static __always_inline void close_flush(struct bpf_sock *bsk,
					struct conn_key *ckey)
{
	struct state_key in = { .conn = *ckey, .cap_dir = CAP_INGRESS };
	struct state_key eg = { .conn = *ckey, .cap_dir = CAP_EGRESS };
	struct parse_state *sin = bpf_map_lookup_elem(&http_states, &in);
	struct parse_state *seg = bpf_map_lookup_elem(&http_states, &eg);

	// next_seq counts the requests seen on this connection; it stays 0 for a
	// TCP connection we never framed. Each null check is kept separate so clang
	// does not fold them into a prohibited OR of the two map-value pointers.
	__u32 next = 0;
	if (sin && sin->next_seq > next)
		next = sin->next_seq;
	if (seg && seg->next_seq > next)
		next = seg->next_seq;

	if (next > 0) {
		__u32 netns = 0;
		sock_ctx(bsk, &netns); // netns for the key; filter result unused
		struct canon_key canon;
		build_canon_key(ckey, netns, &canon);

		__u32 zero = 0;
		struct event_buf *eb = bpf_map_lookup_elem(&http_scratch, &zero);
		if (eb) {
			__u32 window =
				next > FLUSH_WINDOW ? FLUSH_WINDOW : next;
			struct flush_ctx fc = { .ctx = bsk,
						.eb = eb,
						.canon = canon,
						.base = next - window };
			bpf_loop(window, flush_cb, &fc, 0);
		}
	}

	bpf_map_delete_elem(&http_states, &in);
	bpf_map_delete_elem(&http_states, &eg);
}

SEC("sockops")
int http_sockops(struct bpf_sock_ops *skops)
{
	if (skops->family != AF_INET && skops->family != AF_INET6)
		return 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		struct bpf_sock *bsk = skops->sk;
		if (!bsk)
			break;
		struct conn_key key = {};
		build_conn_key(bsk, &key);
		bpf_sock_hash_update(skops, &http_sockhash, &key, BPF_NOEXIST);
		// Ask to be called again on state changes so we can flush on close.
		bpf_sock_ops_cb_flags_set(skops,
					  skops->bpf_sock_ops_cb_flags |
						  BPF_SOCK_OPS_STATE_CB_FLAG);
		break;
	}
	case BPF_SOCK_OPS_STATE_CB: {
		// args[1] is the new TCP state.
		if (skops->args[1] != BPF_TCP_CLOSE)
			break;
		struct bpf_sock *bsk = skops->sk;
		if (!bsk)
			break;
		struct conn_key key = {};
		build_conn_key(bsk, &key);
		close_flush(bsk, &key);
		break;
	}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
