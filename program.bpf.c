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
// For each framed message the program forwards, on its first segment, the header
// block plus a bounded body preview (MSG_HEADERS), then bounds how much of the
// body reaches user space. When the body finishes (Content-Length reached or the
// chunked terminator seen) it emits a small MSG_COMPLETE marker carrying the
// final timestamp and byte count. sock_ops emits MSG_CLOSE on connection close.
// The accompanying WASM module joins request+response into one event and derives
// latency and sizes; the eBPF side only frames and times.

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

// HTTP message direction, derived from the start line.
#define HTTP_DIR_UNKNOWN 0
#define HTTP_DIR_REQUEST 1
#define HTTP_DIR_RESPONSE 2

// Capture path: which side observed the bytes. Also selects the framing-state
// slot so the two streams on one socket frame independently.
#define CAP_INGRESS 0
#define CAP_EGRESS 1

// Event kind.
#define MSG_HEADERS 0 // start of a message: headers + body preview
#define MSG_COMPLETE 1 // a message body finished: final timestamp + byte count
#define MSG_CLOSE 2 // the connection closed

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
};

struct http_event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src; // sender
	struct gadget_l4endpoint_t dst; // receiver
	gadget_netns_id netns_id;
	struct gadget_process proc;
	__u8 msg_type; // MSG_HEADERS / MSG_COMPLETE / MSG_CLOSE
	__u8 direction_raw; // HTTP request/response (HEADERS, COMPLETE)
	__u8 cap_dir; // capture path (ingress/egress), for correlation/debug
	__u8 pad;
	__u32 seq; // per-stream sequence number, pairs request[N] with response[N]
	__u32 hdr_len; // length of the header block within data (HEADERS)
	__u32 data_len; // bytes appended after this struct (HEADERS)
	__u32 total_len; // total message bytes: headers + body (COMPLETE)
};

struct event_buf {
	struct http_event ev;
	__u8 data[MAX_DATA];
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_buf);
} http_scratch SEC(".maps");

GADGET_TRACER_MAP(events, 1 << 24);
GADGET_TRACER(http_msg, events, http_event);

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
static __always_inline void scan_headers(const __u8 *buf, __u32 len,
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

// fill_endpoints reads the tuple and netns from the kernel socket, assigns
// src/dst so that src is always the sender and dst the receiver (for egress the
// local socket is the sender; for ingress the remote peer is), and enriches with
// the owning process. Returns false if the socket is unavailable or the owning
// container/process is excluded by an active filter.
static __always_inline bool fill_endpoints(struct bpf_sock *bsk, __u8 cap_dir,
					   struct http_event *ev)
{
	if (!bsk)
		return false;
	struct sock *sk = (struct sock *)bpf_skc_to_tcp_sock(bsk);
	if (!sk)
		return false;

	__u32 netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	ev->netns_id = netns;

	struct gadget_l4endpoint_t local = {}, remote = {};
	local.proto_raw = IPPROTO_TCP;
	remote.proto_raw = IPPROTO_TCP;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	struct inet_sock *isk = (struct inet_sock *)sk;

	if (family == AF_INET6) {
		local.version = 6;
		remote.version = 6;
		BPF_CORE_READ_INTO(&remote.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&local.addr_raw.v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	} else {
		local.version = 4;
		remote.version = 4;
		BPF_CORE_READ_INTO(&remote.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&local.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
	}

	__u16 dport = 0, sport = 0;
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	remote.port = bpf_ntohs(dport);
	BPF_CORE_READ_INTO(&sport, isk, inet_sport);
	local.port = bpf_ntohs(sport);

	if (cap_dir == CAP_EGRESS) {
		ev->src = local; // we sent: local is the sender
		ev->dst = remote;
	} else {
		ev->src = remote; // we received: remote is the sender
		ev->dst = local;
	}

	struct gadget_socket_value *sv = gadget_socket_lookup(sk, netns);
	gadget_process_populate_from_socket(sv, &ev->proc);
	return !gadget_should_discard_data_by_skb(sv);
}

// emit_complete sends a small MSG_COMPLETE marker for the message that just
// finished: its final timestamp, sequence number and total byte count. WASM uses
// it to compute time-to-full-response and message size.
static __always_inline void emit_complete(void *ctx, struct bpf_sock *bsk,
					  __u8 cap_dir, struct event_buf *eb,
					  struct parse_state *st)
{
	struct http_event *ev = &eb->ev;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->timestamp_raw = bpf_ktime_get_boot_ns();
	ev->msg_type = MSG_COMPLETE;
	ev->direction_raw = st->cur_dir;
	ev->cap_dir = cap_dir;
	ev->seq = st->cur_seq;
	ev->total_len = st->cur_hdr_len + st->total_body;
	if (fill_endpoints(bsk, cap_dir, ev))
		gadget_output_buf(ctx, &events, eb, sizeof(struct http_event));
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
static __always_inline bool scan_terminator(const __u8 *buf, __u32 len,
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

// observe runs the per-stream framing state machine, loading only the bytes the
// current phase needs. seg_len is the full segment/message length; is_skb selects
// the load helper. It updates and writes back st.
static __always_inline void observe(void *ctx, struct bpf_sock *bsk,
				    __u8 cap_dir, struct state_key *skey,
				    struct parse_state *st, struct event_buf *eb,
				    __u32 seg_len, bool is_skb)
{
	if (seg_len == 0)
		return;

	if (st->phase == PH_SKIP) {
		if ((__u64)seg_len < st->skip_remaining) {
			st->skip_remaining -= seg_len;
			st->total_body += seg_len;
		} else {
			st->total_body += st->skip_remaining;
			st->skip_remaining = 0;
			st->phase = PH_HEADERS;
			emit_complete(ctx, bsk, cap_dir, eb, st);
		}
		bpf_map_update_elem(&http_states, skey, st, BPF_ANY);
		return;
	}

	if (st->phase == PH_DRAIN) {
		bool done = drain_load_scan(ctx, is_skb, eb, seg_len, st->tail);
		st->total_body += seg_len;
		if (done) {
			st->phase = PH_HEADERS;
			emit_complete(ctx, bsk, cap_dir, eb, st);
		}
		bpf_map_update_elem(&http_states, skey, st, BPF_ANY);
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
	__u32 preview = body_loaded > PREVIEW ? PREVIEW : body_loaded;
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

	struct http_event *ev = &eb->ev;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->timestamp_raw = bpf_ktime_get_boot_ns();
	ev->msg_type = MSG_HEADERS;
	ev->direction_raw = dir;
	ev->cap_dir = cap_dir;
	ev->seq = my_seq;
	ev->hdr_len = hdr_end;
	ev->data_len = data_len;
	if (fill_endpoints(bsk, cap_dir, ev))
		gadget_output_buf(ctx, &events, eb,
				  sizeof(struct http_event) + data_len);

	// Decide how to treat the rest of the body.
	if (has_cl) {
		if (content_length > body_in_seg) {
			st->phase = PH_SKIP;
			st->skip_remaining = content_length - body_in_seg;
		} else {
			st->total_body = content_length;
			st->phase = PH_HEADERS;
			emit_complete(ctx, bsk, cap_dir, eb, st);
		}
	} else if (is_chunked && dir == HTTP_DIR_RESPONSE) {
		// The chunked body (and its terminator) may already be in this
		// segment. Scan the segment tail before waiting for more: a
		// response written in a single sendmsg completes right here.
		st->phase = PH_DRAIN;
		if (drain_load_scan(ctx, is_skb, eb, seg_len, st->tail)) {
			st->phase = PH_HEADERS;
			emit_complete(ctx, bsk, cap_dir, eb, st);
		}
	} else if (dir == HTTP_DIR_RESPONSE) {
		// A response with neither Content-Length nor chunked ends only
		// when the connection closes: no in-stream marker to frame by.
		st->phase = PH_PASS;
	} else {
		st->phase = PH_HEADERS; // request without a body
		emit_complete(ctx, bsk, cap_dir, eb, st);
	}
	bpf_map_update_elem(&http_states, skey, st, BPF_ANY);
}

// run frames one segment/message for the given capture direction. observe loads
// only the bytes the current phase needs.
static __always_inline void run(void *ctx, struct bpf_sock *bsk, __u8 cap_dir,
				struct conn_key *ckey, __u32 seg_len,
				bool is_skb)
{
	struct state_key skey = {};
	skey.conn = *ckey;
	skey.cap_dir = cap_dir;

	struct parse_state *stp = bpf_map_lookup_elem(&http_states, &skey);
	struct parse_state st;
	if (stp)
		st = *stp;
	else
		__builtin_memset(&st, 0, sizeof(st));

	if (st.phase == PH_PASS)
		return;

	__u32 zero = 0;
	struct event_buf *eb = bpf_map_lookup_elem(&http_scratch, &zero);
	if (!eb)
		return;

	observe(ctx, bsk, cap_dir, &skey, &st, eb, seg_len, is_skb);
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

// emit_close signals that a connection we have framed has closed, so user space
// can flush any request still waiting for its response. Only connections with
// framing state emit a close, which bounds these events to HTTP connections
// rather than every TCP close on the host.
static __always_inline void emit_close(struct bpf_sock *bsk,
				       struct conn_key *ckey)
{
	struct state_key in = { .conn = *ckey, .cap_dir = CAP_INGRESS };
	struct state_key eg = { .conn = *ckey, .cap_dir = CAP_EGRESS };
	bool tracked = bpf_map_lookup_elem(&http_states, &in) ||
		       bpf_map_lookup_elem(&http_states, &eg);
	if (!tracked)
		return;

	__u32 zero = 0;
	struct event_buf *eb = bpf_map_lookup_elem(&http_scratch, &zero);
	if (!eb)
		return;
	struct http_event *ev = &eb->ev;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->timestamp_raw = bpf_ktime_get_boot_ns();
	ev->msg_type = MSG_CLOSE;
	// cap_dir is irrelevant for a close; endpoints let WASM derive the
	// canonical connection.
	if (fill_endpoints(bsk, CAP_EGRESS, ev))
		gadget_output_buf(bsk, &events, eb, sizeof(struct http_event));

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
		emit_close(bsk, &key);
		break;
	}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
