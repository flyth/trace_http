// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 The Inspektor Gadget authors */

// trace_http extracts HTTP/1.x requests and responses from TCP connections.
//
// It is built from two eBPF programs wired to a sockhash:
//
//   - a sock_ops program, attached to the cgroup-v2 root, adds every established
//     TCP socket to the sockhash;
//   - an sk_skb stream_verdict program processes the data received on those
//     sockets. It always returns SK_PASS, so the application's traffic is
//     delivered untouched; the program only observes it.
//
// The verdict keeps a small amount of per-connection state so it can frame HTTP
// messages and bound how much data reaches user space. On the segment that
// begins a message it forwards the header block plus up to 1024 bytes of the
// body; it then reads the Content-Length and skips the remaining body bytes,
// which are delivered to the application but never copied out. This keeps the
// volume sent to user space proportional to the number of messages, not to the
// size of their bodies.
//
// sk_skb programs only see the data a socket receives. Because both the client
// and the server sockets are in the sockhash, requests are observed on the
// server's receive side and responses on the client's; the direction of each
// message is determined by parsing its start line.
//
// The eBPF side finds the end of the header block, reads the Content-Length and
// detects chunked transfer-encoding; the accompanying WASM module parses the
// forwarded header bytes into structured fields (method, path, status, Host,
// versions, body preview).
//
// Limitations: the body preview is only captured when the body shares the
// segment with the headers; after a chunked or length-less response the
// connection is passed through without further capture; and a request pipelined
// into the same segment as a previous body may be missed. Capturing data a
// socket sends (rather than receives) would require an additional sk_msg program.

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

// MAX_SCAN bounds header scanning, PREVIEW bounds the body preview, MAX_DATA
// bounds the forwarded event payload.
#define MAX_SCAN 1024
#define PREVIEW 1024
#define MAX_DATA (MAX_SCAN + PREVIEW)

#define HTTP_DIR_UNKNOWN 0
#define HTTP_DIR_REQUEST 1
#define HTTP_DIR_RESPONSE 2

enum http_phase : __u8 {
	PH_HEADERS = 0, // expecting the start of a message
	PH_SKIP = 1, // skipping skip_remaining body bytes
	PH_PASS = 2, // pass the rest of the connection through untouched
};

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

struct parse_state {
	enum http_phase phase;
	__u32 skip_remaining;
};

struct http_event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	gadget_netns_id netns_id;
	struct gadget_process proc;
	__u8 direction_raw;
	__u8 pad[3];
	__u32 hdr_len; // length of the header block within data
	__u32 data_len; // total bytes appended after this struct
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
	__type(key, struct conn_key);
	__type(value, struct parse_state);
} http_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_buf);
} http_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[MAX_SCAN]);
} http_parse_scratch SEC(".maps");

GADGET_TRACER_MAP(events, 1 << 24);
GADGET_TRACER(http, events, http_event);

static __always_inline __u8 to_lower(__u8 c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	return c;
}

// pfx8 reports whether the first bytes of b match the lowercase needle n of
// length nl (nl <= 8). b must be at least 8 bytes.
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
// rather than unrolling per iteration. This is what makes matching several
// patterns in a single pass affordable. Each match uses a 4-byte shift register
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
// "nked" (for example "ranked"); this is vanishingly rare in real HTTP, and a
// Content-Length match is confirmed by parsing digits after it.
static __always_inline void scan_headers(const __u8 *buf, __u32 len,
					 __u32 *hdr_end, int *cl_pos,
					 bool *chunked)
{
	struct hscan s = {};
	s.buf = buf;
	s.len = len;
	s.cl_pos = -1;
	// Variable count so the verifier does not inline the loop (which would
	// unroll it and defeat the point).
	bpf_loop(len, hscan_cb, &s, 0);
	*hdr_end = s.hdr_end;
	*cl_pos = s.cl_pos;
	*chunked = s.chunked != 0;
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

// fill_from_socket reads the connection tuple and network namespace from the
// kernel socket and, using the socket-enricher map, the process that owns it.
// For received data src is the remote peer (the socket's destination) and dst is
// the local end (the socket's source). It returns true if the event should be
// kept: false means the socket is unavailable or the owning container/process is
// excluded by an active filter (--containername, --podname, --pid, --comm, ...).
static __always_inline bool fill_from_socket(struct __sk_buff *skb,
					     struct http_event *ev)
{
	struct bpf_sock *bsk = skb->sk;
	if (!bsk)
		return false;
	struct sock *sk = (struct sock *)bpf_skc_to_tcp_sock(bsk);
	if (!sk)
		return false;

	ev->src.proto_raw = IPPROTO_TCP;
	ev->dst.proto_raw = IPPROTO_TCP;

	__u32 netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	ev->netns_id = netns;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	struct inet_sock *isk = (struct inet_sock *)sk;

	if (family == AF_INET6) {
		ev->src.version = 6;
		ev->dst.version = 6;
		BPF_CORE_READ_INTO(&ev->src.addr_raw.v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&ev->dst.addr_raw.v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	} else {
		ev->src.version = 4;
		ev->dst.version = 4;
		BPF_CORE_READ_INTO(&ev->src.addr_raw.v4, sk,
				   __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&ev->dst.addr_raw.v4, sk,
				   __sk_common.skc_rcv_saddr);
	}

	__u16 dport = 0, sport = 0;
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	ev->src.port = bpf_ntohs(dport); // remote peer
	BPF_CORE_READ_INTO(&sport, isk, inet_sport);
	ev->dst.port = bpf_ntohs(sport); // local

	// Enrich with the owning process/container via the socket enricher, and
	// apply the container/process filters against that owner.
	struct gadget_socket_value *sv = gadget_socket_lookup(sk, netns);
	gadget_process_populate_from_socket(sv, &ev->proc);
	return !gadget_should_discard_data_by_skb(sv);
}

static __always_inline void build_key(struct __sk_buff *skb,
				      struct conn_key *key)
{
	struct bpf_sock *sk = skb->sk;
	if (!sk)
		return;

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

static __always_inline __u32 load_scan(struct __sk_buff *skb, __u8 *buf)
{
	__u32 load_len = skb->len;
	if (load_len > MAX_SCAN)
		load_len = MAX_SCAN;
	if (load_len == 0)
		return 0;
	if (bpf_skb_load_bytes(skb, 0, buf, load_len) < 0)
		return 0;
	return load_len;
}

// handle_verdict runs per received segment (no stream parser, so no strparser
// reassembly — which was breaking keep-alive delivery). It keeps per-connection
// state to frame messages: on a message start it forwards the headers plus up to
// 1024 body bytes, then skips the rest of the body so body data is delivered to
// the application (SK_PASS) but never copied to user space. This is what keeps
// the traffic volume to user space bounded.
static __always_inline void handle_verdict(struct __sk_buff *skb)
{
	struct conn_key key = {};
	build_key(skb, &key);

	struct parse_state *stp = bpf_map_lookup_elem(&http_states, &key);
	struct parse_state st;
	if (stp) {
		st = *stp;
	} else {
		st.phase = PH_HEADERS;
		st.skip_remaining = 0;
	}

	__u32 seg_len = skb->len;
	if (seg_len == 0)
		return;

	if (st.phase == PH_PASS)
		return;

	if (st.phase == PH_SKIP) {
		// Body bytes: consumed here, not copied to user space.
		if ((__u64)seg_len < st.skip_remaining) {
			st.skip_remaining -= seg_len;
		} else {
			// If this segment also carries the start of the next
			// message, it is picked up on the following segment.
			st.skip_remaining = 0;
			st.phase = PH_HEADERS;
		}
		bpf_map_update_elem(&http_states, &key, &st, BPF_ANY);
		return;
	}

	// PH_HEADERS: this segment should start a new message.
	__u32 zero = 0;
	struct event_buf *eb = bpf_map_lookup_elem(&http_scratch, &zero);
	if (!eb)
		return;

	__u32 load_len = seg_len;
	if (load_len > MAX_DATA)
		load_len = MAX_DATA;
	if (bpf_skb_load_bytes(skb, 0, eb->data, load_len) < 0)
		return;

	__u8 dir = classify_start_line(eb->data);
	if (dir == HTTP_DIR_UNKNOWN)
		return; // not a recognisable message start; leave state untouched

	__u32 scan = load_len > MAX_SCAN ? MAX_SCAN : load_len;
	__u32 hdr_end = 0;
	int cl_pos = -1;
	bool is_chunked = false;
	scan_headers(eb->data, scan, &hdr_end, &cl_pos, &is_chunked);
	if (hdr_end == 0)
		return; // headers not complete within this segment (ceiling)

	bool has_cl = false;
	__u32 content_length = 0;
	if (cl_pos >= 0)
		content_length = parse_uint_at(eb->data, cl_pos, hdr_end, &has_cl);

	__u32 body_in_seg = load_len - hdr_end;
	__u32 preview = body_in_seg > PREVIEW ? PREVIEW : body_in_seg;
	__u32 data_len = hdr_end + preview;
	if (data_len > MAX_DATA)
		data_len = MAX_DATA;

	struct http_event *ev = &eb->ev;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->timestamp_raw = bpf_ktime_get_boot_ns();
	ev->direction_raw = dir;
	ev->hdr_len = hdr_end;
	ev->data_len = data_len;
	// Fill endpoints, netns and the owning process, and drop the event if the
	// connection's container/process is excluded by a filter. Framing (below)
	// still runs so body bytes are skipped regardless.
	if (fill_from_socket(skb, ev))
		gadget_output_buf(skb, &events, eb,
				  sizeof(struct http_event) + data_len);

	// Decide how to treat the rest of the body so it isn't copied to user space.
	if (has_cl) {
		if (content_length > body_in_seg) {
			st.phase = PH_SKIP;
			st.skip_remaining = content_length - body_in_seg;
		} else {
			st.phase = PH_HEADERS; // whole body already in this segment
		}
	} else if (is_chunked || dir == HTTP_DIR_RESPONSE) {
		// No length to frame by (chunked, or a response whose body runs
		// until the connection closes): stop emitting on this connection.
		st.phase = PH_PASS;
	} else {
		st.phase = PH_HEADERS; // request without a body
	}
	bpf_map_update_elem(&http_states, &key, &st, BPF_ANY);
}

SEC("sk_skb/stream_verdict")
int http_verdict(struct __sk_buff *skb)
{
	handle_verdict(skb);
	return SK_PASS;
}

SEC("sockops")
int http_sockops(struct bpf_sock_ops *skops)
{
	if (skops->family != AF_INET && skops->family != AF_INET6)
		return 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		struct conn_key key = {};
		key.family = (__u8)skops->family;
		key.local_port = (__u16)skops->local_port;
		key.remote_port = (__u16)skops->remote_port;
		if (skops->family == AF_INET6) {
			key.local_ip6[0] = skops->local_ip6[0];
			key.local_ip6[1] = skops->local_ip6[1];
			key.local_ip6[2] = skops->local_ip6[2];
			key.local_ip6[3] = skops->local_ip6[3];
			key.remote_ip6[0] = skops->remote_ip6[0];
			key.remote_ip6[1] = skops->remote_ip6[1];
			key.remote_ip6[2] = skops->remote_ip6[2];
			key.remote_ip6[3] = skops->remote_ip6[3];
		} else {
			key.local_ip4 = skops->local_ip4;
			key.remote_ip4 = skops->remote_ip4;
		}
		bpf_sock_hash_update(skops, &http_sockhash, &key, BPF_NOEXIST);
		break;
	}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
