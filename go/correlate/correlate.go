// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package correlate joins the per-message HTTP markers emitted by the eBPF
// program into one event per request/response exchange, deriving latency and
// sizes. It holds only in-flight exchanges and is bounded by an idle timeout and
// a hard cap, so memory does not grow under load. It has no wasmapi dependency
// so it can be unit-tested on the host.
package correlate

import (
	"strconv"
	"strings"
)

// Marker kinds, mirroring the eBPF msg_type field.
const (
	KindHeaders  uint8 = 0
	KindComplete uint8 = 1
	KindClose    uint8 = 2
)

// HTTP directions, mirroring the eBPF direction_raw field.
const (
	DirRequest  uint8 = 1
	DirResponse uint8 = 2
)

// Endpoint is one end of a connection.
type Endpoint struct {
	Addr string
	Port uint16
}

func (e Endpoint) String() string {
	return e.Addr + ":" + strconv.FormatUint(uint64(e.Port), 10)
}

// Event is one eBPF marker fed into the correlator.
type Event struct {
	Kind     uint8
	HTTPDir  uint8
	Seq      uint32
	Ts       uint64
	Src      Endpoint // sender
	Dst      Endpoint // receiver
	Netns    uint64
	Mntns    uint64
	Comm     string
	Pid      uint32
	Tid      uint32
	TotalLen uint32 // KindComplete: total message bytes

	// Parsed header fields (KindHeaders).
	Method      string
	Path        string
	HTTPVersion string
	Host        string
	StatusCode  uint16
	HasCL       bool
	Chunked     bool
	Websocket   bool
	Body        []byte
}

// Exchange is one correlated request/response pair (or an unpaired request).
type Exchange struct {
	Ts    uint64 // request start
	Src   Endpoint
	Dst   Endpoint
	Netns uint64
	Mntns uint64
	Comm  string
	Pid   uint32
	Tid   uint32

	Method      string
	Path        string
	HTTPVersion string
	Host        string
	StatusCode  uint16

	ReqSize  uint32
	RespSize uint32
	TTFBns   uint64 // response first byte - request start
	Totalns  uint64 // response last byte - request start (0 if unknown)

	ReqBody   []byte
	RespBody  []byte
	Chunked   bool
	Websocket bool

	Complete bool // false = request-only (no response captured)
}

type reqInfo struct {
	ts          uint64
	method      string
	path        string
	httpVersion string
	host        string
	size        uint32
	body        []byte
	src, dst    Endpoint
	netns       uint64
	mntns       uint64
	comm        string
	pid, tid    uint32
}

type respInfo struct {
	tsFirst   uint64
	status    uint16
	chunked   bool
	websocket bool
	body      []byte
}

type conn struct {
	reqs     map[uint32]*reqInfo
	resps    map[uint32]*respInfo
	lastSeen uint64
}

// Correlator joins markers into exchanges. Not safe for concurrent use; the WASM
// data path is single-threaded.
type Correlator struct {
	conns      map[string]*conn
	emit       func(Exchange)
	idleNs     uint64
	maxPending int
	pending    int
	lastSweep  uint64
}

// New returns a correlator. idleNs is how long a pending exchange may sit before
// it is flushed as a request-only row; maxPending caps the number of in-flight
// requests held (oldest connections are flushed when exceeded). emit is called
// once per finished exchange.
func New(emit func(Exchange), idleNs uint64, maxPending int) *Correlator {
	return &Correlator{
		conns:      make(map[string]*conn),
		emit:       emit,
		idleNs:     idleNs,
		maxPending: maxPending,
	}
}

// isLoopback reports whether addr is an IPv4/IPv6 loopback address.
func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1"
}

// canonKey builds a connection identity that is identical for both mirrored
// captures of one connection: the request seen as client->server and the
// response seen as server->client normalise to the same key. netns is included
// only for loopback, where distinct connections can share a 4-tuple across
// namespaces but both captures share one netns; for routed traffic the pod IPs
// are globally unique and the two captures may be in different netns.
func canonKey(a, b Endpoint, netns uint64) string {
	ka, kb := a.String(), b.String()
	if ka > kb {
		ka, kb = kb, ka
	}
	key := ka + "|" + kb
	if isLoopback(a.Addr) || isLoopback(b.Addr) {
		key += "|" + strconv.FormatUint(netns, 10)
	}
	return key
}

func (c *Correlator) getConn(key string) *conn {
	cn := c.conns[key]
	if cn == nil {
		cn = &conn{reqs: make(map[uint32]*reqInfo), resps: make(map[uint32]*respInfo)}
		c.conns[key] = cn
	}
	return cn
}

// Process feeds one marker into the correlator.
func (c *Correlator) Process(e Event) {
	c.sweep(e.Ts)

	if e.Kind == KindClose {
		key := canonKey(e.Src, e.Dst, e.Netns)
		if cn := c.conns[key]; cn != nil {
			c.flushConn(cn)
			delete(c.conns, key)
		}
		return
	}

	key := canonKey(e.Src, e.Dst, e.Netns)
	cn := c.getConn(key)
	cn.lastSeen = e.Ts

	switch e.Kind {
	case KindHeaders:
		if e.HTTPDir == DirRequest {
			cn.reqs[e.Seq] = &reqInfo{
				ts:          e.Ts,
				method:      e.Method,
				path:        e.Path,
				httpVersion: e.HTTPVersion,
				host:        e.Host,
				body:        e.Body,
				src:         e.Src,
				dst:         e.Dst,
				netns:       e.Netns,
				mntns:       e.Mntns,
				comm:        e.Comm,
				pid:         e.Pid,
				tid:         e.Tid,
			}
			c.pending++
			c.enforceCap()
		} else if e.HTTPDir == DirResponse {
			cn.resps[e.Seq] = &respInfo{
				tsFirst:   e.Ts,
				status:    e.StatusCode,
				chunked:   e.Chunked,
				websocket: e.Websocket,
				body:      e.Body,
			}
			// A response with neither Content-Length nor chunked framing
			// ends only on connection close: no completion marker will
			// arrive, so finalise now with partial timing/size.
			if !e.HasCL && !e.Chunked {
				c.finalize(cn, e.Seq, e.Ts, 0, false)
			}
		}
	case KindComplete:
		if e.HTTPDir == DirRequest {
			if ri := cn.reqs[e.Seq]; ri != nil {
				ri.size = e.TotalLen
			}
		} else if e.HTTPDir == DirResponse {
			c.finalize(cn, e.Seq, e.Ts, e.TotalLen, true)
		}
	}
}

// finalize pairs request[seq] with response[seq], emits the exchange and drops
// the state. full is false for connection-close responses (no known end).
func (c *Correlator) finalize(cn *conn, seq uint32, tsLast uint64, respSize uint32, full bool) {
	rs := cn.resps[seq]
	if rs == nil {
		return
	}
	ri := cn.reqs[seq]

	ex := Exchange{
		StatusCode: rs.status,
		RespBody:   rs.body,
		Chunked:    rs.chunked,
		Websocket:  rs.websocket,
		Complete:   full && ri != nil,
	}
	if full {
		ex.RespSize = respSize
	}
	if ri != nil {
		ex.Ts = ri.ts
		ex.Src = ri.src
		ex.Dst = ri.dst
		ex.Netns = ri.netns
		ex.Mntns = ri.mntns
		ex.Comm = ri.comm
		ex.Pid = ri.pid
		ex.Tid = ri.tid
		ex.Method = ri.method
		ex.Path = ri.path
		ex.HTTPVersion = ri.httpVersion
		ex.Host = ri.host
		ex.ReqSize = ri.size
		ex.ReqBody = ri.body
		ex.TTFBns = rs.tsFirst - ri.ts
		if full {
			ex.Totalns = tsLast - ri.ts
		}
		c.pending--
		delete(cn.reqs, seq)
	} else {
		// Response without a captured request: still report it.
		ex.Ts = rs.tsFirst
	}
	delete(cn.resps, seq)
	c.emit(ex)
}

// flushConn emits every still-pending request in cn as a request-only row.
func (c *Correlator) flushConn(cn *conn) {
	for seq, ri := range cn.reqs {
		c.emit(Exchange{
			Ts:          ri.ts,
			Src:         ri.src,
			Dst:         ri.dst,
			Netns:       ri.netns,
			Mntns:       ri.mntns,
			Comm:        ri.comm,
			Pid:         ri.pid,
			Tid:         ri.tid,
			Method:      ri.method,
			Path:        ri.path,
			HTTPVersion: ri.httpVersion,
			Host:        ri.host,
			ReqSize:     ri.size,
			ReqBody:     ri.body,
			Complete:    false,
		})
		c.pending--
		delete(cn.reqs, seq)
	}
}

// sweep flushes connections idle for longer than idleNs. It runs at most once per
// idleNs of event time so it stays cheap on the hot path.
func (c *Correlator) sweep(now uint64) {
	if c.idleNs == 0 || now < c.lastSweep+c.idleNs {
		return
	}
	c.lastSweep = now
	for key, cn := range c.conns {
		if now-cn.lastSeen > c.idleNs {
			c.flushConn(cn)
			delete(c.conns, key)
		}
	}
}

// enforceCap keeps the number of in-flight requests bounded by flushing the
// least-recently-seen connection when the cap is exceeded. Eviction is coarse
// (whole-connection) rather than per-request, which is enough to bound memory.
func (c *Correlator) enforceCap() {
	for c.maxPending > 0 && c.pending > c.maxPending {
		var oldestKey string
		var oldest *conn
		for key, cn := range c.conns {
			if oldest == nil || cn.lastSeen < oldest.lastSeen {
				oldestKey, oldest = key, cn
			}
		}
		if oldest == nil {
			return
		}
		c.flushConn(oldest)
		delete(c.conns, oldestKey)
	}
}

// Flush emits all remaining pending requests as request-only rows. Call on
// gadget stop. Under normal operation close/idle handling keeps this near-empty.
func (c *Correlator) Flush() {
	for key, cn := range c.conns {
		c.flushConn(cn)
		delete(c.conns, key)
	}
}
