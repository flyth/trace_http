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

package correlate

import "testing"

var (
	client = Endpoint{Addr: "127.0.0.1", Port: 42940}
	server = Endpoint{Addr: "127.0.0.1", Port: 8088}
)

// The request (client->server) and its mirrored response (server->client) must
// normalise to the same connection key, or correlation cannot pair them.
func TestCanonKeyMirrorEqual(t *testing.T) {
	reqKey := canonKey(client, server, 100)  // request: src=client, dst=server
	respKey := canonKey(server, client, 100) // response: src=server, dst=client
	if reqKey != respKey {
		t.Fatalf("mirror keys differ: %q vs %q", reqKey, respKey)
	}
}

// Two loopback connections that share a 4-tuple but live in different netns must
// not collide.
func TestCanonKeyLoopbackNetnsDistinct(t *testing.T) {
	a := canonKey(client, server, 100)
	b := canonKey(client, server, 200)
	if a == b {
		t.Fatalf("loopback keys in different netns collided: %q", a)
	}
}

// For routed (non-loopback) traffic netns is excluded, so the two captures of an
// on-node cross-namespace connection (different netns) still match.
func TestCanonKeyRoutedIgnoresNetns(t *testing.T) {
	c := Endpoint{Addr: "10.0.0.1", Port: 5000}
	s := Endpoint{Addr: "10.0.0.2", Port: 80}
	if canonKey(c, s, 100) != canonKey(s, c, 200) {
		t.Fatal("routed mirror keys should match regardless of netns")
	}
}

// A request captured on one socket and its response on the mirrored socket must
// combine into a single exchange with correct latency and sizes.
func TestPairAcrossMirroredSockets(t *testing.T) {
	var got []Exchange
	c := New(func(e Exchange) { got = append(got, e) }, 0, 0)

	// Request captured on the client's egress (src=client).
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 1000, Src: client, Dst: server, Netns: 100, Method: "GET", Path: "/x", Host: "h", HasCL: true})
	c.Process(Event{Kind: KindComplete, HTTPDir: DirRequest, Seq: 0, Ts: 1010, Src: client, Dst: server, Netns: 100, TotalLen: 78})
	// Response captured on the server's egress (src=server, mirrored tuple).
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirResponse, Seq: 0, Ts: 1500, Src: server, Dst: client, Netns: 100, StatusCode: 200, HasCL: true})
	c.Process(Event{Kind: KindComplete, HTTPDir: DirResponse, Seq: 0, Ts: 2000, Src: server, Dst: client, Netns: 100, TotalLen: 161})

	if len(got) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(got))
	}
	e := got[0]
	if !e.Complete || e.Method != "GET" || e.Path != "/x" || e.StatusCode != 200 {
		t.Fatalf("unexpected exchange: %+v", e)
	}
	if e.ReqSize != 78 || e.RespSize != 161 {
		t.Fatalf("sizes: req=%d resp=%d", e.ReqSize, e.RespSize)
	}
	if e.TTFBns != 500 { // 1500 - 1000
		t.Fatalf("ttfb: %d", e.TTFBns)
	}
	if e.Totalns != 1000 { // 2000 - 1000
		t.Fatalf("total: %d", e.Totalns)
	}
	if e.Src != client || e.Dst != server {
		t.Fatalf("endpoints: src=%v dst=%v", e.Src, e.Dst)
	}
}

// Pipelined requests pair with responses in order via the sequence number.
func TestPipeliningFIFO(t *testing.T) {
	var got []Exchange
	c := New(func(e Exchange) { got = append(got, e) }, 0, 0)
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 1, Src: client, Dst: server, Netns: 1, Path: "/a", HasCL: true})
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 1, Ts: 2, Src: client, Dst: server, Netns: 1, Path: "/b", HasCL: true})
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirResponse, Seq: 0, Ts: 3, Src: server, Dst: client, Netns: 1, StatusCode: 200, HasCL: true})
	c.Process(Event{Kind: KindComplete, HTTPDir: DirResponse, Seq: 0, Ts: 4, Src: server, Dst: client, Netns: 1, TotalLen: 10})
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirResponse, Seq: 1, Ts: 5, Src: server, Dst: client, Netns: 1, StatusCode: 404, HasCL: true})
	c.Process(Event{Kind: KindComplete, HTTPDir: DirResponse, Seq: 1, Ts: 6, Src: server, Dst: client, Netns: 1, TotalLen: 20})

	if len(got) != 2 {
		t.Fatalf("want 2 exchanges, got %d", len(got))
	}
	if got[0].Path != "/a" || got[0].StatusCode != 200 {
		t.Fatalf("first: %+v", got[0])
	}
	if got[1].Path != "/b" || got[1].StatusCode != 404 {
		t.Fatalf("second: %+v", got[1])
	}
}

// A connection-close response (no Content-Length, not chunked) is emitted at
// header time with no full-response time.
func TestConnectionCloseResponse(t *testing.T) {
	var got []Exchange
	c := New(func(e Exchange) { got = append(got, e) }, 0, 0)
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 100, Src: client, Dst: server, Netns: 1, Path: "/s", HasCL: true})
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirResponse, Seq: 0, Ts: 200, Src: server, Dst: client, Netns: 1, StatusCode: 200})

	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Complete {
		t.Fatal("should be marked incomplete (no full response time)")
	}
	if got[0].TTFBns != 100 || got[0].Totalns != 0 {
		t.Fatalf("timing: ttfb=%d total=%d", got[0].TTFBns, got[0].Totalns)
	}
}

// A request that never gets a response is flushed as a request-only row on close.
func TestUnpairedFlushedOnClose(t *testing.T) {
	var got []Exchange
	c := New(func(e Exchange) { got = append(got, e) }, 0, 0)
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 1, Src: client, Dst: server, Netns: 1, Path: "/gone", HasCL: true})
	if len(got) != 0 {
		t.Fatalf("nothing should emit before close, got %d", len(got))
	}
	c.Process(Event{Kind: KindClose, Ts: 2, Src: client, Dst: server, Netns: 1})
	if len(got) != 1 || got[0].Complete || got[0].Path != "/gone" {
		t.Fatalf("want one request-only row, got %+v", got)
	}
}

// Idle connections are flushed after the timeout without a close marker.
func TestIdleTimeoutFlush(t *testing.T) {
	var got []Exchange
	c := New(func(e Exchange) { got = append(got, e) }, 1000, 0)
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 1, Src: client, Dst: server, Netns: 1, Path: "/idle", HasCL: true})
	// A later event on another connection advances the clock past the timeout.
	other := Endpoint{Addr: "127.0.0.1", Port: 9999}
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 5000, Src: other, Dst: server, Netns: 1, Path: "/other", HasCL: true})
	if len(got) != 1 || got[0].Path != "/idle" || got[0].Complete {
		t.Fatalf("idle flush: %+v", got)
	}
}

// The pending cap flushes the oldest connection when exceeded.
func TestMaxPendingCap(t *testing.T) {
	var got []Exchange
	c := New(func(e Exchange) { got = append(got, e) }, 0, 1)
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 1, Src: client, Dst: server, Netns: 1, Path: "/first", HasCL: true})
	other := Endpoint{Addr: "127.0.0.1", Port: 9999}
	c.Process(Event{Kind: KindHeaders, HTTPDir: DirRequest, Seq: 0, Ts: 2, Src: other, Dst: server, Netns: 1, Path: "/second", HasCL: true})
	if len(got) != 1 || got[0].Path != "/first" {
		t.Fatalf("cap should evict oldest: %+v", got)
	}
}
