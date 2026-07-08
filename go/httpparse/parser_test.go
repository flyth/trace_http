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

package httpparse

import (
	"bytes"
	"testing"
)

// build builds a raw message (headers + body) and returns it with the header
// length, mimicking what the eBPF program forwards.
func build(headers, body string) ([]byte, int) {
	h := []byte(headers)
	return append(append([]byte{}, h...), []byte(body)...), len(h)
}

func TestParseRequest(t *testing.T) {
	data, hdrLen := build("GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n", "")
	m := ParseMessage(data, hdrLen, DirRequest)
	if m.Direction != "request" {
		t.Errorf("direction = %q, want request", m.Direction)
	}
	if m.Method != "GET" {
		t.Errorf("method = %q, want GET", m.Method)
	}
	if m.Path != "/index.html" {
		t.Errorf("path = %q, want /index.html", m.Path)
	}
	if m.HTTPVersion != "1.1" {
		t.Errorf("version = %q, want 1.1", m.HTTPVersion)
	}
	if m.Host != "example.com" {
		t.Errorf("host = %q, want example.com", m.Host)
	}
}

func TestParseResponseContentLength(t *testing.T) {
	data, hdrLen := build("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n", "hello")
	m := ParseMessage(data, hdrLen, DirResponse)
	if m.Direction != "response" {
		t.Errorf("direction = %q, want response", m.Direction)
	}
	if m.StatusCode != 200 {
		t.Errorf("status = %d, want 200", m.StatusCode)
	}
	if m.HTTPVersion != "1.1" {
		t.Errorf("version = %q, want 1.1", m.HTTPVersion)
	}
	if string(m.Body) != "hello" {
		t.Errorf("body = %q, want hello", m.Body)
	}
}

func TestParseResponseChunked(t *testing.T) {
	// Two chunks: "Wiki" (4) and "pedia" (5), then terminator.
	body := "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
	data, hdrLen := build("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", body)
	m := ParseMessage(data, hdrLen, DirResponse)
	if got := string(m.Body); got != "Wikipedia" {
		t.Errorf("dechunked body = %q, want Wikipedia", got)
	}
}

func TestParseChunkedTruncatedPreview(t *testing.T) {
	// Body preview cut off in the middle of the first chunk's data.
	body := "10\r\nHello, wor" // declares 16 bytes, only 9 present
	data, hdrLen := build("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", body)
	m := ParseMessage(data, hdrLen, DirResponse)
	if got := string(m.Body); got != "Hello, wor" {
		t.Errorf("truncated dechunk = %q, want %q", got, "Hello, wor")
	}
}

func TestParseWebsocketUpgrade(t *testing.T) {
	data, hdrLen := build("GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", "")
	m := ParseMessage(data, hdrLen, DirRequest)
	if m.Method != "GET" || m.Path != "/chat" {
		t.Errorf("got method=%q path=%q, want GET /chat", m.Method, m.Path)
	}
	if m.Host != "ws.example.com" {
		t.Errorf("host = %q, want ws.example.com", m.Host)
	}
}

func TestCaseInsensitiveHost(t *testing.T) {
	data, hdrLen := build("GET / HTTP/1.1\r\nHOST: UPPER.example\r\n\r\n", "")
	m := ParseMessage(data, hdrLen, DirRequest)
	if m.Host != "UPPER.example" {
		t.Errorf("host = %q, want UPPER.example", m.Host)
	}
}

func TestTruncatedHeadersNoBlankLine(t *testing.T) {
	// eBPF passes hdrLen == len(data) when no blank line was found.
	raw := []byte("GET /really/long HTTP/1.1\r\nHost: partial.exa")
	m := ParseMessage(raw, len(raw), DirRequest)
	if m.Method != "GET" || m.Path != "/really/long" {
		t.Errorf("got method=%q path=%q", m.Method, m.Path)
	}
	// The partial Host line is still a header line and should be parsed.
	if m.Host != "partial.exa" {
		t.Errorf("host = %q, want partial.exa", m.Host)
	}
	if len(m.Body) != 0 {
		t.Errorf("body = %q, want empty", m.Body)
	}
}

func TestNonHTTPUnknownDirection(t *testing.T) {
	// eBPF would normally not forward this, but guard against it anyway.
	raw := []byte("\x16\x03\x01\x00\xa5") // TLS ClientHello prefix
	m := ParseMessage(raw, len(raw), DirUnknown)
	if m.Direction != "unknown" {
		t.Errorf("direction = %q, want unknown", m.Direction)
	}
	if m.Method != "" || m.StatusCode != 0 {
		t.Errorf("unexpected parse of non-HTTP: method=%q status=%d", m.Method, m.StatusCode)
	}
}

func TestBodyPreviewNotChunked(t *testing.T) {
	data, hdrLen := build("POST /submit HTTP/1.1\r\nContent-Length: 11\r\n\r\n", "hello world")
	m := ParseMessage(data, hdrLen, DirRequest)
	if !bytes.Equal(m.Body, []byte("hello world")) {
		t.Errorf("body = %q, want hello world", m.Body)
	}
	if m.Method != "POST" {
		t.Errorf("method = %q, want POST", m.Method)
	}
}
