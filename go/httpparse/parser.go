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

// Package httpparse turns the bounded, pre-split HTTP/1.x message bytes
// forwarded by the trace_http eBPF program into structured fields. All framing
// (message splitting, body bounding) already happened in eBPF, so this package
// parses exactly one message per call: no reassembly, no boundary logic. It has
// no wasmapi dependency so it can be unit-tested on the host.
package httpparse

import (
	"bytes"
	"strconv"
)

// Direction values, mirroring the eBPF direction_raw field.
const (
	DirUnknown  uint8 = 0
	DirRequest  uint8 = 1
	DirResponse uint8 = 2
)

// Message is the parsed representation of a single HTTP/1.x message.
type Message struct {
	Direction        string
	Method           string
	Path             string
	HTTPVersion      string
	StatusCode       uint16
	Host             string
	ContentType      string
	ContentLength    uint32
	HasContentLength bool
	IsChunked        bool
	IsWebsocket      bool
	Body             []byte
}

// ParseMessage parses one bounded HTTP/1.x message. data is the raw bytes
// (headers + body preview) captured by eBPF, hdrLen marks the end of the header
// block within data, and directionRaw is the eBPF-derived direction. Chunked
// transfer-encoding is detected from the headers and the body preview is
// de-chunked for readability (best effort).
func ParseMessage(data []byte, hdrLen int, directionRaw uint8) Message {
	var m Message

	if hdrLen < 0 || hdrLen > len(data) {
		hdrLen = len(data)
	}
	header := data[:hdrLen]
	body := data[hdrLen:]

	lines := splitLines(header)

	switch directionRaw {
	case DirRequest:
		m.Direction = "request"
	case DirResponse:
		m.Direction = "response"
	default:
		m.Direction = "unknown"
	}

	if len(lines) > 0 && directionRaw != DirUnknown {
		parseStartLine(lines[0], &m)
	}

	for _, line := range lines[1:] {
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch {
		case equalFold(name, "host"):
			if m.Host == "" {
				m.Host = string(value)
			}
		case equalFold(name, "content-type"):
			if m.ContentType == "" {
				m.ContentType = string(bytes.TrimSpace(value))
			}
		case equalFold(name, "content-length"):
			if n, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 10, 32); err == nil {
				m.ContentLength = uint32(n)
				m.HasContentLength = true
			}
		case equalFold(name, "transfer-encoding"):
			if containsFold(value, "chunked") {
				m.IsChunked = true
			}
		case equalFold(name, "upgrade"):
			if containsFold(value, "websocket") {
				m.IsWebsocket = true
			}
		}
	}

	if m.IsChunked {
		m.Body = dechunk(body)
	} else {
		m.Body = body
	}

	return m
}

// parseStartLine fills either request (method/path/version) or response
// (version/status) fields from the first line.
func parseStartLine(line []byte, m *Message) {
	if bytes.HasPrefix(line, []byte("HTTP/")) {
		// Response: "HTTP/1.1 200 OK"
		parts := bytes.SplitN(line, []byte(" "), 3)
		if len(parts) >= 1 {
			m.HTTPVersion = versionOf(parts[0])
		}
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(string(bytes.TrimSpace(parts[1]))); err == nil {
				m.StatusCode = uint16(code)
			}
		}
		return
	}

	// Request: "GET /path HTTP/1.1"
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) >= 1 {
		m.Method = string(parts[0])
	}
	if len(parts) >= 2 {
		m.Path = string(parts[1])
	}
	if len(parts) >= 3 {
		m.HTTPVersion = versionOf(bytes.TrimSpace(parts[2]))
	}
}

// versionOf extracts "1.1" from "HTTP/1.1".
func versionOf(token []byte) string {
	if v, ok := bytes.CutPrefix(token, []byte("HTTP/")); ok {
		return string(v)
	}
	return ""
}

// splitLines splits a header block on CRLF (or LF), dropping empty lines.
func splitLines(header []byte) [][]byte {
	var lines [][]byte
	for _, raw := range bytes.Split(header, []byte("\n")) {
		line := bytes.TrimSuffix(raw, []byte("\r"))
		if len(line) == 0 {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// splitHeader splits "Name: value" into name and trimmed value.
func splitHeader(line []byte) (name, value []byte, ok bool) {
	idx := bytes.IndexByte(line, ':')
	if idx < 0 {
		return nil, nil, false
	}
	return line[:idx], bytes.TrimSpace(line[idx+1:]), true
}

// equalFold reports whether b equals the ASCII-lowercase literal lower.
func equalFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// containsFold reports whether b contains the ASCII-lowercase literal lower,
// case-insensitively.
func containsFold(b []byte, lower string) bool {
	return bytes.Contains(bytes.ToLower(b), []byte(lower))
}

// dechunk decodes a (possibly truncated) chunked body preview, returning as much
// decoded data as it can. On malformed input it returns what was decoded so far.
func dechunk(body []byte) []byte {
	var out []byte
	pos := 0
	for pos < len(body) {
		nl := bytes.IndexByte(body[pos:], '\n')
		if nl < 0 {
			break
		}
		sizeLine := bytes.TrimSpace(body[pos : pos+nl])
		// A chunk-size line may carry extensions after ';'.
		if semi := bytes.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = sizeLine[:semi]
		}
		size, err := strconv.ParseInt(string(sizeLine), 16, 64)
		if err != nil || size < 0 {
			break
		}
		pos += nl + 1
		if size == 0 {
			break
		}
		end := pos + int(size)
		if end > len(body) {
			// Truncated preview: take what remains.
			out = append(out, body[pos:]...)
			break
		}
		out = append(out, body[pos:end]...)
		pos = end
		// Skip trailing CRLF after the chunk data.
		if pos < len(body) && body[pos] == '\r' {
			pos++
		}
		if pos < len(body) && body[pos] == '\n' {
			pos++
		}
	}
	return out
}
