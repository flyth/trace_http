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

// The trace_http WASM module turns the bounded, pre-split HTTP message bytes
// forwarded by the eBPF program into structured datasource fields. All framing
// (message splitting, body bounding) already happened in eBPF, so this module
// only parses one message per event: no reassembly, no boundary logic.
package main

import (
	"trace_http/httpparse"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var rawBuf []byte

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("http")
	if err != nil {
		api.Warnf("trace_http: failed to get datasource: %s", err)
		return 1
	}

	dataF, err := ds.GetField("data")
	if err != nil {
		api.Warnf("trace_http: failed to get field data: %s", err)
		return 1
	}
	dataLenF, err := ds.GetField("data_len")
	if err != nil {
		api.Warnf("trace_http: failed to get field data_len: %s", err)
		return 1
	}
	hdrLenF, err := ds.GetField("hdr_len")
	if err != nil {
		api.Warnf("trace_http: failed to get field hdr_len: %s", err)
		return 1
	}
	dirRawF, err := ds.GetField("direction_raw")
	if err != nil {
		api.Warnf("trace_http: failed to get field direction_raw: %s", err)
		return 1
	}

	var addErr bool
	add := func(name string, kind api.FieldKind) api.Field {
		f, err := ds.AddField(name, kind)
		if err != nil {
			api.Warnf("trace_http: failed to add field %s: %s", name, err)
			addErr = true
		}
		return f
	}
	directionF := add("direction", api.Kind_String)
	methodF := add("method", api.Kind_String)
	pathF := add("path", api.Kind_String)
	versionF := add("http_version", api.Kind_String)
	statusF := add("status_code", api.Kind_Uint16)
	hostF := add("host", api.Kind_String)
	contentLengthF := add("content_length", api.Kind_Uint32)
	isChunkedF := add("is_chunked", api.Kind_Bool)
	isWebsocketF := add("is_websocket", api.Kind_Bool)
	bodyF := add("body", api.Kind_Bytes)
	if addErr {
		return 1
	}

	rawBuf = make([]byte, 4096)

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		dataLen, err := dataLenF.Uint32(data)
		if err != nil {
			api.Warnf("trace_http: reading data_len: %s", err)
			return
		}
		hdrLen, err := hdrLenF.Uint32(data)
		if err != nil {
			api.Warnf("trace_http: reading hdr_len: %s", err)
			return
		}
		dirRaw, err := dirRawF.Uint8(data)
		if err != nil {
			api.Warnf("trace_http: reading direction_raw: %s", err)
			return
		}

		n, err := dataF.Bytes(data, rawBuf)
		if err != nil {
			api.Warnf("trace_http: reading data: %s", err)
			return
		}
		if uint32(n) > dataLen {
			n = dataLen
		}

		msg := httpparse.ParseMessage(rawBuf[:n], int(hdrLen), dirRaw)

		directionF.SetString(data, msg.Direction)
		if msg.Method != "" {
			methodF.SetString(data, msg.Method)
		}
		if msg.Path != "" {
			pathF.SetString(data, msg.Path)
		}
		if msg.HTTPVersion != "" {
			versionF.SetString(data, msg.HTTPVersion)
		}
		if msg.StatusCode != 0 {
			statusF.SetUint16(data, msg.StatusCode)
		}
		if msg.Host != "" {
			hostF.SetString(data, msg.Host)
		}
		contentLengthF.SetUint32(data, msg.ContentLength)
		isChunkedF.SetBool(data, msg.IsChunked)
		isWebsocketF.SetBool(data, msg.IsWebsocket)
		if len(msg.Body) > 0 {
			bodyF.SetBytes(data, msg.Body)
		}
	}, 0)

	return 0
}

func main() {}
