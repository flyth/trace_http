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

// The trace_http WASM module enriches the correlated exchange events produced by
// the eBPF program. Correlation, latency and sizes are computed in the kernel;
// this module only parses the two raw header blocks the event carries (request
// then response) and fills in method/path/host/status and the body previews. It
// holds no state.
package main

import (
	"trace_http/httpparse"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Input fields carried by the eBPF "http" event.
var (
	inReqHdrLen, inReqDataLen   api.Field
	inRespHdrLen, inRespDataLen api.Field
	inData                      api.Field
)

// Output fields parsed from the header blocks.
var (
	outMethod, outPath, outVersion api.Field
	outHost, outStatus, outCType   api.Field
	outReqBody, outRespBody        api.Field
	outChunked, outWebsocket       api.Field
)

var dataBuf []byte

func getField(ds api.DataSource, name string) api.Field {
	f, err := ds.GetField(name)
	if err != nil {
		api.Warnf("trace_http: missing input field %s: %s", name, err)
	}
	return f
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("http")
	if err != nil {
		api.Warnf("trace_http: failed to get datasource: %s", err)
		return 1
	}

	inReqHdrLen = getField(ds, "req_hdr_len")
	inReqDataLen = getField(ds, "req_data_len")
	inRespHdrLen = getField(ds, "resp_hdr_len")
	inRespDataLen = getField(ds, "resp_data_len")
	inData = getField(ds, "data")

	var addErr bool
	add := func(name string, kind api.FieldKind) api.Field {
		f, err := ds.AddField(name, kind)
		if err != nil {
			api.Warnf("trace_http: adding field %s: %s", name, err)
			addErr = true
		}
		return f
	}
	outMethod = add("method", api.Kind_String)
	outPath = add("path", api.Kind_String)
	outVersion = add("http_version", api.Kind_String)
	outHost = add("host", api.Kind_String)
	outStatus = add("status_code", api.Kind_Uint16)
	outCType = add("content_type", api.Kind_String)
	outReqBody = add("request_body", api.Kind_Bytes)
	outRespBody = add("response_body", api.Kind_Bytes)
	outChunked = add("is_chunked", api.Kind_Bool)
	outWebsocket = add("is_websocket", api.Kind_Bool)
	if addErr {
		return 1
	}

	dataBuf = make([]byte, 8192)

	if err := ds.Subscribe(onEvent, 0); err != nil {
		api.Warnf("trace_http: subscribing: %s", err)
		return 1
	}
	return 0
}

func onEvent(source api.DataSource, data api.Data) {
	reqHdrLen, _ := inReqHdrLen.Uint32(data)
	reqDataLen, _ := inReqDataLen.Uint32(data)
	respHdrLen, _ := inRespHdrLen.Uint32(data)
	respDataLen, _ := inRespDataLen.Uint32(data)

	n, err := inData.Bytes(data, dataBuf)
	if err != nil {
		return
	}
	blob := dataBuf[:n]

	// The event carries the request block followed by the response block; the
	// response block starts at offset req_data_len.
	reqEnd := reqDataLen
	if reqEnd > uint32(len(blob)) {
		reqEnd = uint32(len(blob))
	}
	respEnd := reqEnd + respDataLen
	if respEnd > uint32(len(blob)) {
		respEnd = uint32(len(blob))
	}

	var reqCType, respCType string

	if reqDataLen > 0 {
		req := httpparse.ParseMessage(blob[:reqEnd], int(reqHdrLen), httpparse.DirRequest)
		if req.Method != "" {
			outMethod.SetString(data, req.Method)
		}
		if req.Path != "" {
			outPath.SetString(data, req.Path)
		}
		if req.HTTPVersion != "" {
			outVersion.SetString(data, req.HTTPVersion)
		}
		if req.Host != "" {
			outHost.SetString(data, req.Host)
		}
		reqCType = req.ContentType
		if len(req.Body) > 0 {
			outReqBody.SetBytes(data, req.Body)
		}
	}

	if respDataLen > 0 {
		resp := httpparse.ParseMessage(blob[reqEnd:respEnd], int(respHdrLen), httpparse.DirResponse)
		outStatus.SetUint16(data, resp.StatusCode)
		outChunked.SetBool(data, resp.IsChunked)
		outWebsocket.SetBool(data, resp.IsWebsocket)
		respCType = resp.ContentType
		if len(resp.Body) > 0 {
			outRespBody.SetBytes(data, resp.Body)
		}
	}

	// content_type reflects the payload type: the response's Content-Type when
	// present, otherwise the request's (e.g. for a POST body or request-only row).
	if respCType != "" {
		outCType.SetString(data, respCType)
	} else if reqCType != "" {
		outCType.SetString(data, reqCType)
	}
}

func main() {}
