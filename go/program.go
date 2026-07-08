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

// The trace_http WASM module turns the per-message HTTP markers emitted by the
// eBPF program (on the internal "http_msg" datasource) into one event per
// request/response exchange, on the user-facing "http" datasource. Message
// framing happens in eBPF; this module parses the header bytes, correlates
// request with response, and derives latency and sizes.
package main

import (
	"strconv"

	"trace_http/correlate"
	"trace_http/httpparse"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Raw input fields (internal "http_msg" datasource).
var (
	inMsgType, inDir, inSeq, inTs            api.Field
	inHdrLen, inDataLen, inTotalLen, inNetns api.Field
	inSrcAddr, inSrcVer, inSrcPort           api.Field
	inDstAddr, inDstVer, inDstPort           api.Field
	inComm, inPid, inTid, inMntns, inData    api.Field
)

// Output fields (user-facing "http" datasource).
var (
	outTs, outSrc, outDst             api.Field
	outComm, outPid, outMntns         api.Field
	outMethod, outPath, outVersion    api.Field
	outHost, outStatus                api.Field
	outReqSize, outRespSize           api.Field
	outTTFB, outTotal                 api.Field
	outReqBody, outRespBody           api.Field
	outChunked, outWebsocket, outDone api.Field
)

var (
	dsOut  api.DataSource
	corr   *correlate.Correlator
	rawBuf []byte
)

func getField(ds api.DataSource, name string) api.Field {
	f, err := ds.GetField(name)
	if err != nil {
		api.Warnf("trace_http: missing input field %s: %s", name, err)
	}
	return f
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	rawDS, err := api.GetDataSource("http_msg")
	if err != nil {
		api.Warnf("trace_http: failed to get datasource: %s", err)
		return 1
	}

	inMsgType = getField(rawDS, "msg_type")
	inDir = getField(rawDS, "direction_raw")
	inSeq = getField(rawDS, "seq")
	inTs = getField(rawDS, "timestamp_raw")
	inHdrLen = getField(rawDS, "hdr_len")
	inDataLen = getField(rawDS, "data_len")
	inTotalLen = getField(rawDS, "total_len")
	inNetns = getField(rawDS, "netns_id")
	inSrcAddr = getField(rawDS, "src.addr_raw")
	inSrcVer = getField(rawDS, "src.version")
	inSrcPort = getField(rawDS, "src.port")
	inDstAddr = getField(rawDS, "dst.addr_raw")
	inDstVer = getField(rawDS, "dst.version")
	inDstPort = getField(rawDS, "dst.port")
	inComm = getField(rawDS, "proc.comm")
	inPid = getField(rawDS, "proc.pid")
	inTid = getField(rawDS, "proc.tid")
	inMntns = getField(rawDS, "proc.mntns_id")
	inData = getField(rawDS, "data")

	dsOut, err = api.NewDataSource("http", api.DataSourceTypeSingle)
	if err != nil {
		api.Warnf("trace_http: creating datasource: %s", err)
		return 1
	}

	var addErr bool
	add := func(name string, kind api.FieldKind) api.Field {
		f, err := dsOut.AddField(name, kind)
		if err != nil {
			api.Warnf("trace_http: adding field %s: %s", name, err)
			addErr = true
		}
		return f
	}
	outTs = add("timestamp_raw", api.Kind_Uint64)
	outSrc = add("src", api.Kind_String)
	outDst = add("dst", api.Kind_String)
	outComm = add("comm", api.Kind_String)
	outPid = add("pid", api.Kind_Uint32)
	outMntns = add("mntns_id", api.Kind_Uint64)
	outMethod = add("method", api.Kind_String)
	outPath = add("path", api.Kind_String)
	outVersion = add("http_version", api.Kind_String)
	outHost = add("host", api.Kind_String)
	outStatus = add("status_code", api.Kind_Uint16)
	outReqSize = add("request_size", api.Kind_Uint32)
	outRespSize = add("response_size", api.Kind_Uint32)
	outTTFB = add("latency_ttfb_ns", api.Kind_Uint64)
	outTotal = add("latency_total_ns", api.Kind_Uint64)
	outReqBody = add("request_body", api.Kind_Bytes)
	outRespBody = add("response_body", api.Kind_Bytes)
	outChunked = add("is_chunked", api.Kind_Bool)
	outWebsocket = add("is_websocket", api.Kind_Bool)
	outDone = add("complete", api.Kind_Bool)
	if addErr {
		return 1
	}

	// Tag the mount-namespace id so the container/k8s enrichers add pod and
	// container fields to the combined event.
	if err := outMntns.AddTag("type:gadget_mntns_id"); err != nil {
		api.Warnf("trace_http: tagging mntns_id: %s", err)
		return 1
	}
	if err := outTs.AddTag("type:gadget_timestamp"); err != nil {
		api.Warnf("trace_http: tagging timestamp: %s", err)
	}

	idleNs := uint64(10) * 1_000_000_000
	maxPending := 16384
	corr = correlate.New(emit, idleNs, maxPending)

	rawBuf = make([]byte, 4096)

	// Only the combined "http" datasource is shown; the raw per-message stream
	// is internal to correlation.
	if err := rawDS.Unreference(); err != nil {
		api.Warnf("trace_http: unreferencing http_msg: %s", err)
	}

	if err := rawDS.Subscribe(onEvent, 0); err != nil {
		api.Warnf("trace_http: subscribing: %s", err)
		return 1
	}
	return 0
}

func paramUint(key string, def uint64) uint64 {
	s, err := api.GetParamValue(key, 32)
	if err != nil || s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	return v
}

var addrBuf = make([]byte, 16)

// ipString formats a raw address from the eBPF addr_raw union. IPv4 octets are in
// network order (display order); IPv6 is formatted as eight hex groups.
func ipString(version uint8, raw []byte) string {
	if version == 6 && len(raw) >= 16 {
		s := ""
		for i := 0; i < 16; i += 2 {
			if i > 0 {
				s += ":"
			}
			s += strconv.FormatUint(uint64(raw[i])<<8|uint64(raw[i+1]), 16)
		}
		return s
	}
	if len(raw) >= 4 {
		return strconv.Itoa(int(raw[0])) + "." + strconv.Itoa(int(raw[1])) + "." +
			strconv.Itoa(int(raw[2])) + "." + strconv.Itoa(int(raw[3]))
	}
	return ""
}

func endpoint(addrF, verF, portF api.Field, data api.Data) correlate.Endpoint {
	ver, _ := verF.Uint8(data)
	n, _ := addrF.Bytes(data, addrBuf)
	port, _ := portF.Uint16(data)
	return correlate.Endpoint{Addr: ipString(ver, addrBuf[:n]), Port: port}
}

func onEvent(source api.DataSource, data api.Data) {
	msgType, _ := inMsgType.Uint8(data)
	dir, _ := inDir.Uint8(data)
	seq, _ := inSeq.Uint32(data)
	ts, _ := inTs.Uint64(data)
	netns, _ := inNetns.Uint32(data)
	comm, _ := inComm.String(data, 32)
	pid, _ := inPid.Uint32(data)
	tid, _ := inTid.Uint32(data)
	mntns, _ := inMntns.Uint64(data)

	ev := correlate.Event{
		Kind:    msgType,
		HTTPDir: dir,
		Seq:     seq,
		Ts:      ts,
		Src:     endpoint(inSrcAddr, inSrcVer, inSrcPort, data),
		Dst:     endpoint(inDstAddr, inDstVer, inDstPort, data),
		Netns:   uint64(netns),
		Mntns:   mntns,
		Comm:    comm,
		Pid:     pid,
		Tid:     tid,
	}

	switch msgType {
	case correlate.KindHeaders:
		hdrLen, _ := inHdrLen.Uint32(data)
		dataLen, _ := inDataLen.Uint32(data)
		n, err := inData.Bytes(data, rawBuf)
		if err == nil {
			if uint32(n) > dataLen {
				n = dataLen
			}
			msg := httpparse.ParseMessage(rawBuf[:n], int(hdrLen), dir)
			ev.Method = msg.Method
			ev.Path = msg.Path
			ev.HTTPVersion = msg.HTTPVersion
			ev.Host = msg.Host
			ev.StatusCode = msg.StatusCode
			ev.HasCL = msg.HasContentLength
			ev.Chunked = msg.IsChunked
			ev.Websocket = msg.IsWebsocket
			if len(msg.Body) > 0 {
				ev.Body = append([]byte(nil), msg.Body...)
			}
		}
	case correlate.KindComplete:
		ev.TotalLen, _ = inTotalLen.Uint32(data)
	}

	corr.Process(ev)
}

func emit(ex correlate.Exchange) {
	p, err := dsOut.NewPacketSingle()
	if err != nil {
		api.Warnf("trace_http: new packet: %s", err)
		return
	}
	d := api.Data(p)

	outTs.SetUint64(d, ex.Ts)
	outSrc.SetString(d, ex.Src.String())
	outDst.SetString(d, ex.Dst.String())
	outComm.SetString(d, ex.Comm)
	outPid.SetUint32(d, ex.Pid)
	outMntns.SetUint64(d, ex.Mntns)
	if ex.Method != "" {
		outMethod.SetString(d, ex.Method)
	}
	if ex.Path != "" {
		outPath.SetString(d, ex.Path)
	}
	if ex.HTTPVersion != "" {
		outVersion.SetString(d, ex.HTTPVersion)
	}
	if ex.Host != "" {
		outHost.SetString(d, ex.Host)
	}
	outStatus.SetUint16(d, ex.StatusCode)
	outReqSize.SetUint32(d, ex.ReqSize)
	outRespSize.SetUint32(d, ex.RespSize)
	outTTFB.SetUint64(d, ex.TTFBns)
	outTotal.SetUint64(d, ex.Totalns)
	if len(ex.ReqBody) > 0 {
		outReqBody.SetBytes(d, ex.ReqBody)
	}
	if len(ex.RespBody) > 0 {
		outRespBody.SetBytes(d, ex.RespBody)
	}
	outChunked.SetBool(d, ex.Chunked)
	outWebsocket.SetBool(d, ex.Websocket)
	outDone.SetBool(d, ex.Complete)

	if err := dsOut.EmitAndRelease(api.Packet(p)); err != nil {
		api.Warnf("trace_http: emit: %s", err)
	}
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	idleNs := paramUint("idle-timeout-seconds", 10) * 1_000_000_000
	maxPending := int(paramUint("max-pending", 16384))
	corr = correlate.New(emit, idleNs, maxPending)
	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	if corr != nil {
		corr.Flush()
	}
	return 0
}

func main() {}
