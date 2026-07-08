# trace_http

An [Inspektor Gadget](https://inspektor-gadget.io) gadget that extracts
**HTTP/1.x request/response exchanges** from TCP connections and reports **one
event per exchange** — method, path, status, sizes and latency — with the usual
Inspektor Gadget process/container/Kubernetes enrichment.

It observes traffic passively: connections are never modified or delayed.

## What it does

For every HTTP/1.x request the gadget correlates the request with its response
and emits a single event:

| Column             | Description                                                        |
| ------------------ | ----------------------------------------------------------------- |
| `method`           | request method (`GET`, `POST`, …)                                 |
| `path`             | request target                                                    |
| `http_version`     | protocol version, e.g. `1.1`                                      |
| `status_code`      | response status code (`0` if no response was captured)           |
| `host`             | value of the request `Host` header                               |
| `request_size`     | total request size in bytes (headers + body)                     |
| `response_size`    | total response size in bytes (headers + body), `0` if unknown    |
| `latency_ttfb_ns`  | time from request start to the first response byte (nanoseconds) |
| `latency_total_ns` | time from request start to the last response byte (nanoseconds)  |
| `is_chunked`       | whether the response used chunked transfer-encoding              |
| `is_websocket`     | whether the exchange upgraded to a WebSocket                     |
| `request_body`     | first bytes of the request body (up to 1024)                     |
| `response_body`    | first bytes of the response body (up to 1024)                    |
| `src`, `dst`       | client (request sender) and server (request receiver) endpoints  |

Each event is enriched with the process and container that owns the connection:
`comm`, `pid`, the mount namespace, and — on Kubernetes or when using a container
runtime — the container name and the pod/namespace/labels. This is the standard
Inspektor Gadget process/container/Kubernetes enrichment.

`src` is always the client (which sent the request) and `dst` the server.

## How it works

The gadget attaches three small eBPF programs:

- a **`sock_ops`** program on the node's cgroup-v2 root that registers every
  established TCP socket,
- an **`sk_skb`** program that observes the data sockets **receive**, and
- an **`sk_msg`** program that observes the data sockets **send**.

Observing both the sent and received sides lets the gadget capture both ends of a
connection, including connections where only one endpoint is on the node. When
both endpoints are on the node the message is captured exactly once (no
duplicates). The eBPF programs forward each message's headers and a short body
preview to user space and skip the rest of the body, so the amount of data
leaving the kernel stays proportional to the number of messages rather than to
their size. A WebAssembly module then parses the forwarded bytes, pairs each
request with its response, and computes the sizes and latency.

The owning process and container are resolved through Inspektor Gadget's socket
enricher, which maps each socket to the task that created it (and therefore to
its container/pod).

## Requirements

- Linux kernel **5.17 or newer** with cgroup-v2 (a unified hierarchy mounted at
  `/sys/fs/cgroup`) and sockmap/`sk_skb`/`sk_msg` support (enabled on stock
  distributions).
- [`ig`](https://inspektor-gadget.io/docs/latest/reference/install-linux) to run
  the gadget, and Docker to build the image.

> **Note:** this gadget uses the `sock_ops`, `sk_skb` and `sk_msg` eBPF program
> types. Your `ig` (and, on Kubernetes, the deployed Inspektor Gadget) must
> include support for attaching these program types. If your `ig` reports an
> unsupported program type when loading the gadget, upgrade to a build that
> includes it and set `IG_VERSION` in `.github/workflows/*.yml` accordingly.

## Getting started

Build the OCI image (uses the `ig` builder container):

```bash
make build            # or: sudo ig image build -t trace_http:latest .
```

Run it and generate some HTTP traffic in another terminal. On a plain host, pass
`--host` so connections in the host network namespace are shown (without it, `ig`
reports only traffic that belongs to a container):

```bash
make run              # or: sudo ig run trace_http:latest --host
```

```
$ sudo ig run trace_http:latest --host
SRC                DST                COMM     METHOD  PATH        HTTP  STATUS  REQUEST_SIZE  RESPONSE_SIZE  LATENCY_TTFB_NS  LATENCY_TOTAL_NS
127.0.0.1:53578    127.0.0.1:8080     curl     GET     /           1.1   200     78            161            387835           448461
127.0.0.1:53578    127.0.0.1:8080     curl     POST    /submit     1.1   201     159           175            255168           283585
```

### Options

| Flag                     | Default | Description                                                             |
| ------------------------ | ------- | ---------------------------------------------------------------------- |
| `--idle-timeout-seconds` | `10`    | Emit a request-only row if its response is not seen within this time.  |
| `--max-pending`          | `16384` | Maximum number of in-flight requests held while awaiting a response.   |

### Filtering

Restrict the output with the standard Inspektor Gadget filters, which are
matched against the process/container that owns the connection:

```bash
# only a specific container / pod
sudo ig run trace_http:latest --containername my-app
kubectl gadget run trace_http:latest --podname web-0 --namespace prod

# only a specific process
sudo ig run trace_http:latest --host --comm curl
sudo ig run trace_http:latest --host --pid 1234
```

### Selecting fields and output format

Use the standard `ig` flags, for example JSON output with a chosen set of fields:

```bash
sudo ig run trace_http:latest --host \
  --fields method,path,status_code,request_size,response_size,latency_ttfb_ns,src,dst,k8s.podName \
  -o json
```

### Running on Kubernetes

Deploy Inspektor Gadget in the cluster and run the gadget with
`kubectl gadget` (events are automatically enriched with the pod, namespace and
container):

```bash
kubectl gadget run ghcr.io/your-org/trace_http:latest
```

## What is captured

- Only **HTTP/1.x** is parsed. Connections carrying other protocols are ignored
  (they still flow normally).
- One event is emitted **per request/response exchange**, when the response
  completes. A request that never receives a response is reported on its own
  (with `status_code` `0`) once the connection closes or the idle timeout
  elapses.
- `request_body`/`response_body` hold a preview of up to 1024 bytes, populated
  when the body is sent together with the headers.
- `latency_total_ns` and `response_size` are known for responses framed by a
  `Content-Length` or chunked transfer-encoding. For a response whose body ends
  only when the connection closes, only `latency_ttfb_ns` is reported.
- A **WebSocket** upgrade is reported (`is_websocket`), after which the connection
  carries WebSocket frames and is no longer parsed as HTTP.

## Development

Unit-test the userspace parser and correlation logic (no root or kernel required):

```bash
make unit             # cd go && go test ./...
```

Build and smoke-test the gadget on the current kernel:

```bash
make test             # builds the image, loads it, and captures a request
```

## License

The eBPF program (`program.bpf.c`) is GPL-2.0. The rest of the project is
Apache-2.0; see [LICENSE](LICENSE).
