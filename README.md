# trace_http

An [Inspektor Gadget](https://inspektor-gadget.io) gadget that extracts
**HTTP/1.x requests and responses** from TCP connections and reports them as a
stream of structured events — method, path, status, `Host`, Content-Length and
more — with the usual Inspektor Gadget process/container/Kubernetes enrichment.

It observes traffic passively: connections are never modified or delayed.

## What it does

For every HTTP/1.x message seen on a connection the gadget emits one event:

| Column           | Description                                                       |
| ---------------- | ----------------------------------------------------------------- |
| `direction`      | `request` or `response`                                           |
| `method`         | request method (`GET`, `POST`, …) — requests only                 |
| `path`           | request target — requests only                                    |
| `status_code`    | response status code — responses only                            |
| `http_version`   | protocol version, e.g. `1.1`                                      |
| `host`           | value of the `Host` header (requests)                             |
| `content_length` | value of the `Content-Length` header (`0` if absent)              |
| `is_chunked`     | whether the message uses chunked transfer-encoding                |
| `is_websocket`   | whether the message is a WebSocket upgrade                        |
| `body`           | the first bytes of the message body (up to 1024)                  |
| `src`, `dst`     | source and destination L4 endpoints                               |

Each event is also enriched with the process and container that owns the local
end of the connection: `comm`, `pid`, `tid`, the mount and network namespaces,
and — on Kubernetes or when using a container runtime — the container name,
image and the pod/namespace/labels. This is the standard Inspektor Gadget
process/container/Kubernetes enrichment.

Requests and responses on the same connection share the connection's endpoints:
for a request, `src` is the client and `dst` the server; for the matching
response the two are swapped. The enrichment always reflects the **local**
process that received the message (the server for a request, the client for a
response).

## How it works

The gadget attaches two small eBPF programs:

- a **`sock_ops`** program on the node's cgroup-v2 root that registers every
  established TCP socket, and
- an **`sk_skb`** verdict program that inspects the data those sockets receive.

Because it looks at *received* data on both ends of a connection, requests are
seen as they arrive at the server and responses as they arrive at the client;
the direction of each message is determined by reading its start line. The eBPF
program forwards each message's headers and a short body preview to user space
and skips the rest of the body, so the amount of data leaving the kernel stays
proportional to the number of messages rather than to their size. A small
WebAssembly module then turns the forwarded bytes into the structured fields
above.

The owning process and container are resolved through Inspektor Gadget's socket
enricher, which maps each socket to the task that created it (and therefore to
its container/pod).

## Requirements

- Linux kernel **5.17 or newer** with cgroup-v2 (a unified hierarchy mounted at
  `/sys/fs/cgroup`) and sockmap/`sk_skb` support (enabled on stock distributions).
- [`ig`](https://inspektor-gadget.io/docs/latest/reference/install-linux) to run
  the gadget, and Docker to build the image.

> **Note:** this gadget uses the `sk_skb` and `sock_ops` eBPF program types. Your
> `ig` (and, on Kubernetes, the deployed Inspektor Gadget) must include support
> for attaching these program types. If your `ig` reports an unsupported
> program type when loading the gadget, upgrade to a build that includes it and
> set `IG_VERSION` in `.github/workflows/*.yml` accordingly.

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
DIRECTION   METHOD  PATH             HTTP  STATUS  HOST               SRC                DST                COMM     PID
request     GET     /                1.1   0       127.0.0.1:8080     127.0.0.1:44274    127.0.0.1:8080     python3  1312
response                             1.1   200                        127.0.0.1:8080     127.0.0.1:44274    curl     1373
```

### Filtering

Restrict the output with the standard Inspektor Gadget filters, which are
matched against the process/container that owns the local end of each
connection:

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
  --fields direction,method,path,status_code,host,src,dst,proc.comm,k8s.podName \
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
- The **`body`** column holds a preview of up to 1024 bytes. It is populated when
  the body arrives together with the headers; a body sent in a later network
  packet is skipped and reported only through `content_length`.
- A **WebSocket** upgrade is reported (`is_websocket`), after which the connection
  carries WebSocket frames and is no longer parsed as HTTP.
- The gadget sees a connection only once both of its endpoints exist on the node
  where it runs. On a Kubernetes node this means pod-to-pod and pod-to-host
  traffic; traffic to endpoints outside the node is seen from the local side only.

## Development

Unit-test the userspace HTTP parser (no root or kernel required):

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
