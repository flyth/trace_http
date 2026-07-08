# Image coordinates. Override on the command line or via env, e.g.:
#   make build IMAGE=ghcr.io/my-org/trace_http TAG=v0.1.0
IMAGE ?= ghcr.io/your-org/trace_http
TAG   ?= latest
IG    ?= ig

IMAGE_REF := $(IMAGE):$(TAG)

.PHONY: build push run test unit clean

# --- build (needs docker for the ig builder container) ---

build:
	sudo -E $(IG) image build -t $(IMAGE_REF) .

# --- push (run `docker login` / CI login first) ---

push:
	sudo -E $(IG) image push $(IMAGE_REF)

# --- run ---
# The gadget captures every connection on the node (its sock_ops program is
# attached to the cgroup-v2 root). Filter with the usual ig flags as needed.

run:
	sudo -E $(IG) run $(IMAGE_REF) --host

# --- test ---

# Unit-test the userspace HTTP parser (no root, no kernel needed).
unit:
	cd go && go test ./...

# Build the image then smoke-test it (loads on the kernel, captures a request).
test: build
	sudo IG=$(IG) bash test/smoke.sh $(IMAGE_REF)

clean:
	sudo -E $(IG) image remove $(IMAGE_REF) || true
