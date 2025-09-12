
APP            ?= deepfuzz
PKG            ?= ./cmd/deepfuzz
DATE           := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT         := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
VERSION        ?= $(shell git describe --tags --always 2>/dev/null || echo "v0.0.0-dev")
MODULE         := $(shell go list -m 2>/dev/null || echo "https://github.com/bl4ck0w1/deepFuzz/proto")

LD_FLAGS       = -s -w \
                 -X 'main.Version=$(VERSION)' \
                 -X 'main.Commit=$(COMMIT)' \
                 -X 'main.Date=$(DATE)'

PROTO_DIR      := proto
PROTO_OUT      := $(PROTO_DIR)

.PHONY: all
all: build 

.PHONY: tools
tools: 
	@command -v protoc >/dev/null || (echo "ERROR: protoc not found. Install from https://grpc.io/docs/protoc-installation/"; exit 1)
	@command -v protoc-gen-go >/dev/null || GOBIN=$$(go env GOPATH)/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@command -v protoc-gen-go-grpc >/dev/null || GOBIN=$$(go env GOPATH)/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

.PHONY: proto
proto: tools
	@mkdir -p $(PROTO_OUT)
	protoc -I $(PROTO_DIR) \
		--go_out=$(PROTO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/adaptive_engine.proto \
		$(PROTO_DIR)/waf_generator.proto \
		$(PROTO_DIR)/response_cluster.proto
	@echo "OK: protobufs generated under $(PROTO_OUT)"
	@echo "NOTE: Make sure option go_package in .proto matches: $(MODULE)/$(PROTO_OUT)/<pkg> ; <pkg>"

.PHONY: proto-clean
proto-clean: 
	@rm -rf $(PROTO_OUT)

.PHONY: tidy
tidy: 
	@go mod tidy

.PHONY: fmt
fmt: 
	@go fmt ./...

.PHONY: vet
vet: 
	@go vet ./...

.PHONY: build
build: 
	@mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 go build -ldflags "$(LD_FLAGS)" -o bin/$(APP) $(PKG)
	@echo "Built bin/$(APP) (Version=$(VERSION) Commit=$(COMMIT))"

.PHONY: test
test: 
	@go test -race -count=1 ./...

.PHONY: cover
cover: 
	@go test -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -n 1

OS_ARCHES = \
	darwin/amd64 darwin/arm64 \
	linux/amd64 linux/arm64 \
	windows/amd64

.PHONY: build-all
build-all:
	@mkdir -p dist
	@for target in $(OS_ARCHES); do \
		GOOS=$${target%/*}; GOARCH=$${target#*/}; \
		out="dist/$(APP)-$$GOOS-$$GOARCH"; \
		if [ "$$GOOS" = "windows" ]; then out="$$out.exe"; fi; \
		echo ">> Building $$out"; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags "$(LD_FLAGS)" -o $$out $(PKG) || exit 1; \
	done
	@echo "OK: binaries in dist/"

.PHONY: clean
clean:
	@rm -rf bin dist coverage.out $(PROTO_OUT)

.PHONY: help
help: 
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_\-\/]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
