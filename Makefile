BIN     := ai-auth
PKG     := github.com/linktoming/ai-auth
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)

.PHONY: all build test race vet fmt lint demo clean install

all: vet test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/ai-auth

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/ai-auth

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: vet
	@gofmt -l . | grep . && { echo "gofmt found unformatted files"; exit 1; } || echo "formatting clean"

demo: build
	./examples/demo.sh

clean:
	rm -f $(BIN)
