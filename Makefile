.DEFAULT_GOAL := build

GO ?= go
GOFMT ?= gofmt
VERSION ?= dev
CHROME_BIN ?= chromium

.PHONY: build test test-race integration vet fmt check clean help

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/aalogin ./cmd/aalogin

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

integration:
	CHROME_BIN="$(CHROME_BIN)" $(GO) test -tags=integration ./internal/browser -run TestBrowserFlow -count=1

vet:
	$(GO) vet ./...

fmt:
	$(GOFMT) -w cmd internal

check: vet test-race

clean:
	rm -f bin/aalogin

help:
	@printf '%s\n' \
	  'make                         Build bin/aalogin (static; VERSION=dev)' \
	  'make build VERSION=1.0.0     Embed a version in the executable' \
	  'make test                   Run ordinary tests without a browser' \
	  'make test-race              Run ordinary tests with the race detector' \
	  'make integration            Run real Chromium fixtures (CHROME_BIN=chromium)' \
	  'make vet                    Run Go static analysis' \
	  'make fmt                    Format Go source in cmd/ and internal/' \
	  'make check                  Run static analysis and race-enabled tests' \
	  'make clean                  Remove only the generated bin/aalogin executable'
