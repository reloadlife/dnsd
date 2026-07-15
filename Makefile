MODULE  := github.com/reloadlife/dnsd
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w \
	-X main.version=$(VERSION)

.PHONY: all build test test-race vet cover ci run clean install

all: build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/dnsd ./cmd/dnsd
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/dnsctl ./cmd/dnsctl

test:
	go test ./... -count=1

test-race:
	go test ./... -count=1 -race

cover:
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -20

vet:
	go vet ./...

ci: vet test-race build

run: build
	./bin/dnsd --listen 127.0.0.1:51920 --token dev-token --dns-listen 127.0.0.1:5353

DNSD_LOCAL ?= $(HOME)/.local/share/networkingd/daemons/dnsd/bin
LOCAL_BIN ?= $(HOME)/.local/bin

install: build
	mkdir -p /usr/local/bin
	install -m 755 bin/dnsd bin/dnsctl /usr/local/bin/
	mkdir -p "$(LOCAL_BIN)"
	ln -sfn /usr/local/bin/dnsctl "$(LOCAL_BIN)/dnsctl"
	ln -sfn /usr/local/bin/dnsd "$(LOCAL_BIN)/dnsd"
	@if [ -d "$(HOME)/.local/share/networkingd/daemons" ]; then \
	  mkdir -p "$(DNSD_LOCAL)"; \
	  install -m 755 bin/dnsd bin/dnsctl "$(DNSD_LOCAL)/"; \
	  echo "installed to $(DNSD_LOCAL)"; \
	fi
	@echo "installed: /usr/local/bin/dnsd /usr/local/bin/dnsctl"

clean:
	rm -rf bin
