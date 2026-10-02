BINARY  := argus
PKG     := github.com/guaidao2/argus
CMD     := ./cmd/argus
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

# A static binary is the whole point: no cgo, no runtime dependencies, so the
# same file runs on any machine of that platform.
GOFLAGS := CGO_ENABLED=0

.PHONY: all build test test-race vet fmt lint cover install clean cross smoke

all: fmt vet test build

build:
	$(GOFLAGS) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

install:
	$(GOFLAGS) go install -trimpath -ldflags "$(LDFLAGS)" $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# gofmt -l prints the files that would change; failing on a non-empty list keeps
# formatting honest in CI without needing a formatter dependency.
check-fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt'd:"; echo "$$out"; exit 1; fi

cover:
	go test -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -func=coverage.txt | tail -1

cross:
	$(GOFLAGS) GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64     $(CMD)
	$(GOFLAGS) GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64     $(CMD)
	$(GOFLAGS) GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64    $(CMD)
	$(GOFLAGS) GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64    $(CMD)
	$(GOFLAGS) GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe $(CMD)
	$(GOFLAGS) GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-arm64.exe $(CMD)

# Release archives: the binaries from cross, plus what someone needs to run and
# extend argus. The plugin guide is in there on purpose - the whole point of the
# YAML rule format is that the rules are meant to be written by whoever uses it,
# and that is not discoverable from the binary alone.
#
# Pass VERSION explicitly for a release: the default comes from git describe,
# which has no tag to find on a tree that has not been tagged yet.
#
#	make package VERSION=1.0.0
DISTNAME := $(BINARY)-$(VERSION)

.PHONY: package
package: cross
	@rm -rf dist/stage
	@for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do \
		stage=dist/stage/$(DISTNAME)-$$target; \
		mkdir -p $$stage/docs; \
		cp dist/$(BINARY)-$$target $$stage/$(BINARY); \
		cp README.md README.zh-CN.md LICENSE $$stage/; \
		cp docs/plugin-guide.md docs/plugin-guide.zh-CN.md $$stage/docs/; \
		tar -czf dist/$(DISTNAME)-$$target.tar.gz -C dist/stage $(DISTNAME)-$$target; \
		rm -rf $$stage; \
	done
	@for target in windows-amd64 windows-arm64; do \
		stage=dist/stage/$(DISTNAME)-$$target; \
		mkdir -p $$stage/docs; \
		cp dist/$(BINARY)-$$target.exe $$stage/$(BINARY).exe; \
		cp docs/plugin-guide.md docs/plugin-guide.zh-CN.md $$stage/docs/; \
		cp README.md README.zh-CN.md LICENSE $$stage/; \
		(cd dist/stage && zip -qr ../$(DISTNAME)-$$target.zip $(DISTNAME)-$$target); \
		rm -rf $$stage; \
	done
	@rm -rf dist/stage
	@echo "=== archives ==="
	@ls -lh dist/*.tar.gz dist/*.zip

# Scans the loopback interface, which is a self contained smoke test.
smoke: build
	./$(BINARY) -Pn -sV -p 1-1024 --hack-reason 127.0.0.1

clean:
	rm -rf $(BINARY) dist coverage.txt
