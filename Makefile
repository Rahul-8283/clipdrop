BINARY := clipdrop
PKG := ./cmd/clipdrop
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X github.com/Rahul-8283/clipdrop/app.Version=$(VERSION) -X github.com/Rahul-8283/clipdrop/app.Commit=$(COMMIT) -X github.com/Rahul-8283/clipdrop/app.BuildDate=$(BUILD_DATE)"

.PHONY: all build run test clean

all: build

build:
	go build $(LDFLAGS) -o $(BINARY) $(PKG)

run:
	go run $(LDFLAGS) $(PKG) $(ARGS)

test:
	go test -race -v ./test/...

clean:
	rm -f $(BINARY) $(BINARY).exe
