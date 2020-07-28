OUT_DIR := bin
PROG := dnscrypt-proxy

VERSION ?= $(shell cat VERSION)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOVERSION ?= $(shell go version | sed -nr 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

ifeq ($(GOOS),windows)
	BIN_SUFFIX := ".exe"
endif

.PHONY: build
build:
	go build -trimpath -mod=vendor -buildmode=exe -ldflags "-buildid= -s -w -X main.goversion=$(GOVERSION) -X main.AppVersion=$(VERSION)" -o $(OUT_DIR)/$(PROG)$(BIN_SUFFIX) ./dnscrypt-proxy

.PHONY: dep
clean:
	go clean -ldflags "-s -w -X main.goversion=1.14"
dep:
	dep ensure

