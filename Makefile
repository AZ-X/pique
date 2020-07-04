OUT_DIR := out
PROG := dnscrypt-proxy

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

ifeq ($(GOOS),windows)
	BIN_SUFFIX := ".exe"
endif

.PHONY: build
build:
	go build -trimpath -mod=vendor -buildmode=exe -ldflags "-s -w -X main.goversion=1.14" -o $(OUT_DIR)/$(PROG)$(BIN_SUFFIX) ./

.PHONY: dep
clean:
	go clean -ldflags "-s -w -X main.goversion=1.14"
dep:
	dep ensure

