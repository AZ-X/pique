OUT_DIR := bin
PROG := repique

VERSION ?= $(shell cat VERSION)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOVERSION ?= $(shell go version | sed -nr 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

ifeq ($(GOOS),windows)
	BIN_SUFFIX := .exe
endif

.PHONY: build
build:
	go build -trimpath -mod=vendor -buildmode=exe -gcflags=-trimpath=$(GOPATH) -asmflags=-trimpath=$(GOPATH) -ldflags "-buildid= -s -w -X main.goversion=$(GOVERSION) -X main.AppVersion=$(VERSION)" -o $(OUT_DIR)/$(PROG)$(BIN_SUFFIX) ./repique
