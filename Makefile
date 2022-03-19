OUT_DIR := bin
OUT2_DIR := dump
PROG := repique

VERSION ?= $(shell cat VERSION)
GOOS ?= $(shell go env GOOS)
GOROOT ?= $(shell go env GOROOT)
GOARCH ?= $(shell go env GOARCH)
GOVERSION ?= $(shell go version | sed -nr 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')
MKFILE_DIR := $(strip $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST)))))

ifeq ($(GOOS),windows)
	BIN_SUFFIX := .exe
endif

.PHONY: build
build:
	go build -a -trimpath -mod=vendor -buildmode=exe -gcflags="all=-smallframes -json=0,$(MKFILE_DIR)/$(OUT2_DIR)/foo.json -trimpath=$(MKFILE_DIR)" -asmflags=-trimpath=$(MKFILE_DIR) -ldflags "-buildid= -s -w -X main.goversion=$(GOVERSION) -X main.AppVersion=$(VERSION)" -o $(OUT_DIR)/$(PROG)$(BIN_SUFFIX) ./repique
