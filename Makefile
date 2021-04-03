# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH 		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.39.0
MOCK_VERSION 	?=v1.5.0
PROJECT_ROOT 	=github.com/trustbloc/vct
GOMOCKS			=pkg/internal/gomocks

DOCKER_OUTPUT_NS 	?=ghcr.io
VCT_IMAGE_NAME 		?=trustbloc/vct

ALPINE_VER ?= 3.12
GO_VER ?= 1.16

.PHONY: all
all: clean checks unit-test bdd-test

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint: mocks
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	@$(GOBIN_PATH)/golangci-lint run

.PHONY: unit-test
unit-test: mocks
	@go test $(shell go list ./... | grep -v /gomocks/ | grep -v /test/bdd) -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m

.PHONY: bdd-test
bdd-test: build-vct-docker
	@go test github.com/trustbloc/vct/test/bdd -count=1 -v -cover . -p 1 -timeout=20m -race

.PHONY: build-vct
build-vct:
	@echo "Building verifiable credentials transparency (vct)"
	@go build -o build/bin/vct cmd/vct/main.go

.PHONY: build-vct-docker
build-vct-docker:
	@echo "Building verifiable credentials transparency (vct) docker image"
	@docker build -f ./images/vct/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VCT_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER)  .

.PHONY: clean
clean: clean-mocks
	@rm -rf ./build
	@rm -rf ./test/bdd/build
	@rm -rf coverage.out

.PHONY: mocks
mocks: clean-mocks
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	$(call create_mock,pkg/controller/command,KeyManager;TrillianLogClient;Crypto)
	$(call create_mock,pkg/controller/rest,Cmd)

.PHONY: clean-mocks
clean-mocks:
	@if [ -d $(GOMOCKS) ]; then rm -r $(GOMOCKS); echo "Folder $(GOMOCKS) was removed!"; fi

comma:= ,
semicolon:= ;
mocks_dir =

define create_mock
  $(eval mocks_dir := $(subst pkg,$(GOMOCKS),$(1)))
  @echo Creating $(mocks_dir)
  @mkdir -p $(mocks_dir) && rm -rf $(mocks_dir)/*
  @$(GOBIN_PATH)/mockgen -destination $(mocks_dir)/mocks.go -self_package mocks -package mocks $(PROJECT_ROOT)/$(1) $(subst $(semicolon),$(comma),$(2))
endef
