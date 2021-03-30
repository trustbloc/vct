# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH 		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.39.0
MOCK_VERSION 	?=v1.5.0
PROJECT_ROOT 	=github.com/trustbloc/vct
GOMOCKS			=pkg/internal/gomocks

.PHONY: all
all: clean checks unit-test

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
	@go test $(shell go list ./... | grep -v /gomocks/) -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m

.PHONY: clean
clean: clean-mocks
	@rm -rf ./build
	@rm -rf coverage.out

.PHONY: mockgen
mockgen:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)

.PHONY: mocks
mocks: mockgen clean-mocks
	$(call create_mock,pkg/controller/command,KeyManager;TrillianLogClient;Crypto)

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
