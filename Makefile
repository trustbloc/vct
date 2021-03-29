# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.39.0

.PHONY: all
all: clean checks

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	@$(GOBIN_PATH)/golangci-lint run

.PHONY: unit-test
unit-test:
	@go test ./... -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf coverage.out
