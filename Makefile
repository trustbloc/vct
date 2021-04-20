# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH 		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.39.0
MOCK_VERSION 	?=v1.5.0
PROJECT_ROOT 	=github.com/trustbloc/vct

DOCKER_OUTPUT_NS 	?=ghcr.io
VCT_IMAGE_NAME 		?=trustbloc/vct

ALPINE_VER ?= 3.12
GO_VER ?= 1.16

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

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
	@go test $(shell go list ./... | grep -v /test/bdd) -count=1 -race -coverprofile=coverage.out -covermode=atomic -timeout=10m

.PHONY: bdd-test
bdd-test: generate-test-keys build-vct-docker
	@go test github.com/trustbloc/vct/test/bdd -count=1 -v -cover . -p 1 -timeout=20m -race

.PHONY: build-vct
build-vct:
	@echo "Building verifiable credentials transparency (vct)"
	@go build -o build/bin/vct cmd/vct/main.go

.PHONY: build-vct-dist
build-vct-dist:
	@echo "Building verifiable credentials transparency (vct)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/dist/bin/vct-linux-amd64 cmd/vct/main.go
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o build/dist/bin/vct-linux-arm64 cmd/vct/main.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o build/dist/bin/vct-darwin-arm64 cmd/vct/main.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o build/dist/bin/vct-darwin-amd64 cmd/vct/main.go
	@for f in build/dist/bin/vct*; do shasum -a 256 $$f > $$f.sha256; done

.PHONY: build-vct-docker
build-vct-docker:
	@echo "Building verifiable credentials transparency (vct) docker image"
	@docker build -f ./images/vct/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VCT_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER)  .

.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p test/bdd/fixtures/vct/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/vct \
		--entrypoint "/opt/workspace/vct/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf test/bdd/fixtures/vct/keys
	@rm -rf ./test/bdd/build
	@rm -rf coverage.out
	@find . -name "gomocks_test.go" -delete

.PHONY: mocks
mocks:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@go generate ./...
