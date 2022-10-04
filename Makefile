# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH 		=$(abspath .)/build/bin
LINT_VERSION 	?=v1.39.0
MOCK_VERSION 	?=v1.5.0
SWAGGER_VERSION ?=v0.27.0
SWAGGER_DIR		="./test/bdd/fixtures/vct/specs"
SWAGGER_OUTPUT	=$(SWAGGER_DIR)"/openAPI.yml"
PROJECT_ROOT 	=github.com/trustbloc/vct

DOCKER_OUTPUT_NS 	?=ghcr.io
VCT_IMAGE_NAME 		?=trustbloc/vct
LOG_SERVER_IMAGE_NAME ?=trustbloc/vct-log-server
LOG_SIGNER_IMAGE_NAME ?=trustbloc/vct-log-signer

ALPINE_VER ?= 3.15
GO_VER ?= 1.17

OS := $(shell uname)
ifeq  ($(OS),$(filter $(OS),Darwin Linux))
	PATH:=$(PATH):$(GOBIN_PATH)
else
	PATH:=$(PATH);$(subst /,\\,$(GOBIN_PATH))
endif

.PHONY: all
all: clean checks unit-test bdd-test

.PHONY: checks
checks: clean license lint open-api-spec

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint: mocks
	@GOBIN=$(GOBIN_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINT_VERSION)
	@$(GOBIN_PATH)/golangci-lint run

.PHONY: unit-test
unit-test: mocks
	@scripts/check_unit.sh

.PHONY: bdd-test
bdd-test: generate-test-keys build-vct-docker build-log-server-docker build-log-signer-docker
	@go test github.com/trustbloc/vct/test/bdd -count=1 -v -cover . -p 1 -timeout=20m -race
	@VCT_LOGS=maple2020:rw,maple2021:rw,maple2022:r,maple2023:w,maple2024:rw go test github.com/trustbloc/vct/test/bdd -count=1 -v -cover . -p 1 -timeout=20m -race


.PHONY: build-vct
build-vct:
	@echo "Building verifiable credentials transparency (vct)"
	@go build -o build/bin/vct cmd/vct/main.go

.PHONY: build-log-server
build-log-server:
	@echo "Building log server (log-server)"
	@go build -o build/bin/log-server cmd/log_server/main.go

.PHONY: build-log-signer
build-log-signer:
	@echo "Building log signer (log-signer)"
	@go build -o build/bin/log-signer cmd/log_signer/main.go

.PHONY: build-vct-dist
build-vct-dist:
	@echo "Building verifiable credentials transparency (vct)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/dist/bin/vct-linux-amd64 cmd/vct/main.go
	@cd build/dist/bin;tar cvzf vct-linux-amd64.tar.gz vct-linux-amd64;rm -rf vct-linux-amd64
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o build/dist/bin/vct-linux-arm64 cmd/vct/main.go
	@cd build/dist/bin;tar cvzf vct-linux-arm64.tar.gz vct-linux-arm64;rm -rf vct-linux-arm64
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o build/dist/bin/vct-darwin-arm64 cmd/vct/main.go
	@cd build/dist/bin;tar cvzf vct-darwin-arm64.tar.gz vct-darwin-arm64;rm -rf vct-darwin-arm64
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o build/dist/bin/vct-darwin-amd64 cmd/vct/main.go
	@cd build/dist/bin;tar cvzf vct-darwin-amd64.tar.gz vct-darwin-amd64;rm -rf vct-darwin-amd64
	@for f in build/dist/bin/vct*; do shasum -a 256 $$f > $$f.sha256; done

.PHONY: build-log-server-dist
build-log-server-dist:
	@echo "Building log server (log-server)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/dist/bin/log-server-linux-amd64 cmd/log_server/main.go
	@cd build/dist/bin;tar cvzf log-server-linux-amd64.tar.gz log-server-linux-amd64;rm -rf log-server-linux-amd64
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o build/dist/bin/log-server-linux-arm64 cmd/log_server/main.go
	@cd build/dist/bin;tar cvzf log-server-linux-arm64.tar.gz log-server-linux-arm64;rm -rf log-server-linux-arm64
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o build/dist/bin/log-server-darwin-arm64 cmd/log_server/main.go
	@cd build/dist/bin;tar cvzf log-server-darwin-arm64.tar.gz log-server-darwin-arm64;rm -rf log-server-darwin-arm64
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o build/dist/bin/log-server-darwin-amd64 cmd/log_server/main.go
	@cd build/dist/bin;tar cvzf log-server-darwin-amd64.tar.gz log-server-darwin-amd64;rm -rf log-server-darwin-amd64
	@for f in build/dist/bin/log-server*; do shasum -a 256 $$f > $$f.sha256; done

.PHONY: build-log-signer-dist
build-log-signer-dist:
	@echo "Building log signer (log-signer)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/dist/bin/log-signer-linux-amd64 cmd/log_signer/main.go
	@cd build/dist/bin;tar cvzf log-signer-linux-amd64.tar.gz log-signer-linux-amd64;rm -rf log-signer-linux-amd64
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o build/dist/bin/log-signer-linux-arm64 cmd/log_signer/main.go
	@cd build/dist/bin;tar cvzf log-signer-linux-arm64.tar.gz log-signer-linux-arm64;rm -rf log-signer-linux-arm64
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o build/dist/bin/log-signer-darwin-arm64 cmd/log_signer/main.go
	@cd build/dist/bin;tar cvzf log-signer-darwin-arm64.tar.gz log-signer-darwin-arm64;rm -rf log-signer-darwin-arm64
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o build/dist/bin/log-signer-darwin-amd64 cmd/log_signer/main.go
	@cd build/dist/bin;tar cvzf log-signer-darwin-amd64.tar.gz log-signer-darwin-amd64;rm -rf log-signer-darwin-amd64
	@for f in build/dist/bin/log-signer*; do shasum -a 256 $$f > $$f.sha256; done

.PHONY: build-vct-docker
build-vct-docker:
	@echo "Building verifiable credentials transparency (vct) docker image"
	@docker build -f ./images/vct/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(VCT_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg APP_FOLDER=vct \
	--build-arg ALPINE_VER=$(ALPINE_VER)  .

.PHONY: build-log-server-docker
build-log-server-docker:
	@echo "Building log server docker image"
	@docker build -f ./images/vct/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(LOG_SERVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg APP_FOLDER=log_server \
	--build-arg ALPINE_VER=$(ALPINE_VER)  .

.PHONY: build-log-signer-docker
build-log-signer-docker:
	@echo "Building log signer docker image"
	@docker build -f ./images/vct/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(LOG_SIGNER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg APP_FOLDER=log_signer \
	--build-arg ALPINE_VER=$(ALPINE_VER)  .

# TODO (#125): frapsoft/openssl only has an amd64 version. While this does work under amd64 and arm64 Mac OS currently,
#               we should add an arm64 version for systems that can only run arm64 code.
.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p ./test/bdd/fixtures/vct/keys/tls
	@docker run -i --platform linux/amd64 --rm \
		-v $(abspath .):/opt/workspace/vct \
		--entrypoint "/opt/workspace/vct/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean:
	@rm -rf ./build
	@rm -rf ./test/bdd/fixtures/vct/keys/tls
	@rm -rf ./test/bdd/build
	@rm -rf coverage.out
	@rm -rf $(SWAGGER_DIR)
	@find . -name "gomocks_test.go" -delete

.PHONY: mocks
mocks:
	@GOBIN=$(GOBIN_PATH) go install github.com/golang/mock/mockgen@$(MOCK_VERSION)
	@go generate ./...

.PHONY: open-api-spec
open-api-spec:
	@GOBIN=$(GOBIN_PATH) go install github.com/go-swagger/go-swagger/cmd/swagger@$(SWAGGER_VERSION)
	@echo "Generating Open API spec."
	@mkdir $(SWAGGER_DIR)
	@$(GOBIN_PATH)/swagger generate spec -w ./cmd/vct -o $(SWAGGER_OUTPUT)
	@echo "Validating generated spec"
	@$(GOBIN_PATH)/swagger validate $(SWAGGER_OUTPUT)

.PHONY: run-open-api-demo
run-open-api-demo: clean build-vct-docker build-log-server-docker build-log-signer-docker generate-test-keys open-api-spec
	@echo "Running Open API demo on http://localhost:8089/openapi"
	@docker-compose -f test/bdd/fixtures/vct/docker-compose.yml up --force-recreate -d vct.openapi.com
