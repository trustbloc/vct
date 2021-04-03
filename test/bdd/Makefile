# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GOBIN_PATH=$(abspath .)/build/bin
ADMIN_SERVER ?=:8090

.PHONY: createtree
createtree: export GOBIN=$(GOBIN_PATH)
createtree:
	@go install github.com/google/trillian/cmd/createtree@v1.3.13
	@$(eval LOG_ID=$(shell $(GOBIN_PATH)/createtree --admin_server=$(ADMIN_SERVER)))
	@echo $(LOG_ID)
