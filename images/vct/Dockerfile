#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . $GOPATH/src/github.com/trustbloc/vct
WORKDIR $GOPATH/src/github.com/trustbloc/vct
ENV EXECUTABLES go git

FROM golang as vct
LABEL org.opencontainers.image.source https://github.com/trustbloc/vct

RUN make build-vct

FROM alpine:${ALPINE_VER} as base
RUN apk add -U --no-cache ca-certificates
COPY --from=vct /go/src/github.com/trustbloc/vct/build/bin/vct /usr/local/bin
ENTRYPOINT ["vct"]