#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER
ARG BUILDPLATFORM

FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:${GO_VER}-alpine${ALPINE_VER} as builder

RUN apk update && apk add git && apk add ca-certificates
RUN adduser -D -g '' appuser
COPY . $GOPATH/src/github.com/trustbloc/vct/
WORKDIR $GOPATH/src/github.com/trustbloc/vct/

ARG TARGETOS
ARG TARGETARCH
ARG APP_FOLDER

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /usr/bin/binary ./cmd/${APP_FOLDER}

FROM scratch

LABEL org.opencontainers.image.source https://github.com/trustbloc/vct

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/bin/binary /usr/bin/binary
USER appuser

ENTRYPOINT ["/usr/bin/binary"]
