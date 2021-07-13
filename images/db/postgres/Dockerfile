#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FROM postgres:13

COPY images/db/postgres/storage.sql /docker-entrypoint-initdb.d/storage.sql
RUN chmod -R 775 /docker-entrypoint-initdb.d
