#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FROM mysql:8.0.25

COPY images/db/mysql/storage.sql /docker-entrypoint-initdb.d/storage.sql
RUN chmod -R 775 /docker-entrypoint-initdb.d
