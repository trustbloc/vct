[![Release](https://img.shields.io/github/release/trustbloc/vct.svg?style=flat-square)](https://github.com/trustbloc/vct/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/vct/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/vct)

[![Build Status](https://github.com/trustbloc/vct/workflows/build/badge.svg)](https://github.com/trustbloc/vct/actions)
[![codecov](https://codecov.io/gh/trustbloc/vct/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/vct)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/vct)](https://goreportcard.com/report/github.com/trustbloc/vct)

# Verifiable Credential Transparency

The Verifiable Credential Transparency (VCT) is based on certificate transparency [RFC6962](https://datatracker.ietf.org/doc/html/rfc6962).
The Credentials are included into VCT as append-only [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) logs.
VCT uses the existing Merkle Tree implementation provided by [Trillian](https://github.com/google/trillian).
VCT was created for the [orb](https://github.com/trustbloc/orb#orb-did-method) project and its usage is described [here](https://trustbloc.github.io/did-method-orb/#witness-ledger).

## Build and test

To build and test VCT you need:

* Go 1.16 or later
* GNU Make
* Bash
* Docker and Docker-Compose

Run tests:

```make unit-test bdd-test```

## Deploy

VCT itself is a compound of three essential components.

* log-server
* log-signer
* vct

To deploy the service you would need to build them first.

`make build-vct build-log-server build-log-signer`

1. Run the log-server.

Log server depends on the database. To run DB you can simply use `docker-compose` for that.

NOTE: We support MySQL and Postgres. If you run your own DB service, do not forget to import schema.
See [MySQL schema](https://github.com/trustbloc/vct/blob/main/test/bdd/fixtures/vct/mysql-config/mysql_config.sql)
and [Postgres schema](https://github.com/trustbloc/vct/blob/main/test/bdd/fixtures/vct/postgres-config/postgres_config.sql).

Run MySQL by using `docker-compose`:

`cd ./test/bdd/fixtures/vct && docker-compose up vct.mysql`

Then run the log-server.

`./build/bin/log-server --mysql_uri="root@tcp(localhost:3306)/test"`

Log server will start the RPC server on `localhost:8090` and  HTTP server on `localhost:8091`.

Use help flag to find out all available flags `./build/bin/log-server -h`.

2. Run the log-signer.

Log signer must be run with the same DB configuration as a `log-server`.
Log signer will start the RPC server on `localhost:8090` and  HTTP server on `localhost:8091`.
Since those ports are already occupied by the `log-server`, let's change them.

` ./build/bin/log-signer --mysql_uri="root@tcp(localhost:3306)/test" --force_master=true --http_endpoint=0.0.0.0:8099 --rpc_endpoint=0.0.0.0:8098   `

Use help flag to find out all available flags `./build/bin/log-signer -h`.

3.  Run the vct.

` ./build/bin/vct start --logs=maple2021:rw@127.0.0.1:8090`

The required argument here is `--logs`. It specifies an alias for the log, permissions and `log-service` RPC endpoint.
For example, if we want to change logs yearly we can do the following:
`--logs=maple2020:r@127.0.0.1:8090,maple2021:rw@127.0.0.1:8090`

An alias (e.g maple2021) can be any string and it will represent a log-id.
When an alias (e.g maple2021) is provided the service will try to get the correlated log-id from the DB,
if the record does not exist the service will create a new log-id and it will be assigned to the given alias.
The database can be specified by using the `--dsn` argument.

The vct server by default will be run on `localhost:5678`.

Use help flag to find out all available flags `./build/bin/vct -h`.

## Databases

### VCT Storage

VCT uses Aries generic storage interface for storing data.
Backup should be done similarly to other trustbloc projects.
In VCT we support the following databases:
* CouchDB
* MySQL
* Memory (backup is not supported)

Use the database-specific command to get all databases and filter them by `VCT_DATABASE_PREFIX` env.

For instance, to get all databases for CouchDB use the following command:
```
curl -X GET http://admin:password@127.0.0.1:5984/_all_dbs
```
Output:
```
["_replicator","_users","kmspkprimarykey","vctdbmaple2021jsonldcontexts","vctdbconfig"]
```

Then, filter databases from the output above by `VCT_DATABASE_PREFIX=vctdb` env.
Databases we need to backup are `vctdbmaple2021jsonldcontexts` and `vctdbconfig`
Make a backup according to CouchDB documentation.

### Trillian Storage

For Trillian we support the following databases:
* Postgres
* MySQL

Backup should be done according to the official documentation (Postgres or MySQL).

See schemas for better understanding:
* [MySQL schema](https://github.com/trustbloc/vct/blob/main/test/bdd/fixtures/vct/mysql-config/mysql_config.sql)
* [Postgres schema](https://github.com/trustbloc/vct/blob/main/test/bdd/fixtures/vct/postgres-config/postgres_config.sql).

Note: If you want to restore a backup from the ground up make sure that schema was imported first.

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
