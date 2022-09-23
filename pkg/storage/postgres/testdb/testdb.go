/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/testdb/testdb.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package testdb creates new databases for tests.
package testdb

import (
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"time"

	"github.com/google/trillian/testonly"

	"github.com/trustbloc/vct/internal/pkg/log"
)

var logger = log.New("storage/testdb")

// nolint: gochecknoglobals
var (
	trillianSQL = testonly.RelativeToPackage("../schema/storage.sql")
	pgOpts      = flag.String("pg_opts", "sslmode=disable", "Database options to be included when connecting to the db")
	dbName      = flag.String("db_name", "test", "The database name to be used when checking for pg connectivity")
)

// PGAvailable indicates whether a default PG database is available.
func PGAvailable() bool {
	db, err := sql.Open("postgres", getConnStr(*dbName))
	if err != nil {
		return false
	}
	defer db.Close() // nolint: errcheck

	if err := db.Ping(); err != nil {
		return false
	}

	return true
}

// newEmptyDB creates a new, empty database.
// The returned clean up function should be called once the caller no longer
// needs the test DB.
func newEmptyDB(ctx context.Context) (*sql.DB, func(context.Context), error) {
	db, err := sql.Open("postgres", getConnStr(*dbName))
	if err != nil {
		return nil, nil, err
	}

	// Create a randomly-named database and then connect using the new name.
	name := fmt.Sprintf("trl_%v", time.Now().UnixNano())
	stmt := fmt.Sprintf("CREATE DATABASE %v", name)

	if _, err = db.ExecContext(ctx, stmt); err != nil {
		return nil, nil, fmt.Errorf("error running statement %q: %w", stmt, err)
	}

	db.Close() // nolint: errcheck, gosec

	db, err = sql.Open("postgres", getConnStr(name))
	if err != nil {
		return nil, nil, err
	}

	done := func(ctx context.Context) {
		defer db.Close() // nolint: errcheck

		db, err = sql.Open("postgres", getConnStr("test"))
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE %v  WITH (FORCE);", name)); err != nil {
			logger.Warnf("Failed to drop test database %q: %v", name, err)
		}

		db.Close() // nolint: errcheck, gosec
	}

	return db, done, db.Ping() // nolint: gocritic
}

// NewTrillianDB creates an empty database with the Trillian schema. The database name is randomly
// generated.
// NewTrillianDB is equivalent to Default().NewTrillianDB(ctx).
func NewTrillianDB(ctx context.Context) (*sql.DB, func(context.Context), error) {
	db, done, err := newEmptyDB(ctx)
	if err != nil {
		return nil, nil, err
	}

	sqlBytes, err := ioutil.ReadFile(path.Clean(trillianSQL))
	if err != nil {
		return nil, nil, err
	}

	for _, stmt := range strings.Split(sanitize(string(sqlBytes)), ";--end") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, nil, fmt.Errorf("error running statement %q: %w", stmt, err)
		}
	}

	return db, done, nil
}

// sanitize tries to remove empty lines and comments from a sql script
// to prevent them from being executed.
func sanitize(script string) string {
	buf := &bytes.Buffer{}

	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || strings.Index(line, "--") == 0 {
			continue // skip empty lines and comments
		}

		buf.WriteString(line)
		buf.WriteString("\n")
	}

	return buf.String()
}

func getConnStr(name string) string {
	return fmt.Sprintf("user=postgres password=password database=%s %s", name, *pgOpts)
}
