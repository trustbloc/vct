/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/provider.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"database/sql"
	"sync"

	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/storage"

	// Load PG driver.
	_ "github.com/lib/pq"
)

// nolint: gochecknoglobals
var (
	PGConnStr         string
	pgOnce            sync.Once
	pgOnceErr         error //nolint: errname
	pgStorageInstance *pgProvider
)

type pgProvider struct {
	db *sql.DB
	mf monitoring.MetricFactory
}

// NewPGProvider return new pg provider.
func NewPGProvider(mf monitoring.MetricFactory) (storage.Provider, error) {
	pgOnce.Do(func() {
		var db *sql.DB
		db, pgOnceErr = OpenDB(PGConnStr)
		if pgOnceErr != nil {
			return
		}

		pgStorageInstance = &pgProvider{
			db: db,
			mf: mf,
		}
	})

	if pgOnceErr != nil {
		return nil, pgOnceErr
	}

	return pgStorageInstance, nil
}

func (s *pgProvider) LogStorage() storage.LogStorage {
	logger.Warn("Support for the PostgreSQL log is experimental.  Please use at your own risk!!!")

	return NewLogStorage(s.db, s.mf)
}

func (s *pgProvider) AdminStorage() storage.AdminStorage {
	return NewAdminStorage(s.db)
}

func (s *pgProvider) Close() error {
	return s.db.Close()
}
