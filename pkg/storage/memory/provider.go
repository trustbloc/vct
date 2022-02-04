/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/provider.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memory

import (
	"sync"

	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/memory"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("memory")

var (
	newOnce     sync.Once        //nolint: gochecknoglobals
	newInstance storage.Provider //nolint: gochecknoglobals
)

type memProvider struct {
	mf monitoring.MetricFactory
	ts *memory.TreeStorage
}

// NewMemoryStorageProvider return new memory provider.
func NewMemoryStorageProvider(mf monitoring.MetricFactory) (storage.Provider, error) {
	newOnce.Do(func() {
		logger.Errorf("once")
		newInstance = &memProvider{
			mf: mf,
			ts: memory.NewTreeStorage(),
		}
	})
	logger.Errorf("return from new")

	return newInstance, nil
}

func (s *memProvider) LogStorage() storage.LogStorage {
	return memory.NewLogStorage(s.ts, s.mf)
}

func (s *memProvider) AdminStorage() storage.AdminStorage {
	return memory.NewAdminStorage(s.ts)
}

func (s *memProvider) Close() error {
	return nil
}
