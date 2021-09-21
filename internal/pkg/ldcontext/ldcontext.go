/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ldcontext

import (
	"embed"
	"encoding/json"
	"os"
	"sync"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/stretchr/testify/require"
)

const testdataDir = "testdata"

// nolint: gochecknoglobals
var (
	//go:embed testdata/*.json
	fs embed.FS

	contexts []ldcontext.Document
	once     sync.Once
	errOnce  error
)

// GetAll returns all predefined contexts.
func GetAll() ([]ldcontext.Document, error) {
	once.Do(func() {
		var entries []os.DirEntry

		entries, errOnce = fs.ReadDir(testdataDir)
		if errOnce != nil {
			return
		}

		for _, entry := range entries {
			var file os.FileInfo
			file, errOnce = entry.Info()
			if errOnce != nil {
				return
			}

			var content []byte
			// Do not use os.PathSeparator here, we are using go:embed to load files.
			// The path separator is a forward slash, even on Windows systems.
			content, errOnce = fs.ReadFile(testdataDir + "/" + file.Name())
			if errOnce != nil {
				return
			}

			var doc ldcontext.Document

			errOnce = json.Unmarshal(content, &doc)
			if errOnce != nil {
				return
			}

			contexts = append(contexts, doc)
		}
	})

	return append(contexts[:0:0], contexts...), errOnce
}

// MustGetAll returns all predefined contexts.
func MustGetAll() []ldcontext.Document {
	docs, err := GetAll()
	if err != nil {
		panic(err)
	}

	return docs
}

type mockLDStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *mockLDStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *mockLDStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

// DocumentLoader returns a document loader with preloaded test contexts.
func DocumentLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	ldStore := &mockLDStoreProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	loader, err := ld.NewDocumentLoader(ldStore, ld.WithExtraContexts(MustGetAll()...))
	require.NoError(t, err)

	return loader
}
