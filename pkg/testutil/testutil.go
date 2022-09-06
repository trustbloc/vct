/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"embed"
	"encoding/json"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/stretchr/testify/require"

	vctldcontext "github.com/trustbloc/vct/internal/pkg/ldcontext"
)

// GetLoader returns the JSON-LD socument loader for unit testing.
func GetLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	p := &mockProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	ctx := vctldcontext.MustGetAll()

	ctx = append(ctx, getAll()...)

	documentLoader, err := ld.NewDocumentLoader(p, ld.WithExtraContexts(ctx...))
	require.NoError(t, err)

	return documentLoader
}

type mockProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (m *mockProvider) JSONLDContextStore() ldstore.ContextStore {
	return m.ContextStore
}

func (m *mockProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return m.RemoteProviderStore
}

const contextsDir = "testdata"

// nolint: gochecknoglobals
var (
	//go:embed testdata/ld-*.json
	fs embed.FS
)

// getAll returns all predefined contexts.
func getAll() []ldcontext.Document {
	var entries []os.DirEntry

	var contexts []ldcontext.Document

	entries, errOnce := fs.ReadDir(contextsDir)
	if errOnce != nil {
		panic(errOnce)
	}

	for _, entry := range entries {
		var file os.FileInfo

		file, errOnce = entry.Info()
		if errOnce != nil {
			panic(errOnce)
		}

		var content []byte
		// Do not use os.PathSeparator here, we are using go:embed to load files.
		// The path separator is a forward slash, even on Windows systems.
		content, errOnce = fs.ReadFile(contextsDir + "/" + file.Name())
		if errOnce != nil {
			panic(errOnce)
		}

		var doc ldcontext.Document

		errOnce = json.Unmarshal(content, &doc)
		if errOnce != nil {
			panic(errOnce)
		}

		contexts = append(contexts, doc)
	}

	return append(contexts[:0:0], contexts...)
}
