/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command_test

// nolint: lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package command_test . KeyManager,TrillianLogClient,Crypto,StorageProvider

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vct/internal/pkg/ldcontext"
	. "github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/errors"
)

// nolint: gochecknoglobals
var (
	//go:embed testdata/verifiableCredential.json
	verifiableCredential []byte
	//go:embed testdata/queuedLeafValue.json
	queuedLeafValue []byte

	logRoot = []byte{
		0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 32, 182, 56, 230, 122, 160, 166, 224, 172, 78, 222,
		31, 79, 49, 188, 89, 72, 187, 190, 92, 200, 114, 198, 112, 74, 184, 0, 136, 247,
		33, 217, 5, 110, 22, 113, 38, 217, 80, 195, 119, 97, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
	}
)

const alias = "maple2021"

func TestNew(t *testing.T) {
	const kid = "kid"

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km, Key: Key{
				ID:   kid,
				Type: kms.ECDSAP256TypeDER,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("Document loader error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return(nil, nil)

		db := NewMockStorageProvider(ctrl)
		db.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)
		db.EXPECT().OpenStore(gomock.Any()).Return(nil, errors.New("error"))

		cmd, err := New(&Config{
			KMS: km, Key: Key{
				ID:   kid,
				Type: kms.ECDSAP256TypeDER,
			},
			StorageProvider: db,
		})
		require.EqualError(t, err, "new document loader: new document loader: error")
		require.Nil(t, cmd)
	})

	t.Run("Create cmd error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return(nil, nil)

		db := NewMockStorageProvider(ctrl)
		db.EXPECT().OpenStore(gomock.Any()).Return(nil, errors.New("error"))

		cmd, err := New(&Config{
			KMS: km, Key: Key{
				ID:   kid,
				Type: kms.ECDSAP256TypeDER,
			},
			StorageProvider: db,
		})
		require.EqualError(t, err, "new cmd context: open store: error")
		require.Nil(t, cmd)
	})

	t.Run("Key is not supported", func(t *testing.T) {
		cmd, err := New(&Config{Key: Key{Type: "test"}})
		require.EqualError(t, err, "key type test is not supported")
		require.Nil(t, cmd)
	})

	t.Run("KMS no key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, errors.New("no key"))

		cmd, err := New(&Config{KMS: km, Key: Key{
			ID:   kid,
			Type: kms.ECDSAP256TypeDER,
		}})
		require.EqualError(t, err, "kms get kh: no key")
		require.Nil(t, cmd)
	})

	t.Run("KMS export pub key failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return(nil, errors.New("internal error"))

		cmd, err := New(&Config{KMS: km, Key: Key{
			ID:   kid,
			Type: kms.ECDSAP256TypeDER,
		}})
		require.EqualError(t, err, "export pub key bytes: internal error")
		require.Nil(t, cmd)
	})
}

func TestCmd_AddLdContext(t *testing.T) {
	const kid = "kid"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	km := NewMockKeyManager(ctrl)
	km.EXPECT().Get(kid).Return(nil, nil)
	km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

	cmd, err := New(&Config{
		KMS: km, Key: Key{
			ID:   kid,
			Type: kms.ECDSAP256TypeIEEEP1363,
		},
		StorageProvider: mem.NewProvider(),
	})
	require.NoError(t, err)
	require.NotNil(t, cmd)

	const (
		errorMsg = "context URL is mandatory"
		payload  = `{"documents":[{}]}`
	)

	require.EqualError(t, cmd.AddLdContext(nil, bytes.NewBufferString(payload)), errorMsg)
	require.EqualError(t, lookupHandler(t, cmd, AddLdContext)(nil, bytes.NewBufferString(payload)), errorMsg)
}

func TestCmd_GetIssuers(t *testing.T) {
	const kid = "kid"

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km, Key: Key{
				ID:   kid,
				Type: kms.ECDSAP256TypeIEEEP1363,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Issuers:    []string{"issuer_a", "issuer_b"},
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var fr bytes.Buffer

		require.NoError(t, cmd.GetIssuers(&fr,
			bytes.NewBufferString(fmt.Sprintf("%q", alias))))

		var hr bytes.Buffer

		require.NoError(t, lookupHandler(t, cmd, GetIssuers)(&hr,
			bytes.NewBufferString(fmt.Sprintf("%q", alias))))

		require.Equal(t, fr.String(), hr.String())
		require.Equal(t, `["issuer_a","issuer_b"]`+"\n", fr.String())
	})

	t.Run("Action forbidden", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km, Key: Key{
				ID:   kid,
				Type: kms.ECDSAP256TypeIEEEP1363,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Issuers:    []string{"issuer_a", "issuer_b"},
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		require.EqualError(t, cmd.GetIssuers(nil,
			bytes.NewBufferString(fmt.Sprintf("%q", alias))),
			"has permissions: action forbidden for \"maple2021\"",
		)
		require.EqualError(t, lookupHandler(t, cmd, GetIssuers)(nil,
			bytes.NewBufferString(fmt.Sprintf("%q", alias))),
			"has permissions: action forbidden for \"maple2021\"",
		)
	})

	t.Run("Decode alias failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km, Key: Key{
				ID:   kid,
				Type: kms.ECDSAP256TypeIEEEP1363,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Issuers:    []string{"issuer_a", "issuer_b"},
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		require.EqualError(t, cmd.GetIssuers(nil,
			bytes.NewBufferString("2021")),
			"internal error: decode alias failed",
		)
		require.EqualError(t, lookupHandler(t, cmd, GetIssuers)(nil,
			bytes.NewBufferString("2021")),
			"internal error: decode alias failed",
		)
	})
}

func TestCmd_GetPublicKey(t *testing.T) {
	const kid = "kid"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	km := NewMockKeyManager(ctrl)
	km.EXPECT().Get(kid).Return(nil, nil)
	km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

	cmd, err := New(&Config{
		KMS: km, Key: Key{
			ID:   kid,
			Type: kms.ECDSAP256TypeIEEEP1363,
		},
		StorageProvider: mem.NewProvider(),
	})
	require.NoError(t, err)
	require.NotNil(t, cmd)

	var fr bytes.Buffer

	require.NoError(t, cmd.GetPublicKey(&fr, nil))

	var hr bytes.Buffer

	require.NoError(t, lookupHandler(t, cmd, GetPublicKey)(&hr, nil))

	require.Equal(t, fr.String(), hr.String())
	require.Equal(t, "\"cHVibGljIGtleQ==\"\n", fr.String())
}

func TestCmd_GetEntries(t *testing.T) {
	const (
		kid     = "kid"
		keyType = kms.ECDSAP256TypeIEEEP1363
	)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLeavesByRangeResponse{
				Leaves:        []*trillian.LogLeaf{{LeafValue: queuedLeafValue}},
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, GetEntriesResponse{}

		require.NoError(t, cmd.GetEntries(&fr, bytes.NewBufferString(`{"alias":"maple2021"}`)))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, GetEntriesResponse{}

		require.NoError(t, lookupHandler(t, cmd, GetEntries)(&hr, bytes.NewBufferString(`{"alias":"maple2021"}`)))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.Entries, hrs.Entries)
		require.NotEmpty(t, frs.Entries)
		require.NotEmpty(t, hrs.Entries)
	})

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "decode GetEntries request: EOF"

		require.EqualError(t, cmd.GetEntries(nil, bytes.NewBuffer(nil)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil, bytes.NewBuffer(nil)), expErr)
	})

	t.Run("Validation error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "validate GetEntries request: validation failed: start 0 and end -1 values must be >= 0"

		require.EqualError(t, cmd.GetEntries(nil,
			bytes.NewBufferString(`{"end": -1}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil,
			bytes.NewBufferString(`{"end": -1}`),
		), expErr)
	})

	t.Run("Get leaves error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(nil, errors.New("error")).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "get leaves by range: error"

		require.EqualError(t, cmd.GetEntries(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
	})

	t.Run("Unmarshal binary error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLeavesByRangeResponse{
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: []byte{0}},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: unmarshal binary: [0]"

		require.EqualError(t, cmd.GetEntries(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
	})

	t.Run("Tree size error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLeavesByRangeResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: logRoot,
				},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: need tree size: 4 to get leaves but only got: 1"

		require.EqualError(t, cmd.GetEntries(nil,
			bytes.NewBufferString(`{"alias":"maple2021","start":3,"end":4}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil,
			bytes.NewBufferString(`{"alias":"maple2021","start":3,"end":4}`),
		), expErr)
	})

	t.Run("Bad leaf index", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLeavesByRangeResponse{
				Leaves:        []*trillian.LogLeaf{{LeafIndex: 10}},
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: unexpected leaf index: rsp.Leaves[0].LeafIndex=10 for range [0,0]"

		require.EqualError(t, cmd.GetEntries(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
	})

	t.Run("Action forbidden", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias: alias,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "has permissions: action forbidden for \"maple2021\""

		require.EqualError(t, cmd.GetEntries(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntries)(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
	})
}

func TestCmd_GetProofByHash(t *testing.T) {
	const (
		kid     = "kid"
		keyType = kms.ECDSAP256TypeIEEEP1363
	)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
			&trillian.GetInclusionProofByHashResponse{
				Proof:         []*trillian.Proof{{Hashes: [][]byte{{0, 1, 2}}}},
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, GetProofByHashResponse{}

		require.NoError(t, cmd.GetProofByHash(&fr,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`)))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, GetProofByHashResponse{}

		require.NoError(t, lookupHandler(t, cmd, GetProofByHash)(&hr,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`)))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.AuditPath, hrs.AuditPath)
		require.Equal(t, frs.LeafIndex, hrs.LeafIndex)
		require.NotEmpty(t, frs.AuditPath)
		require.NotEmpty(t, hrs.AuditPath)
	})

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "decode GetProofByHash request: EOF"

		require.EqualError(t, cmd.GetProofByHash(nil, bytes.NewBuffer(nil)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetProofByHash)(nil, bytes.NewBuffer(nil)), expErr)
	})

	t.Run("Validation error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "validate GetProofByHash request: validation failed: tree_size value must be greater than zero"

		require.EqualError(t, cmd.GetProofByHash(nil,
			bytes.NewBufferString(`{}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetProofByHash)(nil,
			bytes.NewBufferString(`{}`),
		), expErr)
	})

	t.Run("Unmarshal binary error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
			&trillian.GetInclusionProofByHashResponse{
				Proof:         []*trillian.Proof{{Hashes: [][]byte{{0}}}},
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: []byte{0}},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: unmarshal binary: [0]"

		require.EqualError(t, cmd.GetProofByHash(nil,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetProofByHash)(nil,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`),
		), expErr)
	})
}

func TestCmd_GetSTHConsistency(t *testing.T) {
	const (
		kid     = "kid"
		keyType = kms.ECDSAP256TypeIEEEP1363
	)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(
			&trillian.GetConsistencyProofResponse{
				Proof:         &trillian.Proof{Hashes: [][]byte{{0, 1, 2}}},
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, GetSTHConsistencyResponse{}

		require.NoError(t, cmd.GetSTHConsistency(&fr,
			bytes.NewBufferString(`{"alias":"maple2021","first_tree_size": 1, "second_tree_size": 1}`),
		))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, GetSTHConsistencyResponse{}

		require.NoError(t, lookupHandler(t, cmd, GetSTHConsistency)(&hr,
			bytes.NewBufferString(`{"alias":"maple2021","first_tree_size": 1, "second_tree_size": 1}`),
		))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.Consistency, hrs.Consistency)
		require.NotEmpty(t, frs.Consistency)
	})

	t.Run("Success (empty)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, GetSTHConsistencyResponse{}

		require.NoError(t, cmd.GetSTHConsistency(&fr,
			bytes.NewBufferString(`{"alias":"maple2021"}`),
		))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, GetSTHConsistencyResponse{}

		require.NoError(t, lookupHandler(t, cmd, GetSTHConsistency)(&hr,
			bytes.NewBufferString(`{"alias":"maple2021"}`),
		))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.Consistency, hrs.Consistency)
		require.Empty(t, frs.Consistency)
	})

	t.Run("Decode error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "decode GetSTHConsistency request: EOF"

		require.EqualError(t, cmd.GetSTHConsistency(nil, bytes.NewBuffer(nil)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTHConsistency)(nil, bytes.NewBuffer(nil)), expErr)
	})

	t.Run("Validation error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "validate GetSTHConsistency request: validation failed: first_tree_size -1 and second_tree_size 0 values must be >= 0" // nolint: lll

		require.EqualError(t, cmd.GetSTHConsistency(nil,
			bytes.NewBufferString(`{"first_tree_size": -1}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTHConsistency)(nil,
			bytes.NewBufferString(`{"first_tree_size": -1}`),
		), expErr)
	})

	t.Run("Unmarshal binary error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(
			&trillian.GetConsistencyProofResponse{
				Proof:         &trillian.Proof{Hashes: [][]byte{{0, 1, 2}}},
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: []byte{0}},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: unmarshal binary: [0]"

		require.EqualError(t, cmd.GetSTHConsistency(nil,
			bytes.NewBufferString(`{"alias":"maple2021","first_tree_size": 1, "second_tree_size": 1}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTHConsistency)(nil,
			bytes.NewBufferString(`{"alias":"maple2021","first_tree_size": 1, "second_tree_size": 1}`),
		), expErr)
	})

	t.Run("Alias maple2021 is not supported", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "has permissions: alias \"maple2021\" is not supported"

		require.EqualError(t, cmd.GetSTHConsistency(nil,
			bytes.NewBufferString(`{"alias":"maple2021","first_tree_size": 1, "second_tree_size": 1}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTHConsistency)(nil,
			bytes.NewBufferString(`{"alias":"maple2021","first_tree_size": 1, "second_tree_size": 1}`),
		), expErr)
	})
}

func TestCmd_GetSTH(t *testing.T) {
	const (
		kid           = "kid"
		logID   int64 = 123
		keyType       = kms.ECDSAP256TypeIEEEP1363
	)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km, cr := createKMSAndCrypto(t)
		newKID, _, err := km.Create(keyType)
		require.NoError(t, err)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS:    km,
			Crypto: cr,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   newKID,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, GetSTHResponse{}

		require.NoError(t, cmd.GetSTH(&fr, bytes.NewBufferString(fmt.Sprintf("%q", alias))))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, GetSTHResponse{}

		require.NoError(t, lookupHandler(t, cmd, GetSTH)(&hr, bytes.NewBufferString(fmt.Sprintf("%q", alias))))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.TreeSize, hrs.TreeSize)
		require.Equal(t, frs.SHA256RootHash, hrs.SHA256RootHash)
		require.Equal(t, frs.Timestamp, hrs.Timestamp)

		require.NotEmpty(t, frs.TreeHeadSignature)
		require.NotEmpty(t, hrs.TreeHeadSignature)
	})

	t.Run("Latest signed log root (error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLatestSignedLogRoot(
			gomock.Any(), gomock.Any(),
		).Return(nil, errors.New("error")).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "get latest signed log root: error"
		require.EqualError(t, cmd.GetSTH(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTH)(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
	})

	t.Run("No signed log root", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLatestSignedLogRoot(
			gomock.Any(), gomock.Any(),
		).Return(nil, nil).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: no signed log root returned"
		require.EqualError(t, cmd.GetSTH(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTH)(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
	})

	t.Run("Corrupted bytes (unmarshal binary)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: []byte{0}},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "unmarshal binary: logRootBytes too short"
		require.EqualError(t, cmd.GetSTH(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTH)(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
	})

	t.Run("Sign error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cr := NewMockCrypto(ctrl)
		cr.EXPECT().Sign(gomock.Any(), gomock.Any()).Return([]byte{}, errors.New("error")).Times(2)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(
			&trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS:    km,
			Crypto: cr,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "sign tree head (v1): sign TreeHeadSignature: error"
		require.EqualError(t, cmd.GetSTH(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetSTH)(nil, bytes.NewBufferString(fmt.Sprintf("%q", alias))), expErr)
	})
}

func TestCmd_GetEntryAndProof(t *testing.T) {
	const (
		logID   int64 = 123
		keyType       = kms.ECDSAP256TypeIEEEP1363
	)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km, cr := createKMSAndCrypto(t)
		newKID, _, err := km.Create(keyType)
		require.NoError(t, err)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Return(
			&trillian.GetEntryAndProofResponse{
				Proof: &trillian.Proof{},
				Leaf:  &trillian.LogLeaf{LeafValue: []byte{0}},
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: logRoot,
				},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS:    km,
			Crypto: cr,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   newKID,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, GetEntryAndProofResponse{}

		require.NoError(t, cmd.GetEntryAndProof(&fr,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`)))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, GetEntryAndProofResponse{}

		require.NoError(t, lookupHandler(t, cmd, GetEntryAndProof)(&hr,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`)))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.AuditPath, hrs.AuditPath)
		require.Equal(t, frs.ExtraData, hrs.ExtraData)
		require.Equal(t, frs.LeafInput, hrs.LeafInput)
	})

	t.Run("Bad tree size", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km, cr := createKMSAndCrypto(t)
		newKID, _, err := km.Create(keyType)
		require.NoError(t, err)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Return(
			&trillian.GetEntryAndProofResponse{
				Proof: &trillian.Proof{},
				Leaf:  &trillian.LogLeaf{LeafValue: []byte{0}},
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: logRoot,
				},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS:    km,
			Crypto: cr,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   newKID,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "bad request: need tree size: 2 for proof, got: 1"

		require.EqualError(t, cmd.GetEntryAndProof(nil,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 2}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntryAndProof)(nil,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 2}`),
		), expErr)
	})

	t.Run("Corrupted data received", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km, cr := createKMSAndCrypto(t)
		newKID, _, err := km.Create(keyType)
		require.NoError(t, err)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Return(
			&trillian.GetEntryAndProofResponse{
				SignedLogRoot: &trillian.SignedLogRoot{LogRoot: logRoot},
			}, nil,
		).Times(2)

		cmd, err := New(&Config{
			KMS:    km,
			Crypto: cr,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
				Client:     client,
			}},
			Key: Key{
				ID:   newKID,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "internal error: corrupted data received: signed_log_root:{log_root:\"\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01 \\xb68\\xe6z\\xa0\\xa6\\xe0\\xacN\\xde\\x1fO1\\xbcYH\\xbb\\xbe\\\\\\xc8r\\xc6pJ\\xb8\\x00\\x88\\xf7!\\xd9\\x05n\\x16q&\\xd9P\\xc3wa\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\"}" // nolint: lll

		require.EqualError(t, cmd.GetEntryAndProof(nil,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`),
		), expErr)
		require.EqualError(t, lookupHandler(t, cmd, GetEntryAndProof)(nil,
			bytes.NewBufferString(`{"alias":"maple2021","tree_size": 1}`),
		), expErr)
	})
}

func TestCreateLeaf(t *testing.T) {
	simpleVC := &verifiable.Credential{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Subject: "did:key:123",
		Issuer:  verifiable.Issuer{ID: "did:key:123"},
		Issued:  &util.TimeWithTrailingZeroMsec{},
		Types:   []string{"VerifiableCredential"},
		Proofs:  []verifiable.Proof{{}, {}},
	}

	_, err := CreateLeaf(1, simpleVC)
	require.NoError(t, err)

	require.Len(t, simpleVC.Proofs, 2)
}

func TestCmd_AddVC(t *testing.T) {
	const (
		kid     = "kid"
		keyType = kms.ECDSAP256TypeIEEEP1363
	)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km, cr := createKMSAndCrypto(t)
		newKID, _, err := km.Create(keyType)
		require.NoError(t, err)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(
			&trillian.QueueLeafResponse{
				QueuedLeaf: &trillian.QueuedLogLeaf{
					Leaf: &trillian.LogLeaf{LeafValue: queuedLeafValue},
				},
			}, nil,
		).Times(2)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS:    km,
			Crypto: cr,
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Client:     client,
			}},
			VDR: vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   newKID,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		fr, frs := bytes.Buffer{}, AddVCResponse{}

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		require.NoError(t, cmd.AddVC(&fr, bytes.NewBuffer(req)))
		require.NoError(t, json.Unmarshal(fr.Bytes(), &frs))

		hr, hrs := bytes.Buffer{}, AddVCResponse{}

		require.NoError(t, lookupHandler(t, cmd, AddVC)(&hr, bytes.NewBuffer(req)))
		require.NoError(t, json.Unmarshal(hr.Bytes(), &hrs))

		require.Equal(t, frs.Timestamp, hrs.Timestamp)
		require.Equal(t, frs.ID, hrs.ID)
		require.Equal(t, frs.Extensions, hrs.Extensions)
		require.Equal(t, frs.SVCTVersion, hrs.SVCTVersion)

		require.NotEmpty(t, frs.Signature)
		require.NotEmpty(t, hrs.Signature)

		var sig *DigitallySigned
		require.NoError(t, json.Unmarshal(hrs.Signature, &sig))

		require.NotEmpty(t, sig.Signature)
		require.NotEmpty(t, sig.Algorithm.Hash)
		require.NotEmpty(t, sig.Algorithm.Type)
		require.NotEmpty(t, sig.Algorithm.Signature)
	})

	t.Run("Copy vc failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "decode AddVC request: internal error"
		require.EqualError(t, cmd.AddVC(nil, &readerMock{errors.New("EOF")}), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, &readerMock{errors.New("EOF")}), expErr)
	})

	t.Run("Parse credential", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cmd, err := New(&Config{
			KMS: km,
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
			}},
			StorageProvider: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		const expErr = "parse credential: decode new credential: embedded proof is not JSON: unexpected end of JSON input"
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBufferString(`{"alias":"maple2021"}`)), expErr)
	})

	t.Run("Issuer is not trusted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Issuers:    []string{"issuer_a"},
			}},
			VDR: vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		const expErr = "bad request: issuer did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2 is not in a list" // nolint: lll
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBuffer(req)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBuffer(req)), expErr)
	})

	t.Run("Queue leaf error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(nil, errors.New("error")).Times(2)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Client:     client,
			}},
			VDR: vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		const expErr = "queue leaf: error"
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBuffer(req)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBuffer(req)), expErr)
	})

	t.Run("No leaf", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(&trillian.QueueLeafResponse{}, nil).Times(2)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Client:     client,
			}},
			VDR: vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		const expErr = "internal error: no leaf"
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBuffer(req)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBuffer(req)), expErr)
	})

	t.Run("Corrupted leaf", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(&trillian.QueueLeafResponse{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf: &trillian.LogLeaf{
					LeafValue: []byte(`[]`),
				},
			},
		}, nil).Times(2)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Client:     client,
			}},
			VDR: vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		const expErr = "failed to reconstruct MerkleTreeLeaf: json: cannot unmarshal array into Go value of type command.MerkleTreeLeaf" // nolint: lll
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBuffer(req)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBuffer(req)), expErr)
	})

	t.Run("Sign error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		cr := NewMockCrypto(ctrl)
		cr.EXPECT().Sign(gomock.Any(), gomock.Any()).Return([]byte{}, errors.New("error")).Times(2)

		client := NewMockTrillianLogClient(ctrl)
		client.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(&trillian.QueueLeafResponse{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf: &trillian.LogLeaf{
					LeafValue: queuedLeafValue,
				},
			},
		}, nil).Times(2)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "w",
				Client:     client,
			}},
			Crypto: cr,
			VDR:    vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		const expErr = "sign V1 VCTS: sign TreeHeadSignature: error"
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBuffer(req)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBuffer(req)), expErr)
	})

	t.Run("Action forbidden", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		km := NewMockKeyManager(ctrl)
		km.EXPECT().Get(kid).Return(nil, nil)
		km.EXPECT().ExportPubKeyBytes(kid).Return([]byte(`public key`), nil)

		db := mem.NewProvider()
		loadContexts(t, db)

		cmd, err := New(&Config{
			KMS: km,
			Logs: []Log{{
				Alias:      alias,
				Permission: "r",
			}},
			Crypto: NewMockCrypto(ctrl),
			VDR:    vdr.New(vdr.WithVDR(key.New())),
			Key: Key{
				ID:   kid,
				Type: keyType,
			},
			StorageProvider: db,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(AddVCRequest{
			Alias:   alias,
			VCEntry: verifiableCredential,
		})
		require.NoError(t, err)

		const expErr = "has permissions: action forbidden for \"maple2021\""
		require.EqualError(t, cmd.AddVC(nil, bytes.NewBuffer(req)), expErr)
		require.EqualError(t, lookupHandler(t, cmd, AddVC)(nil, bytes.NewBuffer(req)), expErr)
	})
}

func lookupHandler(t *testing.T, cmd *Cmd, name string) Exec {
	t.Helper()

	for _, handler := range cmd.GetHandlers() {
		if handler.Method() == name {
			return handler.Handle()
		}
	}

	t.Errorf("no handler for %s", name)

	return func(rw io.Writer, req io.Reader) error {
		return nil
	}
}

func loadContexts(t *testing.T, p storage.Provider) {
	t.Helper()

	store, err := p.OpenStore(jsonld.ContextsDBName)
	require.NoError(t, err)

	var ops []storage.Operation

	for _, doc := range ldcontext.MustGetAll() {
		var content interface{}
		content, err = ld.DocumentFromReader(bytes.NewReader(doc.Content))
		require.NoError(t, err)

		var b []byte
		b, err = json.Marshal(ld.RemoteDocument{
			DocumentURL: doc.URL,
			Document:    content,
		})
		require.NoError(t, err)

		ops = append(ops, storage.Operation{Key: doc.URL, Value: b})
	}

	require.NoError(t, store.Batch(ops))
}

func createKMSAndCrypto(t *testing.T) (kms.KeyManager, crypto.Crypto) {
	t.Helper()

	const defaultMasterKeyURI = "local-lock://default/master/key/"

	local, err := localkms.New(defaultMasterKeyURI, &kmsProvider{
		storageProvider: mem.NewProvider(),
		secretLock:      &noop.NoLock{},
	})
	require.NoError(t, err)

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	return local, cr
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

type readerMock struct{ err error }

func (r *readerMock) Read(p []byte) (n int, err error) {
	return 0, r.err
}
