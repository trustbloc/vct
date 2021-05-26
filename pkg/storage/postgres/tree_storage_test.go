/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/tree_storage_test.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/google/trillian/storage/cache"
	"github.com/google/trillian/storage/storagepb"
	trilliantree "github.com/google/trillian/storage/tree"
	"github.com/stretchr/testify/require"
)

//go:generate mockgen -destination gomocks_test.go -self_package mocks -package postgres . SQLResult

type expandTestcase struct {
	input    *statementSkeleton
	expected string
}

func TestTreeTX_IsOpen(t *testing.T) {
	require.True(t, (&treeTX{}).IsOpen())
	require.False(t, (&treeTX{closed: true}).IsOpen())
}

func TestTreeTX_SetMerkleNodes(t *testing.T) {
	ndb, done := openTestDBOrDie()

	tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	done(context.Background())

	require.EqualError(t, (&treeTX{
		ts:           newTreeStorage(ndb),
		tx:           tx,
		subtreeCache: cache.NewLogSubtreeCache(defaultLogStrata, rfc6962.DefaultHasher),
	}).SetMerkleNodes(context.Background(), []trilliantree.Node{{}}), "sql: database is closed")
}

func TestTreeTX_Subtrees(t *testing.T) {
	res, err := (&treeTX{}).getSubtrees(context.Background(), 0, nil)
	require.Nil(t, res)
	require.NoError(t, err)

	ndb, done := openTestDBOrDie()

	tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	done(context.Background())

	res, err = (&treeTX{
		ts:           newTreeStorage(db),
		tx:           tx,
		subtreeCache: cache.NewLogSubtreeCache(defaultLogStrata, rfc6962.DefaultHasher),
	}).getSubtrees(context.Background(), 0, [][]byte{{0x1}})
	require.Nil(t, res)
	require.EqualError(t, err, "sql: Tx.Stmt: statement from different database used")

	require.NoError(t, (&treeTX{}).storeSubtrees(context.Background(), nil))
	require.EqualError(t, (&treeTX{
		ts: newTreeStorage(ndb),
		tx: tx,
	}).storeSubtrees(context.Background(),
		[]*storagepb.SubtreeProto{{Prefix: []byte{}}}),
		"sql: database is closed",
	)
}

func TestCheckResultOkAndRowCountIs(t *testing.T) {
	require.EqualError(t, checkResultOkAndRowCountIs(nil, errors.New("test"), 0), "test")

	t.Run("Error RowsAffected", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		res := NewMockSQLResult(ctrl)
		res.EXPECT().RowsAffected().Return(int64(0), errors.New("test"))

		require.EqualError(t, checkResultOkAndRowCountIs(res, nil, 0), "test")
	})

	t.Run("Error wring count", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		res := NewMockSQLResult(ctrl)
		res.EXPECT().RowsAffected().Return(int64(1), nil)

		require.EqualError(t,
			checkResultOkAndRowCountIs(res, nil, 0),
			"expected 0 row(s) to be affected but saw: 1",
		)
	})
}

// This test exists to prevent the deadcode linter from failing.
// TODO(vishal): remove this once the rest of the storage code is complete.
func TestInitializes(t *testing.T) {
	_ = &statementSkeleton{}
	arbitraryStorage := newTreeStorage(nil)
	_ = arbitraryStorage.getSubtreeStmt
	_ = arbitraryStorage.beginTreeTx
	treeTx := &treeTX{}
	_ = treeTx.getSubtree
	_ = treeTx.getSubtrees
}

func TestExpandPlaceholderSQL(t *testing.T) {
	testCases := []*expandTestcase{
		{
			input: &statementSkeleton{
				sql:               selectSubtreeSQL,
				firstInsertion:    "%s",
				firstPlaceholders: 1,
				restInsertion:     "%s",
				restPlaceholders:  1,
				num:               2,
			},
			expected: strings.Replace(selectSubtreeSQL, placeholderSQL, "$1,$2", 1),
		},
		{
			input: &statementSkeleton{
				sql:               insertSubtreeMultiSQL,
				firstInsertion:    "VALUES(%s, %s, %s, %s)",
				firstPlaceholders: 4,
				restInsertion:     "(%s, %s, %s, %s)",
				restPlaceholders:  4,
				num:               2,
			},
			expected: strings.Replace(
				insertSubtreeMultiSQL,
				placeholderSQL,
				"VALUES($1, $2, $3, $4),($5, $6, $7, $8)",
				1),
		},
		{
			input: &statementSkeleton{
				sql:               selectSubtreeSQL,
				firstInsertion:    "%s",
				firstPlaceholders: 1,
				restInsertion:     "%s",
				restPlaceholders:  1,
				num:               5,
			},
			expected: strings.Replace(selectSubtreeSQL, placeholderSQL, "$1,$2,$3,$4,$5", 1),
		},
		{
			input: &statementSkeleton{
				sql:               insertSubtreeMultiSQL,
				firstInsertion:    "VALUES(%s, %s, %s, %s)",
				firstPlaceholders: 4,
				restInsertion:     "(%s, %s, %s, %s)",
				restPlaceholders:  4,
				num:               5,
			},
			expected: strings.Replace(
				insertSubtreeMultiSQL,
				placeholderSQL,
				"VALUES($1, $2, $3, $4),($5, $6, $7, $8),($9, $10, $11, $12),($13, $14, $15, $16),($17, $18, $19, $20)",
				1),
		},
	}

	for _, tc := range testCases {
		res, err := expandPlaceholderSQL(tc.input)
		if err != nil {
			t.Fatalf("Error while expanding placeholder sql: %v", err)
		}

		if tc.expected != res {
			t.Fatalf("Expected %v but got %v", tc.expected, res)
		}
	}
}
