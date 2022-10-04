/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/
postgres/admin_storage_test.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/trillian"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/testonly"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// nolint: gochecknoglobals
var (
	allTables = []string{
		"unsequenced", "tree_head", "sequenced_leaf_data", "leaf_data", "subtree", "tree_control", "trees",
	}
	db *sql.DB
)

const selectTreeControlByID = "SELECT signing_enabled, sequencing_enabled, sequence_interval_seconds FROM tree_control WHERE tree_id = $1" // nolint: lll

func TestPgAdminStorage(t *testing.T) {
	tester := &testonly.AdminStorageTester{NewAdminStorage: func() storage.AdminStorage {
		cleanTestDB(t, db)

		return NewAdminStorage(db)
	}}
	tester.RunAllTests(t)
}

func TestPgAdminStorage_ReadWriteTransaction(t *testing.T) {
	t.Run("database is closed", func(t *testing.T) {
		ndb, done := openTestDBOrDie()

		s := NewAdminStorage(ndb)

		done(context.Background())

		err := s.ReadWriteTransaction(context.Background(), func(ctx context.Context, tx storage.AdminTX) error {
			return tx.Commit()
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "sql: database is closed")
	})
}

func TestAdminTX_GetTree_BadConnection(t *testing.T) {
	ndb, done := openTestDBOrDie()

	tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	done(context.Background())

	ctx := context.Background()

	tree, err := (&adminTX{tx: tx}).GetTree(ctx, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "driver: bad connection")
	require.Nil(t, tree)
}

func TestAdminTX_ListTrees_BadConnection(t *testing.T) {
	ndb, done := openTestDBOrDie()

	tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	done(context.Background())

	ctx := context.Background()

	tree, err := (&adminTX{tx: tx}).ListTrees(ctx, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "driver: bad connection")
	require.Nil(t, tree)
}

func TestAdminTX_CreateTree_BadConnection(t *testing.T) {
	ndb, done := openTestDBOrDie()

	tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	done(context.Background())

	tree, err := (&adminTX{tx: tx}).CreateTree(context.Background(), testonly.LogTree)
	require.Error(t, err)
	require.Contains(t, err.Error(), "driver: bad connection")
	require.Nil(t, tree)
}

func TestAdminTX_CreateTree_NoDuration(t *testing.T) {
	cleanTestDB(t, db)

	ctx := context.Background()

	tree, err := (&adminTX{}).CreateTree(ctx, &trillian.Tree{
		TreeState:   trillian.TreeState_ACTIVE,
		TreeType:    trillian.TreeType_LOG,
		DisplayName: "Llamas Log",
		Description: "Registry of publicly-owned llamas",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "max_root_duration malformed")
	require.Nil(t, tree)
}

func TestAdminTX_CreateTree_InitializesStorageStructures(t *testing.T) {
	cleanTestDB(t, db)
	s := NewAdminStorage(db)
	ctx := context.Background()

	tree, err := storage.CreateTree(ctx, s, testonly.LogTree)
	if err != nil {
		t.Fatalf("CreateTree() failed: %v", err)
	}

	// Check if TreeControl is correctly written.
	var (
		signingEnabled, sequencingEnabled bool
		sequenceIntervalSeconds           int
	)

	if err := db.QueryRowContext(ctx, selectTreeControlByID, tree.TreeId).
		Scan(&signingEnabled, &sequencingEnabled, &sequenceIntervalSeconds); err != nil {
		t.Fatalf("Failed to read TreeControl: %v", err)
	}
	// We don't mind about specific values, defaults change, but let's check
	// that important numbers are not zeroed.
	if sequenceIntervalSeconds <= 0 {
		t.Errorf("sequenceIntervalSeconds = %v, want > 0", sequenceIntervalSeconds)
	}
}

func TestCreateTreeInvalidStates(t *testing.T) {
	cleanTestDB(t, db)
	s := NewAdminStorage(db)
	ctx := context.Background()

	states := []trillian.TreeState{trillian.TreeState_DRAINING, trillian.TreeState_FROZEN}

	for _, state := range states {
		inTree := proto.Clone(testonly.LogTree).(*trillian.Tree) // nolint: errcheck,forcetypeassert
		inTree.TreeState = state

		if _, err := storage.CreateTree(ctx, s, inTree); err == nil {
			t.Errorf("CreateTree() state: %v got: nil want: err", state)
		}
	}
}

func TestAdminTX_TreeWithNulls(t *testing.T) {
	cleanTestDB(t, db)
	s := NewAdminStorage(db)
	ctx := context.Background()

	// Setup: create a tree and set all nullable columns to null.
	// Some columns have to be manually updated, as it's not possible to set
	// some proto fields to nil.
	tree, err := storage.CreateTree(ctx, s, testonly.LogTree)
	if err != nil {
		t.Fatalf("CreateTree() failed: %v", err)
	}

	treeID := tree.TreeId

	if err := setNulls(ctx, db, treeID); err != nil {
		t.Fatalf("setNulls() = %v, want = nil", err)
	}

	tests := []struct {
		desc string
		fn   storage.AdminTXFunc
	}{
		{
			desc: "GetTree",
			fn: func(ctx context.Context, tx storage.AdminTX) error {
				_, err := tx.GetTree(ctx, treeID)

				return err
			},
		},
		{
			desc: "ListTrees",
			fn: func(ctx context.Context, tx storage.AdminTX) error {
				trees, err := tx.ListTrees(ctx, false /* includeDeleted */)
				if err != nil {
					return err
				}
				for _, tree := range trees {
					if tree.TreeId == treeID {
						return nil
					}
				}

				return fmt.Errorf("ID not found: %v", treeID)
			},
		},
	}
	for _, test := range tests {
		if err := s.ReadWriteTransaction(ctx, test.fn); err != nil {
			t.Errorf("%v: err = %v, want = nil", test.desc, err)
		}
	}
}

func TestAdminTX_IsClosed(t *testing.T) {
	require.False(t, (&adminTX{}).IsClosed())
	require.True(t, (&adminTX{closed: true}).IsClosed())
}

func TestAdminTX_StorageSettingsNotSupported(t *testing.T) {
	cleanTestDB(t, db)
	s := NewAdminStorage(db)
	ctx := context.Background()

	settings, err := anypb.New(&empty.Empty{})
	if err != nil {
		t.Fatalf("Error marshaling proto: %v", err)
	}

	tests := []struct {
		desc string
		// fn attempts to either create or update a tree with a non-nil, valid Any proto
		// on Tree.StorageSettings. It's expected to return an error.
		fn func(storage.AdminStorage) error
	}{
		{
			desc: "CreateTree",
			fn: func(s storage.AdminStorage) error {
				tree := proto.Clone(testonly.LogTree).(*trillian.Tree) // nolint: errcheck,forcetypeassert
				tree.StorageSettings = settings
				_, err := storage.CreateTree(ctx, s, tree)

				return err
			},
		},
		{
			desc: "UpdateTree",
			fn: func(s storage.AdminStorage) error {
				tree, err := storage.CreateTree(ctx, s, testonly.LogTree)
				if err != nil {
					t.Fatalf("CreateTree() failed with err = %v", err)
				}
				_, err = storage.UpdateTree(ctx, s, tree.TreeId, func(tree *trillian.Tree) { tree.StorageSettings = settings })

				return err
			},
		},
	}
	for _, test := range tests {
		if err := test.fn(s); err == nil {
			t.Errorf("%v: err = nil, want non-nil", test.desc)
		}
	}
}

func cleanTestDB(t *testing.T, db *sql.DB) {
	t.Helper()

	for _, table := range allTables {
		if _, err := db.ExecContext(context.TODO(), fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			t.Fatalf("Failed to delete rows in %s: %v", table, err)
		}
	}
}

func setNulls(ctx context.Context, db *sql.DB, treeID int64) error {
	stmt, err := db.PrepareContext(ctx, `
	UPDATE trees SET
		display_name = NULL,
		description = NULL,
		delete_time_millis = NULL
	WHERE tree_id = $1`)
	if err != nil {
		return err
	}
	defer stmt.Close() // nolint: errcheck
	_, err = stmt.ExecContext(ctx, treeID)

	return err
}
