/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/log_storage_test.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/testonly"
	"github.com/google/trillian/types"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Must be 32 bytes to match sha256 length if it was a real hash
// nolint: gochecknoglobals
var (
	dummyHash    = []byte("hashxxxxhashxxxxhashxxxxhashxxxx")
	dummyRawHash = []byte("xxxxhashxxxxhashxxxxhashxxxxhash")
)

// nolint: gochecknoglobals
var (
	// Time we will queue all leaves at.
	fakeQueueTime = time.Date(2016, 11, 10, 15, 16, 27, 0, time.UTC)

	// Time we will integrate all leaves at.
	fakeIntegrateTime = time.Date(2016, 11, 10, 15, 16, 30, 0, time.UTC)

	// Time we'll request for guard cutoff in tests that don't test this (should include all above).
	fakeDequeueCutoffTime = time.Date(2016, 11, 10, 15, 16, 30, 0, time.UTC)

	// Used for tests involving extra data.
	someExtraData = []byte("Some extra data")
)

const (
	leavesToInsert       = 5
	sequenceNumber int64 = 237
)

// Tests that access the db should each use a distinct log ID to prevent lock contention when
// run in parallel or race conditions / unexpected interactions. Tests that pass should hold
// no locks afterwards.

func createFakeLeaf(ctx context.Context, t *testing.T, db *sql.DB, logID int64, rawHash,
	hash, data, extraData []byte, seq int64) *trillian.LogLeaf { // nolint: unparam
	t.Helper()

	queuedAtNanos := fakeQueueTime.UnixNano()
	integratedAtNanos := fakeIntegrateTime.UnixNano()
	_, err := db.ExecContext(ctx, "select * from insert_leaf_data_ignore_duplicates($1,$2,$3,$4,$5)",
		logID, rawHash, data, extraData, queuedAtNanos)
	_, err2 := db.ExecContext(ctx, "select * from insert_sequenced_leaf_data_ignore_duplicates($1,$2,$3,$4,$5)",
		logID, seq, rawHash, hash, integratedAtNanos)

	if err != nil || err2 != nil {
		t.Fatalf("Failed to create test leaves: %v %v", err, err2)
	}

	integrateTimestamp := timestamppb.New(fakeIntegrateTime)

	return &trillian.LogLeaf{
		MerkleLeafHash:     hash,
		LeafValue:          data,
		ExtraData:          extraData,
		LeafIndex:          seq,
		LeafIdentityHash:   rawHash,
		IntegrateTimestamp: integrateTimestamp,
	}
}

func checkLeafContents(t *testing.T, leaf *trillian.LogLeaf, seq int64, rawHash, hash, data, extraData []byte) {
	t.Helper()

	if got, want := leaf.MerkleLeafHash, hash; !bytes.Equal(got, want) {
		t.Fatalf("Wrong leaf hash in returned leaf got\n%v\nwant:\n%v", got, want)
	}

	if got, want := leaf.LeafIdentityHash, rawHash; !bytes.Equal(got, want) {
		t.Fatalf("Wrong raw leaf hash in returned leaf got\n%v\nwant:\n%v", got, want)
	}

	if got, want := seq, leaf.LeafIndex; got != want {
		t.Fatalf("Bad sequence number in returned leaf got: %d, want:%d", got, want)
	}

	if got, want := leaf.LeafValue, data; !bytes.Equal(got, want) {
		t.Fatalf("Unxpected data in returned leaf. got:\n%v\nwant:\n%v", got, want)
	}

	if got, want := leaf.ExtraData, extraData; !bytes.Equal(got, want) {
		t.Fatalf("Unxpected data in returned leaf. got:\n%v\nwant:\n%v", got, want)
	}

	iTime := leaf.IntegrateTimestamp.AsTime()

	if got, want := iTime.UnixNano(), fakeIntegrateTime.UnixNano(); got != want {
		t.Errorf("Wrong IntegrateTimestamp: got %v, want %v", got, want)
	}
}

func TestLogStorage_CheckDatabaseAccessible(t *testing.T) {
	cleanTestDB(t, db)
	s := NewLogStorage(db, nil)

	if err := s.CheckDatabaseAccessible(context.Background()); err != nil {
		t.Errorf("CheckDatabaseAccessible() = %v, want = nil", err)
	}
}

func TestNewAdminStorage_CheckDatabaseAccessible(t *testing.T) {
	cleanTestDB(t, db)
	s := NewAdminStorage(db)

	if err := s.CheckDatabaseAccessible(context.Background()); err != nil {
		t.Errorf("CheckDatabaseAccessible() = %v, want = nil", err)
	}
}

func TestSnapshot(t *testing.T) {
	cleanTestDB(t, db)

	frozenLog := createTreeOrPanic(db, testonly.LogTree)
	createFakeSignedLogRoot(db, frozenLog, 0)

	if _, err := updateTree(db, frozenLog.TreeId, func(tree *trillian.Tree) {
		tree.TreeState = trillian.TreeState_FROZEN
	}); err != nil {
		t.Fatalf("Error updating frozen tree: %v", err)
	}

	activeLog := createTreeOrPanic(db, testonly.LogTree)
	createFakeSignedLogRoot(db, activeLog, 0)

	tests := []struct {
		desc    string
		tree    *trillian.Tree
		wantErr bool
	}{
		{
			desc:    "unknownSnapshot",
			tree:    logTree(-1),
			wantErr: true,
		},
		{
			desc: "activeLogSnapshot",
			tree: activeLog,
		},
		{
			desc: "frozenSnapshot",
			tree: frozenLog,
		},
	}

	ctx := context.Background()
	s := NewLogStorage(db, nil)

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			tx, err := s.SnapshotForTree(ctx, test.tree)

			if errors.Is(err, storage.ErrTreeNeedsInit) {
				defer tx.Close() // nolint: errcheck
			}

			if hasErr := err != nil; hasErr != test.wantErr {
				t.Fatalf("err = %q, wantErr = %v", err, test.wantErr)
			} else if hasErr {
				return
			}
			defer tx.Close() // nolint: errcheck

			_, err = tx.LatestSignedLogRoot(ctx)
			if err != nil {
				t.Errorf("LatestSignedLogRoot() returned err = %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Errorf("Commit() returned err = %v", err)
			}
		})
	}
}

func TestReadWriteTransaction(t *testing.T) {
	cleanTestDB(t, db)
	activeLog := createTreeOrPanic(db, testonly.LogTree)
	createFakeSignedLogRoot(db, activeLog, 0)

	tests := []struct {
		desc        string
		tree        *trillian.Tree
		wantErr     bool
		wantLogRoot []byte
		wantTXRev   int64
	}{
		{
			// Unknown logs IDs are now handled outside storage.
			desc:        "unknownBegin",
			tree:        logTree(-1),
			wantLogRoot: nil,
			wantTXRev:   -1,
		},
		{
			desc: "activeLogBegin",
			tree: activeLog,
			wantLogRoot: func() []byte {
				b, err := (&types.LogRootV1{RootHash: []byte{0}}).MarshalBinary()
				if err != nil {
					panic(err)
				}

				return b
			}(),
			wantTXRev: 1,
		},
	}

	ctx := context.Background()
	s := NewLogStorage(db, nil)

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := s.ReadWriteTransaction(ctx, test.tree, func(ctx context.Context, tx storage.LogTreeTX) error {
				root, err := tx.LatestSignedLogRoot(ctx)
				if err != nil {
					t.Fatalf("%v: LatestSignedLogRoot() returned err = %v", test.desc, err)
				}
				gotRev, _ := tx.WriteRevision(ctx) // nolint: errcheck
				if gotRev != test.wantTXRev {
					t.Errorf("%v: WriteRevision() = %v, want = %v", test.desc, gotRev, test.wantTXRev)
				}
				if got, want := root.GetLogRoot(), test.wantLogRoot; !bytes.Equal(got, want) {
					t.Errorf("%v: LogRoot: \n%x, want \n%x", test.desc, got, want)
				}

				return nil
			})
			if hasErr := err != nil; hasErr != test.wantErr {
				t.Fatalf("%v: err = %q, wantErr = %v", test.desc, err, test.wantErr)
			} else if hasErr {
				return
			}
		})
	}
}

func TestQueueDuplicateLeaf(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	count := 15
	leaves := createTestLeaves(int64(count), 10)
	leaves2 := createTestLeaves(int64(count), 12)
	leaves3 := createTestLeaves(3, 100)

	// Note that tests accumulate queued leaves on top of each other.
	tests := []struct {
		desc   string
		leaves []*trillian.LogLeaf
		want   []*trillian.LogLeaf
	}{
		{
			desc:   "[10, 11, 12, ...]",
			leaves: leaves,
			want:   make([]*trillian.LogLeaf, count),
		},
		{
			desc:   "[12, 13, 14, ...] so first (count-2) are duplicates",
			leaves: leaves2,
			want:   append(leaves[2:], nil, nil),
		},
		{
			desc:   "[10, 100, 11, 101, 102] so [dup, new, dup, new, dup]",
			leaves: []*trillian.LogLeaf{leaves[0], leaves3[0], leaves[1], leaves3[1], leaves[2]},
			want:   []*trillian.LogLeaf{leaves[0], nil, leaves[1], nil, leaves[2]},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			existing, err := s.QueueLeaves(ctx, tree, test.leaves, fakeQueueTime)
			if err != nil {
				t.Fatalf("Failed to queue leaves: %v", err)
			}

			if len(existing) != len(test.want) {
				t.Fatalf("|QueueLeaves()|=%d; want %d", len(existing), len(test.want))
			}
			for i, want := range test.want {
				got := existing[i]
				if want == nil {
					if got.Status != nil {
						t.Fatalf("QueueLeaves()[%d].Status=%v; want nil", i, got)
					}

					return
				}
				if got == nil {
					t.Fatalf("QueueLeaves()[%d]=nil; want non-nil", i)
				} else if !bytes.Equal(got.Leaf.LeafIdentityHash, want.LeafIdentityHash) {
					t.Fatalf("QueueLeaves()[%d].LeafIdentityHash=%x; want %x", i, got.Leaf.LeafIdentityHash, want.LeafIdentityHash)
				}
			}
		})
	}
}

func TestQueueLeaves(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)
	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	leaves := createTestLeaves(leavesToInsert, 20)
	if _, err := s.QueueLeaves(ctx, tree, leaves, fakeQueueTime); err != nil {
		t.Fatalf("Failed to queue leaves: %v", err)
	}

	_, err := s.QueueLeaves(ctx, tree, []*trillian.LogLeaf{{LeafIdentityHash: []byte(`123`)}}, fakeQueueTime)
	require.EqualError(t, err, "queued leaf must have a leaf ID hash of length 32")

	selectCount := "SELECT COUNT(*) FROM unsequenced WHERE Tree_id=$1"

	// Should see the leaves in the database. There is no API to read from the unsequenced data.
	var count int
	if err := db.QueryRowContext(ctx, selectCount, tree.TreeId).Scan(&count); err != nil {
		t.Fatalf("Could not query row count: %v", err)
	}

	if leavesToInsert != count {
		t.Fatalf("Expected %d unsequenced rows but got: %d", leavesToInsert, count)
	}

	selectDistinct := "SELECT DISTINCT queue_timestamp_nanos FROM unsequenced WHERE tree_id=$1"

	// Additional check on timestamp being set correctly in the database
	var queueTimestamp int64
	if err := db.QueryRowContext(ctx, selectDistinct, tree.TreeId).Scan(&queueTimestamp); err != nil {
		t.Fatalf("Could not query timestamp: %v", err)
	}

	if got, want := queueTimestamp, fakeQueueTime.UnixNano(); got != want {
		t.Fatalf("Incorrect queue timestamp got: %d want: %d", got, want)
	}
}

// AddSequencedLeaves tests. ---------------------------------------------------

type addSequencedLeavesTest struct {
	t    *testing.T
	s    storage.LogStorage
	tree *trillian.Tree
}

func initAddSequencedLeavesTest(t *testing.T) addSequencedLeavesTest {
	t.Helper()

	cleanTestDB(t, db)
	s := NewLogStorage(db, nil)
	tree := createTreeOrPanic(db, testonly.PreorderedLogTree)

	return addSequencedLeavesTest{t, s, tree}
}

func (t *addSequencedLeavesTest) addSequencedLeaves(leaves []*trillian.LogLeaf) {
	// TODO(pavelkalinnikov): Verify returned status for each leaf.
	ctx := context.Background()
	if _, err := t.s.AddSequencedLeaves(ctx, t.tree, leaves, fakeQueueTime); err != nil {
		t.t.Fatalf("Failed to add sequenced leaves: %v", err)
	}
}

func (t *addSequencedLeavesTest) verifySequencedLeaves(start, count int64, exp []*trillian.LogLeaf) {
	var stored []*trillian.LogLeaf

	runLogTX(t.t, t.s, t.tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		var err error
		stored, err = tx.GetLeavesByRange(ctx, start, count)
		if err != nil {
			t.t.Fatalf("Failed to read sequenced leaves: %v", err)
		}

		return nil
	})

	if got, want := len(stored), len(exp); got != want {
		t.t.Fatalf("Unexpected number of leaves: got %d, want %d %d %d %v", got, want, start, count, exp)
	}

	for i, leaf := range stored {
		if got, want := leaf.LeafIndex, exp[i].LeafIndex; got != want {
			t.t.Fatalf("Leaf #%d: LeafIndex=%v, want %v", i, got, want)
		}

		if got, want := leaf.LeafIdentityHash, exp[i].LeafIdentityHash; !bytes.Equal(got, want) {
			t.t.Fatalf("Leaf #%d: LeafIdentityHash=%v, want %v %d %d %v", i, got, want, start, count, t.tree)
		}
	}
}

func TestAddSequencedLeavesUnordered(t *testing.T) {
	ctx := context.Background()

	const (
		chunk      = leavesToInsert
		count      = chunk * 5
		extraCount = 16
	)

	leaves := createTestLeaves(count, 0)

	aslt := initAddSequencedLeavesTest(t)
	mustSignAndStoreLogRoot(ctx, aslt.t, aslt.s, aslt.tree, 0)

	for _, idx := range []int{1, 0, 4, 2} {
		aslt.addSequencedLeaves(leaves[chunk*idx : chunk*(idx+1)])
	}

	aslt.verifySequencedLeaves(0, count+extraCount, leaves[:chunk*3])
	aslt.verifySequencedLeaves(chunk*4, chunk+extraCount, leaves[chunk*4:count])
	aslt.addSequencedLeaves(leaves[chunk*3 : chunk*4])
	aslt.verifySequencedLeaves(0, count+extraCount, leaves)
}

func TestAddSequencedLeavesWithDuplicates(t *testing.T) {
	ctx := context.Background()
	leaves := createTestLeaves(6, 0)

	aslt := initAddSequencedLeavesTest(t)
	mustSignAndStoreLogRoot(ctx, aslt.t, aslt.s, aslt.tree, 0)
	aslt.addSequencedLeaves(leaves[:3])
	aslt.verifySequencedLeaves(0, 3, leaves[:3])
	aslt.addSequencedLeaves(leaves[2:]) // Full dup.
	aslt.verifySequencedLeaves(0, 6, leaves)

	dupLeaves := createTestLeaves(4, 6)
	dupLeaves[0].LeafIdentityHash = leaves[0].LeafIdentityHash // Hash dup.
	dupLeaves[2].LeafIndex = 2                                 // Index dup.
	aslt.addSequencedLeaves(dupLeaves)
	aslt.verifySequencedLeaves(6, 4, dupLeaves[0:2])
	aslt.verifySequencedLeaves(7, 4, dupLeaves[1:2])
	aslt.verifySequencedLeaves(8, 4, nil)
	aslt.verifySequencedLeaves(9, 4, dupLeaves[3:4])
	dupLeaves = createTestLeaves(4, 6)
	aslt.addSequencedLeaves(dupLeaves)
}

// -----------------------------------------------------------------------------

func TestDequeueLeavesNoneQueued(t *testing.T) {
	cleanTestDB(t, db)
	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		leaves, err := tx.DequeueLeaves(ctx, 999, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Didn't expect an error on dequeue with no work to be done: %v", err)
		}
		if len(leaves) > 0 {
			t.Fatalf("Expected nothing to be dequeued but we got %d leaves", len(leaves))
		}

		return nil
	})
}

func TestDequeueLeaves(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	leaves := createTestLeaves(leavesToInsert, 20)
	if _, err := s.QueueLeaves(ctx, tree, leaves, fakeDequeueCutoffTime); err != nil {
		t.Fatalf("Failed to queue leaves: %v", err)
	}

	// Now try to dequeue them
	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		leaves2, err := tx2.DequeueLeaves(ctx, 99, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Failed to dequeue leaves: %v", err)
		}
		if len(leaves2) != leavesToInsert {
			t.Fatalf("Dequeued %d leaves but expected to get %d", len(leaves2), leavesToInsert)
		}
		ensureAllLeavesDistinct(t, leaves2)

		return nil
	})

	// If we dequeue again then we should now get nothing
	runLogTX(t, s, tree, func(ctx context.Context, tx3 storage.LogTreeTX) error {
		leaves3, err := tx3.DequeueLeaves(ctx, 99, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Failed to dequeue leaves (second time): %v", err)
		}
		if len(leaves3) != 0 {
			t.Fatalf("Dequeued %d leaves but expected to get none", len(leaves3))
		}

		return nil
	})
}

func TestLogTreeTX_DequeueLeaves(t *testing.T) {
	tx, err := db.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	_, err = (&logTreeTX{
		root: types.LogRootV1{},
		treeTX: treeTX{
			tx:       tx,
			treeType: trillian.TreeType_PREORDERED_LOG,
		},
	}).DequeueLeaves(context.Background(), 1, time.Now())
	require.NoError(t, err)
}

func TestLogTreeTX_GetLeavesByHash(t *testing.T) {
	t.Run("no placeholder", func(t *testing.T) {
		ndb, done := openTestDBOrDie()

		tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
		require.NoError(t, err)

		done(context.Background())

		_, err = (&logTreeTX{
			ls: NewLogStorage(ndb, nil).(*postgresLogStorage),
			treeTX: treeTX{
				tx:       tx,
				treeType: trillian.TreeType_PREORDERED_LOG,
			},
		}).GetLeavesByHash(context.Background(), [][]byte{}, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "trying to expand SQL placeholder with <= 0 parameters")
	})

	t.Run("DB is closed", func(t *testing.T) {
		ndb, done := openTestDBOrDie()

		tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
		require.NoError(t, err)

		done(context.Background())

		_, err = (&logTreeTX{
			ls: NewLogStorage(ndb, nil).(*postgresLogStorage),
			treeTX: treeTX{
				tx:       tx,
				treeType: trillian.TreeType_PREORDERED_LOG,
			},
		}).GetLeavesByHash(context.Background(), [][]byte{{}}, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sql: database is closed")
	})
}

func TestLogTreeTX_DequeueLeaves_BadConnection(t *testing.T) {
	ndb, done := openTestDBOrDie()

	tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
	require.NoError(t, err)

	done(context.Background())

	_, err = (&logTreeTX{
		ls: NewLogStorage(ndb, nil).(*postgresLogStorage),
		treeTX: treeTX{
			tx: tx,
		},
	}).DequeueLeaves(context.Background(), 1, time.Now())
	require.Error(t, err)
	require.Contains(t, err.Error(), "driver: bad connection")
}

func TestLogTreeTX_AddSequencedLeaves(t *testing.T) {
	t.Run("bad connection (driver)", func(t *testing.T) {
		ndb, done := openTestDBOrDie()

		tx, err := ndb.BeginTx(context.Background(), nil /* opts */)
		require.NoError(t, err)

		done(context.Background())

		_, err = (&logTreeTX{
			ls: NewLogStorage(ndb, nil).(*postgresLogStorage),
			treeTX: treeTX{
				tx:       tx,
				treeType: trillian.TreeType_PREORDERED_LOG,
			},
		}).AddSequencedLeaves(context.Background(), []*trillian.LogLeaf{{}}, time.Now())
		require.Error(t, err)
		require.Contains(t, err.Error(), "driver: bad connection")
	})
}

func TestDequeueLeavesHaveQueueTimestamp(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	leaves := createTestLeaves(leavesToInsert, 20)
	if _, err := s.QueueLeaves(ctx, tree, leaves, fakeDequeueCutoffTime); err != nil {
		t.Fatalf("Failed to queue leaves: %v", err)
	}

	// Now try to dequeue them
	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		leaves2, err := tx2.DequeueLeaves(ctx, 99, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Failed to dequeue leaves: %v", err)
		}
		if len(leaves2) != leavesToInsert {
			t.Fatalf("Dequeued %d leaves but expected to get %d", len(leaves2), leavesToInsert)
		}
		ensureLeavesHaveQueueTimestamp(t, leaves2, fakeDequeueCutoffTime)

		return nil
	})
}

func TestDequeueLeavesTwoBatches(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	leavesToDequeue1 := 3
	leavesToDequeue2 := 2

	leaves := createTestLeaves(leavesToInsert, 20)
	if _, err := s.QueueLeaves(ctx, tree, leaves, fakeDequeueCutoffTime); err != nil {
		t.Fatalf("Failed to queue leaves: %v", err)
	}

	var (
		err              error
		leaves2, leaves3 []*trillian.LogLeaf
	)

	// Now try to dequeue some of them
	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		leaves2, err = tx2.DequeueLeaves(ctx, leavesToDequeue1, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Failed to dequeue leaves: %v", err)
		}
		if len(leaves2) != leavesToDequeue1 {
			t.Fatalf("Dequeued %d leaves but expected to get %d", len(leaves2), leavesToInsert)
		}
		ensureAllLeavesDistinct(t, leaves2)
		ensureLeavesHaveQueueTimestamp(t, leaves2, fakeDequeueCutoffTime)

		return nil
	})

	// Now try to dequeue the rest of them
	runLogTX(t, s, tree, func(ctx context.Context, tx3 storage.LogTreeTX) error {
		leaves3, err = tx3.DequeueLeaves(ctx, leavesToDequeue2, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Failed to dequeue leaves: %v", err)
		}
		if len(leaves3) != leavesToDequeue2 {
			t.Fatalf("Dequeued %d leaves but expected to get %d", len(leaves3), leavesToDequeue2)
		}
		ensureAllLeavesDistinct(t, leaves3)
		ensureLeavesHaveQueueTimestamp(t, leaves3, fakeDequeueCutoffTime)

		// Plus the union of the leaf batches should all have distinct hashes
		ensureAllLeavesDistinct(t, append(leaves2, leaves3...))

		return nil
	})

	// If we dequeue again then we should now get nothing
	runLogTX(t, s, tree, func(ctx context.Context, tx4 storage.LogTreeTX) error {
		leaves5, err := tx4.DequeueLeaves(ctx, 99, fakeDequeueCutoffTime)
		if err != nil {
			t.Fatalf("Failed to dequeue leaves (second time): %v", err)
		}
		if len(leaves5) != 0 {
			t.Fatalf("Dequeued %d leaves but expected to get none", len(leaves5))
		}

		return nil
	})
}

// Queues leaves and attempts to dequeue before the guard cutoff allows it. This should
// return nothing. Then retry with an inclusive guard cutoff and ensure the leaves
// are returned.
func TestDequeueLeavesGuardInterval(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	leaves := createTestLeaves(leavesToInsert, 20)
	if _, err := s.QueueLeaves(ctx, tree, leaves, fakeQueueTime); err != nil {
		t.Fatalf("Failed to queue leaves: %v", err)
	}

	// Now try to dequeue them using a cutoff that means we should get none
	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		leaves2, err := tx2.DequeueLeaves(ctx, 99, fakeQueueTime.Add(-time.Second))
		if err != nil {
			t.Fatalf("Failed to dequeue leaves: %v", err)
		}
		if len(leaves2) != 0 {
			t.Fatalf("Dequeued %d leaves when they all should be in guard interval", len(leaves2))
		}

		// Try to dequeue again using a cutoff that should include them
		leaves2, err = tx2.DequeueLeaves(ctx, 99, fakeQueueTime.Add(time.Second))
		if err != nil {
			t.Fatalf("Failed to dequeue leaves: %v", err)
		}
		if len(leaves2) != leavesToInsert {
			t.Fatalf("Dequeued %d leaves but expected to get %d", len(leaves2), leavesToInsert)
		}
		ensureAllLeavesDistinct(t, leaves2)

		return nil
	})
}

func TestDequeueLeavesTimeOrdering(t *testing.T) {
	// Queue two small batches of leaves at different timestamps. Do two separate dequeue
	// transactions and make sure the returned leaves are respecting the time ordering of the
	// queue.
	ctx := context.Background()

	cleanTestDB(t, db)

	as := NewAdminStorage(db)
	tree := mustCreateTree(ctx, t, as, testonly.LogTree)
	s := NewLogStorage(db, nil)
	mustSignAndStoreLogRoot(ctx, t, s, tree, 0)

	batchSize := 2
	leaves := createTestLeaves(int64(batchSize), 0)
	leaves2 := createTestLeaves(int64(batchSize), int64(batchSize))

	if _, err := s.QueueLeaves(ctx, tree, leaves, fakeQueueTime); err != nil {
		t.Fatalf("QueueLeaves(1st batch) = %v", err)
	}
	// These are one second earlier so should be dequeued first
	if _, err := s.QueueLeaves(ctx, tree, leaves2, fakeQueueTime.Add(-time.Second)); err != nil {
		t.Fatalf("QueueLeaves(2nd batch) = %v", err)
	}

	// Now try to dequeue two leaves and we should get the second batch
	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		dequeue1, err := tx2.DequeueLeaves(ctx, batchSize, fakeQueueTime)
		if err != nil {
			t.Fatalf("DequeueLeaves(1st) = %v", err)
		}
		if got, want := len(dequeue1), batchSize; got != want {
			t.Fatalf("Dequeue count mismatch (1st) got: %d, want: %d", got, want)
		}
		ensureAllLeavesDistinct(t, dequeue1)

		// Ensure this is the second batch queued by comparing leaf hashes (must be distinct as
		// the leaf data was).
		if !leafInBatch(dequeue1[0], leaves2) || !leafInBatch(dequeue1[1], leaves2) {
			t.Fatalf("Got leaf from wrong batch (1st dequeue): %v", dequeue1)
		}
		iTimestamp := timestamppb.Now()
		for i, l := range dequeue1 {
			l.IntegrateTimestamp = iTimestamp
			l.LeafIndex = int64(i)
		}
		if err := tx2.UpdateSequencedLeaves(ctx, dequeue1); err != nil {
			t.Fatalf("UpdateSequencedLeaves(): %v", err)
		}

		return nil
	})

	// Try to dequeue again and we should get the batch that was queued first, though at a later time
	runLogTX(t, s, tree, func(ctx context.Context, tx3 storage.LogTreeTX) error {
		dequeue2, err := tx3.DequeueLeaves(ctx, batchSize, fakeQueueTime)
		if err != nil {
			t.Fatalf("DequeueLeaves(2nd) = %v", err)
		}
		if got, want := len(dequeue2), batchSize; got != want {
			t.Fatalf("Dequeue count mismatch (2nd) got: %d, want: %d", got, want)
		}
		ensureAllLeavesDistinct(t, dequeue2)

		// Ensure this is the first batch by comparing leaf hashes.
		if !leafInBatch(dequeue2[0], leaves) || !leafInBatch(dequeue2[1], leaves) {
			t.Fatalf("Got leaf from wrong batch (2nd dequeue): %v", dequeue2)
		}

		return nil
	})
}

func TestGetLeavesByHashNotPresent(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cleanTestDB(t, db)
		tree := createTreeOrPanic(db, testonly.LogTree)
		s := NewLogStorage(db, nil)

		runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
			hashes := [][]byte{[]byte("thisdoesn'texist")}
			leaves, err := tx.GetLeavesByHash(ctx, hashes, false)
			if err != nil {
				t.Fatalf("Error getting leaves by hash: %v", err)
			}
			if len(leaves) != 0 {
				t.Fatalf("Expected no leaves returned but got %d", len(leaves))
			}

			return nil
		})
	})

	t.Run("Success (orderBySequence)", func(t *testing.T) {
		cleanTestDB(t, db)
		tree := createTreeOrPanic(db, testonly.LogTree)
		s := NewLogStorage(db, nil)

		runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
			hashes := [][]byte{[]byte("thisdoesn'texist")}
			leaves, err := tx.GetLeavesByHash(ctx, hashes, true)
			if err != nil {
				t.Fatalf("Error getting leaves by hash: %v", err)
			}
			if len(leaves) != 0 {
				t.Fatalf("Expected no leaves returned but got %d", len(leaves))
			}

			return nil
		})
	})
}

func TestGetLeavesByHash(t *testing.T) {
	ctx := context.Background()

	// Create fake leaf as if it had been sequenced
	cleanTestDB(t, db)
	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)

	data := []byte("some data")
	createFakeLeaf(ctx, t, db, tree.TreeId, dummyRawHash, dummyHash, data, someExtraData, sequenceNumber)

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		hashes := [][]byte{dummyHash}
		leaves, err := tx.GetLeavesByHash(ctx, hashes, false)
		if err != nil {
			t.Fatalf("Unexpected error getting leaf by hash: %v", err)
		}
		if len(leaves) != 1 {
			t.Fatalf("Got %d leaves but expected one", len(leaves))
		}
		checkLeafContents(t, leaves[0], sequenceNumber, dummyRawHash, dummyHash, data, someExtraData)

		return nil
	})
}

// GetLeavesByRange tests. -----------------------------------------------------

type getLeavesByRangeTest struct {
	start, count int64
	want         []int64
	wantErr      bool
}

func testGetLeavesByRangeImpl(t *testing.T, create *trillian.Tree, tests []getLeavesByRangeTest) {
	t.Helper()

	cleanTestDB(t, db)

	ctx := context.Background()

	tree, err := createTree(db, create)
	if err != nil {
		t.Fatalf("Error creating log: %v", err)
	}
	// Note: GetLeavesByRange loads the root internally to get the tree size.
	createFakeSignedLogRoot(db, tree, 14)
	s := NewLogStorage(db, nil)

	// Create leaves [0]..[19] but drop leaf [5] and set the tree size to 14.
	for i := int64(0); i < 20; i++ {
		if i == 5 {
			continue
		}

		data := []byte{byte(i)}
		identityHash := sha256.Sum256(data)
		createFakeLeaf(ctx, t, db, tree.TreeId, identityHash[:], identityHash[:], data, someExtraData, i)
	}

	for _, test := range tests {
		runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
			leaves, err := tx.GetLeavesByRange(ctx, test.start, test.count)
			if err != nil {
				if !test.wantErr {
					t.Errorf("GetLeavesByRange(%d, +%d)=_,%v; want _,nil", test.start, test.count, err)
				}

				return nil
			}
			if test.wantErr {
				t.Errorf("GetLeavesByRange(%d, +%d)=_,nil; want _,non-nil", test.start, test.count)
			}
			got := make([]int64, len(leaves))
			for i, leaf := range leaves {
				got[i] = leaf.LeafIndex
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("GetLeavesByRange(%d, +%d)=%+v; want %+v", test.start, test.count, got, test.want)
			}

			return nil
		})
	}
}

func TestGetLeavesByRangeFromLog(t *testing.T) {
	tests := []getLeavesByRangeTest{
		{start: 0, count: 1, want: []int64{0}},
		{start: 0, count: 2, want: []int64{0, 1}},
		{start: 1, count: 3, want: []int64{1, 2, 3}},
		{start: 10, count: 7, want: []int64{10, 11, 12, 13}},
		{start: 13, count: 1, want: []int64{13}},
		{start: 14, count: 4, wantErr: true},   // Starts right after tree size.
		{start: 19, count: 2, wantErr: true},   // Starts further away.
		{start: 3, count: 5, wantErr: true},    // Hits non-contiguous leaves.
		{start: 5, count: 5, wantErr: true},    // Starts from a missing leaf.
		{start: 1, count: 0, wantErr: true},    // Empty range.
		{start: -1, count: 1, wantErr: true},   // Negative start.
		{start: 1, count: -1, wantErr: true},   // Negative count.
		{start: 100, count: 30, wantErr: true}, // Starts after all stored leaves.
	}
	testGetLeavesByRangeImpl(t, testonly.LogTree, tests)
}

func TestGetLeavesByRangeFromPreorderedLog(t *testing.T) {
	tests := []getLeavesByRangeTest{
		{start: 0, count: 1, want: []int64{0}},
		{start: 0, count: 2, want: []int64{0, 1}},
		{start: 1, count: 3, want: []int64{1, 2, 3}},
		{start: 10, count: 7, want: []int64{10, 11, 12, 13, 14, 15, 16}},
		{start: 13, count: 1, want: []int64{13}},
		// Starts right after tree size.
		{start: 14, count: 4, want: []int64{14, 15, 16, 17}},
		{start: 19, count: 2, want: []int64{19}}, // Starts further away.
		{start: 3, count: 5, wantErr: true},      // Hits non-contiguous leaves.
		{start: 5, count: 5, wantErr: true},      // Starts from a missing leaf.
		{start: 1, count: 0, wantErr: true},      // Empty range.
		{start: -1, count: 1, wantErr: true},     // Negative start.
		{start: 1, count: -1, wantErr: true},     // Negative count.
		{start: 100, count: 30, want: []int64{}}, // Starts after all stored leaves.
	}
	testGetLeavesByRangeImpl(t, testonly.PreorderedLogTree, tests)
}

// -----------------------------------------------------------------------------

func TestLatestSignedRootNoneWritten(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	tree, err := createTree(db, testonly.LogTree)
	if err != nil {
		t.Fatalf("createTree: %v", err)
	}

	s := NewLogStorage(db, nil)

	tx, err := s.SnapshotForTree(ctx, tree)
	if !errors.Is(err, storage.ErrTreeNeedsInit) {
		t.Fatalf("SnapshotForTree gave %v, want %v", err, storage.ErrTreeNeedsInit)
	}

	commit(ctx, t, tx)
}

func TestLatestSignedRootDBClosed(t *testing.T) {
	ndb, done := openTestDBOrDie()

	cleanTestDB(t, ndb)

	tree, err := createTree(ndb, testonly.LogTree)
	if err != nil {
		t.Fatalf("createTree: %v", err)
	}

	s := NewLogStorage(ndb, nil)

	done(context.Background())

	tx, err := s.SnapshotForTree(context.Background(), tree)
	require.EqualError(t, err, "sql: database is closed")
	require.Nil(t, tx)
}

func TestAddSequencedLeavesDBClosed(t *testing.T) {
	ndb, done := openTestDBOrDie()

	cleanTestDB(t, ndb)

	tree, err := createTree(ndb, testonly.LogTree)
	if err != nil {
		t.Fatalf("createTree: %v", err)
	}

	s := NewLogStorage(ndb, nil)

	done(context.Background())

	tx, err := s.AddSequencedLeaves(context.Background(), tree, nil, time.Now())
	require.EqualError(t, err, "sql: database is closed")
	require.Nil(t, tx)
}

func TestQueueLeavesDBClosed(t *testing.T) {
	ndb, done := openTestDBOrDie()

	cleanTestDB(t, ndb)

	tree, err := createTree(ndb, testonly.LogTree)
	if err != nil {
		t.Fatalf("createTree: %v", err)
	}

	s := NewLogStorage(ndb, nil)

	done(context.Background())

	tx, err := s.QueueLeaves(context.Background(), tree, nil, time.Now())
	require.EqualError(t, err, "sql: database is closed")
	require.Nil(t, tx)
}

func TestReadWriteTransactionDBClosed(t *testing.T) {
	ndb, done := openTestDBOrDie()

	cleanTestDB(t, ndb)

	tree, err := createTree(ndb, testonly.LogTree)
	if err != nil {
		t.Fatalf("createTree: %v", err)
	}

	s := NewLogStorage(ndb, nil)

	done(context.Background())

	require.EqualError(t, s.ReadWriteTransaction(context.Background(), tree,
		func(ctx context.Context, tx storage.LogTreeTX) error {
			return tx.Close()
		},
	), "sql: database is closed")
}

func TestLatestSignedLogRoot(t *testing.T) {
	cleanTestDB(t, db)
	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)

	root, err := signLogRoot(&types.LogRootV1{
		TimestampNanos: 98765,
		TreeSize:       16,
		Revision:       5,
		RootHash:       dummyHash,
	})
	if err != nil {
		t.Fatalf("SignLogRoot(): %v", err)
	}

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		err := tx.StoreSignedLogRoot(ctx, &trillian.SignedLogRoot{LogRoot: []byte(`[]`)})
		require.EqualError(t, err, "logRootBytes too short")

		return nil
	})

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		if err := tx.StoreSignedLogRoot(ctx, root); err != nil {
			t.Fatalf("Failed to store signed root: %v", err)
		}

		return nil
	})

	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		root2, err := tx2.LatestSignedLogRoot(ctx)
		if err != nil {
			t.Fatalf("Failed to read back new log root: %v", err)
		}
		if !proto.Equal(root, root2) {
			t.Fatalf("Root round trip failed: <%v> and: <%v>", root, root2)
		}

		return nil
	})
}

func TestDuplicateSignedLogRoot(t *testing.T) {
	cleanTestDB(t, db)
	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)

	root, err := signLogRoot(&types.LogRootV1{
		TimestampNanos: 98765,
		TreeSize:       16,
		Revision:       5,
		RootHash:       dummyHash,
	})
	if err != nil {
		t.Fatalf("SignLogRoot(): %v", err)
	}

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		if err := tx.StoreSignedLogRoot(ctx, root); err != nil {
			t.Fatalf("Failed to store signed root: %v", err)
		}
		// Shouldn't be able to do it again
		//		if err := tx.StoreSignedLogRoot(ctx, *root); err == nil {
		//			t.Fatal("Allowed duplicate signed root")
		//		}
		return nil
	})
}

func TestLogRootUpdate(t *testing.T) {
	// Write two roots for a log and make sure the one with the newest timestamp supersedes
	cleanTestDB(t, db)
	tree := createTreeOrPanic(db, testonly.LogTree)
	s := NewLogStorage(db, nil)

	root, err := signLogRoot(&types.LogRootV1{
		TimestampNanos: 98765,
		TreeSize:       16,
		Revision:       5,
		RootHash:       dummyHash,
	})
	if err != nil {
		t.Fatalf("SignLogRoot(): %v", err)
	}

	root2, err := signLogRoot(&types.LogRootV1{
		TimestampNanos: 98766,
		TreeSize:       16,
		Revision:       6,
		RootHash:       dummyHash,
	})
	if err != nil {
		t.Fatalf("SignLogRoot(): %v", err)
	}

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		if err := tx.StoreSignedLogRoot(ctx, root); err != nil {
			t.Fatalf("Failed to store signed root: %v", err)
		}
		if err := tx.StoreSignedLogRoot(ctx, root2); err != nil {
			t.Fatalf("Failed to store signed root: %v", err)
		}

		return nil
	})

	runLogTX(t, s, tree, func(ctx context.Context, tx2 storage.LogTreeTX) error {
		root3, err := tx2.LatestSignedLogRoot(ctx)
		if err != nil {
			t.Fatalf("Failed to read back new log root: %v", err)
		}
		if !proto.Equal(root2, root3) {
			t.Fatalf("Root round trip failed: <%v> and: <%v>", root, root2)
		}

		return nil
	})
}

func TestGetActiveLogIDs(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)
	admin := NewAdminStorage(db)

	// Create a few test trees
	log1 := proto.Clone(testonly.LogTree).(*trillian.Tree)           // nolint: errcheck, forcetypeassert
	log2 := proto.Clone(testonly.LogTree).(*trillian.Tree)           // nolint: errcheck, forcetypeassert
	log3 := proto.Clone(testonly.PreorderedLogTree).(*trillian.Tree) // nolint: errcheck, forcetypeassert
	drainingLog := proto.Clone(testonly.LogTree).(*trillian.Tree)    // nolint: errcheck, forcetypeassert
	frozenLog := proto.Clone(testonly.LogTree).(*trillian.Tree)      // nolint: errcheck, forcetypeassert
	deletedLog := proto.Clone(testonly.LogTree).(*trillian.Tree)     // nolint: errcheck, forcetypeassert

	for _, tree := range []**trillian.Tree{&log1, &log2, &log3, &drainingLog, &frozenLog, &deletedLog} {
		newTree, err := storage.CreateTree(ctx, admin, *tree)
		if err != nil {
			t.Fatalf("CreateTree(%+v) returned err = %v", tree, err)
		}

		*tree = newTree
	}

	// FROZEN is not a valid initial state, so we have to update it separately.
	if _, err := storage.UpdateTree(ctx, admin, frozenLog.TreeId, func(t *trillian.Tree) {
		t.TreeState = trillian.TreeState_FROZEN
	}); err != nil {
		t.Fatalf("UpdateTree() returned err = %v", err)
	}
	// DRAINING is not a valid initial state, so we have to update it separately.
	if _, err := storage.UpdateTree(ctx, admin, drainingLog.TreeId, func(t *trillian.Tree) {
		t.TreeState = trillian.TreeState_DRAINING
	}); err != nil {
		t.Fatalf("UpdateTree() returned err = %v", err)
	}

	// Update deleted trees accordingly
	updateDeletedStmt, err := db.PrepareContext(ctx, "UPDATE Trees SET Deleted = $1 WHERE Tree_Id = $2")
	if err != nil {
		t.Fatalf("PrepareContext() returned err = %v", err)
	}
	defer updateDeletedStmt.Close() // nolint: errcheck

	for _, treeID := range []int64{deletedLog.TreeId} {
		if _, err = updateDeletedStmt.ExecContext(ctx, true, treeID); err != nil {
			t.Fatalf("ExecContext(%v) returned err = %v", treeID, err)
		}
	}

	s := NewLogStorage(db, nil)

	tx, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() returns err = %v", err)
	}
	defer tx.Close() // nolint: errcheck

	got, err := tx.GetActiveLogIDs(ctx)
	if err != nil {
		t.Fatalf("GetActiveLogIDs() returns err = %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Errorf("Commit() returned err = %v", err)
	}

	want := []int64{log1.TreeId, log2.TreeId, log3.TreeId, drainingLog.TreeId}

	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })

	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("post-GetActiveLogIDs diff (-got +want):\n%v", diff)
	}
}

func TestGetActiveLogIDsEmpty(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)
	s := NewLogStorage(db, nil)

	tx, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() = (_, %v), want = (_, nil)", err)
	}
	defer tx.Close() // nolint: errcheck

	ids, err := tx.GetActiveLogIDs(ctx)
	if err != nil {
		t.Fatalf("GetActiveLogIDs() = (_, %v), want = (_, nil)", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Errorf("Commit() = %v, want = nil", err)
	}

	if got, want := len(ids), 0; got != want {
		t.Errorf("GetActiveLogIDs(): got %v IDs, want = %v", got, want)
	}
}

func TestReadOnlyLogTX_Rollback(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	s := NewLogStorage(db, nil)

	tx, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() = (_, %v), want = (_, nil)", err)
	}
	defer tx.Close() // nolint: errcheck

	if _, err := tx.GetActiveLogIDs(ctx); err != nil {
		t.Fatalf("GetActiveLogIDs() = (_, %v), want = (_, nil)", err)
	}
	// It's a bit hard to have a more meaningful test. This should suffice.
	if err := tx.Rollback(); err != nil {
		t.Errorf("Rollback() = (_, %v), want = (_, nil)", err)
	}
}

func TestSortByLeafIdentityHash(t *testing.T) {
	l := make([]*trillian.LogLeaf, 30)
	for i := range l {
		hash := sha256.Sum256([]byte{byte(i)})
		leaf := trillian.LogLeaf{
			LeafIdentityHash: hash[:],
			LeafValue:        []byte(fmt.Sprintf("Value %d", i)),
			ExtraData:        []byte(fmt.Sprintf("Extra %d", i)),
			LeafIndex:        int64(i),
		}
		l[i] = &leaf
	}

	sort.Sort(byLeafIdentityHash(l))

	for i := range l {
		if i == 0 {
			continue
		}

		if bytes.Compare(l[i-1].LeafIdentityHash, l[i].LeafIdentityHash) != -1 {
			t.Errorf("sorted leaves not in order, [%d] = %x, [%d] = %x", i-1, l[i-1].LeafIdentityHash, i, l[i].LeafIdentityHash)
		}
	}
}

func TestLogTreeTX_ReadRevision(t *testing.T) {
	rev, err := (&logTreeTX{root: types.LogRootV1{Revision: 1}}).ReadRevision(context.Background())
	require.NoError(t, err)
	require.Equal(t, rev, int64(1))
}

func ensureAllLeavesDistinct(t *testing.T, leaves []*trillian.LogLeaf) {
	t.Helper()
	// All the leaf value hashes should be distinct because the leaves were created with distinct
	// leaf data. If only we had maps with slices as keys or sets or pretty much any kind of usable
	// data structures we could do this properly.
	for i := range leaves {
		for j := range leaves {
			if i != j && bytes.Equal(leaves[i].LeafIdentityHash, leaves[j].LeafIdentityHash) {
				t.Fatalf("Unexpectedly got a duplicate leaf hash: %v %v",
					leaves[i].LeafIdentityHash, leaves[j].LeafIdentityHash)
			}
		}
	}
}

func ensureLeavesHaveQueueTimestamp(t *testing.T, leaves []*trillian.LogLeaf, want time.Time) {
	t.Helper()

	for _, leaf := range leaves {
		gotQTimestamp := leaf.QueueTimestamp.AsTime()

		if got, want := gotQTimestamp.UnixNano(), want.UnixNano(); got != want {
			t.Errorf("Got leaf with QueueTimestampNanos = %v, want %v: %v", got, want, leaf)
		}
	}
}

// Creates some test leaves with predictable data.
func createTestLeaves(n, startSeq int64) []*trillian.LogLeaf {
	var leaves []*trillian.LogLeaf

	for l := int64(0); l < n; l++ {
		lv := fmt.Sprintf("Leaf %d", l+startSeq)
		h := sha256.New()
		h.Write([]byte(lv)) // nolint: gosec
		leafHash := h.Sum(nil)
		leaf := &trillian.LogLeaf{
			LeafIdentityHash: leafHash,
			MerkleLeafHash:   leafHash,
			LeafValue:        []byte(lv),
			ExtraData:        []byte(fmt.Sprintf("Extra %d", l)),
			LeafIndex:        startSeq + l,
		}
		leaves = append(leaves, leaf)
	}

	return leaves
}

// Convenience methods to avoid copying out "if err != nil { blah }" all over the place.
func runLogTX(t *testing.T, s storage.LogStorage, tree *trillian.Tree, f storage.LogTXFunc) {
	t.Helper()

	if err := s.ReadWriteTransaction(context.Background(), tree, f); err != nil {
		t.Fatalf("Failed to run log tx: %v", err)
	}
}

type committableTX interface {
	Commit(ctx context.Context) error
}

func commit(ctx context.Context, t *testing.T, tx committableTX) {
	t.Helper()

	if err := tx.Commit(ctx); err != nil {
		t.Errorf("Failed to commit tx: %v", err)
	}
}

func leafInBatch(leaf *trillian.LogLeaf, batch []*trillian.LogLeaf) bool {
	for _, bl := range batch {
		if bytes.Equal(bl.LeafIdentityHash, leaf.LeafIdentityHash) {
			return true
		}
	}

	return false
}

// byLeafIdentityHash allows sorting of leaves by their identity hash, so DB
// operations always happen in a consistent order.
type byLeafIdentityHash []*trillian.LogLeaf

func (l byLeafIdentityHash) Len() int      { return len(l) }
func (l byLeafIdentityHash) Swap(i, j int) { l[i], l[j] = l[j], l[i] }
func (l byLeafIdentityHash) Less(i, j int) bool {
	return bytes.Compare(l[i].LeafIdentityHash, l[j].LeafIdentityHash) == -1
}

func logTree(logID int64) *trillian.Tree {
	return &trillian.Tree{
		TreeId:   logID,
		TreeType: trillian.TreeType_LOG,
	}
}

func mustSignAndStoreLogRoot(ctx context.Context, t *testing.T, l storage.LogStorage,
	tree *trillian.Tree, treeSize uint64) { // nolint: unparam
	t.Helper()

	err := l.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		root, err := signLogRoot(&types.LogRootV1{TreeSize: treeSize, RootHash: []byte{0}})
		if err != nil {
			return fmt.Errorf("error creating new SignedLogRoot: %w", err)
		}
		if err := tx.StoreSignedLogRoot(ctx, root); err != nil {
			return fmt.Errorf("error storing new SignedLogRoot: %w", err)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("ReadWriteTransaction() = %v", err)
	}
}
