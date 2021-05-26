/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/storage_test.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/trillian"
	"github.com/google/trillian/merkle/compact"
	rfc6962 "github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/google/trillian/storage"
	storageto "github.com/google/trillian/storage/testonly"
	stree "github.com/google/trillian/storage/tree"
	"github.com/google/trillian/types"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"

	"github.com/trustbloc/vct/pkg/storage/postgres/testdb"
)

func TestNodeRoundTrip(t *testing.T) {
	nodes := createSomeNodes(256)
	nodeIDs := make([]compact.NodeID, len(nodes))

	for i := range nodes {
		nodeIDs[i] = nodes[i].ID
	}

	for _, tc := range []struct {
		desc    string
		store   []stree.Node
		read    []compact.NodeID
		want    []stree.Node
		wantErr bool
	}{
		{desc: "store-4-read-4", store: nodes[:4], read: nodeIDs[:4], want: nodes[:4]},
		{desc: "store-4-read-1", store: nodes[:4], read: nodeIDs[:1], want: nodes[:1]},
		{desc: "store-2-read-4", store: nodes[:2], read: nodeIDs[:4], want: nodes[:2]},
		{desc: "store-none-read-all", store: nil, read: nodeIDs, wantErr: true},
		{desc: "store-all-read-all", store: nodes, read: nodeIDs, want: nodes},
		{desc: "store-all-read-none", store: nodes, read: nil, want: nil},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			cleanTestDB(t, db)
			as := NewAdminStorage(db)
			tree := mustCreateTree(ctx, t, as, storageto.LogTree)
			s := NewLogStorage(db, nil)

			const writeRev = int64(100)
			runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
				forceWriteRevision(writeRev, tx)
				if err := tx.SetMerkleNodes(ctx, tc.store); err != nil {
					t.Fatalf("Failed to store nodes: %s", err)
				}

				return storeLogRoot(ctx, tx, uint64(len(tc.store)), uint64(writeRev), []byte{1, 2, 3})
			})

			runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
				readNodes, err := tx.GetMerkleNodes(ctx, tc.read)
				if err != nil && !tc.wantErr {
					t.Fatalf("Failed to retrieve nodes: %s", err)
				} else if err == nil && tc.wantErr {
					t.Fatal("Retrieving nodes succeeded unexpectedly")
				}
				if err := nodesAreEqual(readNodes, tc.want); err != nil {
					t.Fatalf("Read back different nodes from the ones stored: %s", err)
				}

				return nil
			})
		})
	}
}

// This test ensures that node writes cross subtree boundaries so this edge case in the subtree
// cache gets exercised. Any tree size > 256 will do this.
func TestLogNodeRoundTripMultiSubtree(t *testing.T) {
	ctx := context.Background()

	cleanTestDB(t, db)

	as := NewAdminStorage(db)
	tree := mustCreateTree(ctx, t, as, storageto.LogTree)

	s := NewLogStorage(db, nil)

	const (
		writeRev = int64(100)
		size     = 871
	)

	nodesToStore, err := createLogNodesForTreeAtSize(t, size)
	if err != nil {
		t.Fatalf("failed to create test tree: %v", err)
	}

	nodeIDsToRead := make([]compact.NodeID, len(nodesToStore))
	for i := range nodesToStore {
		nodeIDsToRead[i] = nodesToStore[i].ID
	}

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		forceWriteRevision(writeRev, tx)
		if err := tx.SetMerkleNodes(ctx, nodesToStore); err != nil {
			t.Fatalf("Failed to store nodes: %s", err)
		}

		return storeLogRoot(ctx, tx, uint64(size), uint64(writeRev), []byte{1, 2, 3})
	})

	runLogTX(t, s, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		readNodes, err := tx.GetMerkleNodes(ctx, nodeIDsToRead)
		if err != nil {
			t.Fatalf("Failed to retrieve nodes: %s", err)
		}
		if err := nodesAreEqual(readNodes, nodesToStore); err != nil {
			missing, extra := diffNodes(readNodes, nodesToStore)
			for _, n := range missing {
				t.Errorf("Missing: %v", n.ID)
			}
			for _, n := range extra {
				t.Errorf("Extra  : %v", n.ID)
			}
			t.Fatalf("Read back different nodes from the ones stored: %s", err)
		}

		return nil
	})
}

func diffNodes(got, want []stree.Node) ([]stree.Node, []stree.Node) {
	var missing []stree.Node

	gotMap := make(map[compact.NodeID]stree.Node)
	for _, n := range got {
		gotMap[n.ID] = n
	}

	for _, n := range want {
		_, ok := gotMap[n.ID]
		if !ok {
			missing = append(missing, n)
		}

		delete(gotMap, n.ID)
	}
	// Unpack the extra nodes to return both as slices
	extra := make([]stree.Node, 0, len(gotMap))
	for _, v := range gotMap {
		extra = append(extra, v)
	}

	return missing, extra
}

func createLogNodesForTreeAtSize(t *testing.T, ts int64) ([]stree.Node, error) {
	t.Helper()

	hasher := rfc6962.New(crypto.SHA256)
	fact := compact.RangeFactory{Hash: hasher.HashChildren}
	cr := fact.NewEmptyRange(0)

	nodeMap := make(map[compact.NodeID][]byte)
	store := func(id compact.NodeID, hash []byte) { nodeMap[id] = hash }

	for l := 0; l < int(ts); l++ {
		hash := hasher.HashLeaf([]byte(fmt.Sprintf("Leaf %d", l)))
		// Store the new leaf node, and all new perfect nodes.
		// TODO(pavelkalinnikov): Visit leaf hash in cr.Append.
		store(compact.NewNodeID(0, cr.End()), hash)

		if err := cr.Append(hash, store); err != nil {
			return nil, err
		}
	}
	// Store the ephemeral nodes as well.
	if _, err := cr.GetRootHash(store); err != nil {
		return nil, err
	}

	// Unroll the map, which has deduped the updates for us and retained the latest
	nodes := make([]stree.Node, 0, len(nodeMap))
	for id, hash := range nodeMap {
		nodes = append(nodes, stree.Node{ID: id, Hash: hash})
	}

	return nodes, nil
}

func storeLogRoot(ctx context.Context, tx storage.LogTreeTX, size, rev uint64, hash []byte) error {
	logRoot, err := (&types.LogRootV1{TreeSize: size, Revision: rev, RootHash: hash}).MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshaling new LogRoot: %w", err)
	}

	root := &trillian.SignedLogRoot{LogRoot: logRoot}
	if err := tx.StoreSignedLogRoot(ctx, root); err != nil {
		return fmt.Errorf("error storing new SignedLogRoot: %w", err)
	}

	return nil
}

// mustCreateTree creates the specified tree using AdminStorage.
func mustCreateTree(ctx context.Context, t *testing.T, s storage.AdminStorage, tree *trillian.Tree) *trillian.Tree {
	t.Helper()

	tree, err := storage.CreateTree(ctx, s, tree)
	if err != nil {
		t.Fatalf("storage.CreateTree(): %v", err)
	}

	return tree
}

func forceWriteRevision(rev int64, tx storage.TreeTX) {
	mtx, ok := tx.(*logTreeTX)
	if !ok {
		panic(fmt.Sprintf("tx is %T, want *logTreeTX", tx))
	}

	mtx.treeTX.writeRevision = rev
}

func createSomeNodes(count int) []stree.Node {
	r := make([]stree.Node, count)
	for i := range r {
		r[i].ID = compact.NewNodeID(0, uint64(i))
		h := sha256.Sum256([]byte{byte(i)})
		r[i].Hash = h[:]
	}

	return r
}

func nodesAreEqual(lhs, rhs []stree.Node) error {
	if ls, rs := len(lhs), len(rhs); ls != rs {
		return fmt.Errorf("different number of nodes, %d vs %d", ls, rs)
	}

	for i := range lhs {
		if l, r := lhs[i].ID, rhs[i].ID; l != r {
			return fmt.Errorf("nodeIDs are not the same,\nlhs = %v,\nrhs = %v", l, r)
		}

		if l, r := lhs[i].Hash, rhs[i].Hash; !bytes.Equal(l, r) {
			return fmt.Errorf("hashes are not the same for %v,\nlhs = %v,\nrhs = %v", lhs[i].ID, l, r)
		}
	}

	return nil
}

func openTestDBOrDie() (*sql.DB, func(context.Context)) {
	_db, done, err := testdb.NewTrillianDB(context.TODO())
	if err != nil {
		panic(err)
	}

	return _db, done
}

func signLogRoot(root *types.LogRootV1) (*trillian.SignedLogRoot, error) {
	logRoot, err := root.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &trillian.SignedLogRoot{LogRoot: logRoot}, nil
}

func createFakeSignedLogRoot(db *sql.DB, tree *trillian.Tree, treeSize uint64) {
	ctx := context.Background()
	l := NewLogStorage(db, nil)

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
		panic(fmt.Sprintf("ReadWriteTransaction() = %v", err))
	}
}

// createTree creates the specified tree using AdminStorage.
func createTree(db *sql.DB, tree *trillian.Tree) (*trillian.Tree, error) {
	ctx := context.Background()
	s := NewAdminStorage(db)

	tree, err := storage.CreateTree(ctx, s, tree)
	if err != nil {
		return nil, err
	}

	return tree, nil
}

func createTreeOrPanic(db *sql.DB, create *trillian.Tree) *trillian.Tree {
	tree, err := createTree(db, create)
	if err != nil {
		panic(fmt.Sprintf("Error creating tree: %v", err))
	}

	return tree
}

// updateTree updates the specified tree using AdminStorage.
func updateTree(db *sql.DB, treeID int64, updateFn func(*trillian.Tree)) (*trillian.Tree, error) {
	ctx := context.Background()
	s := NewAdminStorage(db)

	return storage.UpdateTree(ctx, s, treeID, updateFn)
}

const (
	dockerPostgresImage = "postgres"
	dockerPostgresTag   = "13"
)

func TestMain(m *testing.M) {
	flag.Parse()

	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	postgresResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerPostgresImage, Tag: dockerPostgresTag, Env: []string{
			"POSTGRES_PASSWORD=password", "POSTGRES_DB=test",
		},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5432/tcp": {{HostIP: "", HostPort: "5432"}},
		},
	})
	if err != nil {
		log.Println(`Failed to start Postgres Docker image.` +
			` This can happen if there is a Postgres container still running from a previous unit test run.` +
			` Try "docker ps" from the command line and kill the old container if it's still running.`)

		code = 0

		return
	}

	defer func() {
		if err = pool.Purge(postgresResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	err = backoff.Retry(func() error { // nolint: wrapcheck
		if !testdb.PGAvailable() {
			return errors.New("PG not available, skipping all PG storage tests")
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 120))
	if err != nil {
		panic(err.Error())
	}

	var done func(context.Context)
	db, done = openTestDBOrDie()

	code = m.Run()

	done(context.Background())
}
