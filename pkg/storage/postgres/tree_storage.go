/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/tree_storage.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/google/trillian"
	"github.com/google/trillian/storage/cache"
	"github.com/google/trillian/storage/storagepb"
	trilliantree "github.com/google/trillian/storage/tree"
	"google.golang.org/protobuf/proto"
)

const (
	placeholderSQL        = "<placeholder>"
	insertSubtreeMultiSQL = `INSERT INTO subtree(tree_id, subtree_id, nodes, subtree_revision) ` + placeholderSQL
	// TODO(RJPercival): Consider using a recursive CTE in selectSubtreeSQL
	// to get the benefits of a loose index scan, which would improve
	// performance: https://wiki.postgresql.org/wiki/Loose_indexscan
	selectSubtreeSQL = `
		SELECT x.subtree_id, x.max_revision, subtree.nodes
		FROM (
			SELECT n.subtree_id, max(n.subtree_revision) AS max_revision
			FROM subtree n
			WHERE n.subtree_id IN (` + placeholderSQL + `) AND
			n.tree_id = <param> AND n.subtree_revision <= <param>
			GROUP BY n.subtree_id
		) AS x
		INNER JOIN subtree
		ON subtree.subtree_id = x.subtree_id
		AND subtree.subtree_revision = x.max_revision
		AND subtree.tree_id = <param>`
	insertTreeHeadSQL = `INSERT INTO 
	  tree_head(tree_id,tree_head_timestamp,tree_size,root_hash,tree_revision,root_signature) VALUES($1,$2,$3,$4,$5,$6)`
)

// pgTreeStorage contains the pgLogStorage implementation.
type pgTreeStorage struct {
	db *sql.DB

	// Must hold the mutex before manipulating the statement map. Sharing a lock because
	// it only needs to be held while the statements are built, not while they execute and
	// this will be a short time. These maps are from the number of placeholder '$#'
	// in the query to the statement that should be used.
	statementMutex sync.Mutex
	statements     map[string]map[int]*sql.Stmt
}

// OpenDB opens a database connection for all PG-based storage implementations.
func OpenDB(connStr string) (*sql.DB, error) {
	return sql.Open("postgres", connStr)
}

func newTreeStorage(db *sql.DB) *pgTreeStorage {
	return &pgTreeStorage{
		db:         db,
		statements: make(map[string]map[int]*sql.Stmt),
	}
}

// statementSkeleton contains the structure of a query to create.
type statementSkeleton struct {
	// sql is the main query with an embedded placeholder.
	sql string
	// firstInsertion is the first sql query that should be inserted
	// in place of the placeholder.
	firstInsertion string
	// firstPlaceholders is the number of variables in the firstInsertion.
	// Used for string interpolation.
	firstPlaceholders int
	// restInsertion is the remaining sql query that should be repeated following
	// the first insertion.
	restInsertion string
	// restPlaceholders is the number of variables in a single restInsertion.
	// Used for string interpolation.
	restPlaceholders int
	// num is the total repetitions (firstInsertion + restInsertion * num - 1) that
	// should be inserted.
	num int
}

// expandPlaceholderSQL expands an sql statement by adding a specified number of '%s'
// placeholder slots. At most one placeholder will be expanded.
func expandPlaceholderSQL(skeleton *statementSkeleton) (string, error) {
	if skeleton.num <= 0 {
		return "", fmt.Errorf("trying to expand SQL placeholder with <= 0 parameters: %s", skeleton.sql)
	}

	restCount := skeleton.num - 1

	totalArray := make([]interface{}, skeleton.firstPlaceholders+skeleton.restPlaceholders*(restCount))
	for i := range totalArray {
		totalArray[i] = fmt.Sprintf("$%d", i+1)
	}

	toInsertBuilder := strings.Builder{}
	toInsertBuilder.WriteString(fmt.Sprintf(skeleton.firstInsertion, totalArray[:skeleton.firstPlaceholders]...))
	remainingInsertion := strings.Repeat(","+skeleton.restInsertion, restCount)
	toInsertBuilder.WriteString(fmt.Sprintf(remainingInsertion, totalArray[skeleton.firstPlaceholders:]...))

	return strings.Replace(skeleton.sql, placeholderSQL, toInsertBuilder.String(), 1), nil
}

// getStmt creates and caches sql.Stmt structs based on the passed in statement
// and number of bound arguments.
func (p *pgTreeStorage) getStmt(ctx context.Context, skeleton *statementSkeleton) (*sql.Stmt, error) {
	p.statementMutex.Lock()
	defer p.statementMutex.Unlock()

	if p.statements[skeleton.sql] != nil {
		if p.statements[skeleton.sql][skeleton.num] != nil {
			return p.statements[skeleton.sql][skeleton.num], nil
		}
	} else {
		p.statements[skeleton.sql] = make(map[int]*sql.Stmt)
	}

	statement, err := expandPlaceholderSQL(skeleton)

	counter := skeleton.restPlaceholders*skeleton.num + 1
	for strings.Contains(statement, "<param>") {
		statement = strings.Replace(statement, "<param>", "$"+strconv.Itoa(counter), 1)
		counter++
	}

	if err != nil {
		return nil, err
	}

	s, err := p.db.PrepareContext(ctx, statement)
	if err != nil {
		return nil, err
	}

	p.statements[skeleton.sql][skeleton.num] = s

	return s, nil
}

func (p *pgTreeStorage) getSubtreeStmt(ctx context.Context, num int) (*sql.Stmt, error) {
	skeleton := &statementSkeleton{
		sql:               selectSubtreeSQL,
		firstInsertion:    "%s",
		firstPlaceholders: 1,
		restInsertion:     "%s",
		restPlaceholders:  1,
		num:               num,
	}

	return p.getStmt(ctx, skeleton)
}

func (p *pgTreeStorage) setSubtreeStmt(ctx context.Context, num int) (*sql.Stmt, error) {
	const placeholders = 4

	skeleton := &statementSkeleton{
		sql:               insertSubtreeMultiSQL,
		firstInsertion:    "VALUES(%s, %s, %s, %s)",
		firstPlaceholders: placeholders,
		restInsertion:     "(%s, %s, %s, %s)",
		restPlaceholders:  placeholders,
		num:               num,
	}

	return p.getStmt(ctx, skeleton)
}

func (p *pgTreeStorage) beginTreeTx(ctx context.Context,
	tree *trillian.Tree, hashSizeBytes int, subtreeCache *cache.SubtreeCache) (treeTX, error) {
	t, err := p.db.BeginTx(ctx, nil /* opts */)
	if err != nil {
		return treeTX{}, err
	}

	return treeTX{
		tx:            t,
		ts:            p,
		treeID:        tree.TreeId,
		treeType:      tree.TreeType,
		hashSizeBytes: hashSizeBytes,
		subtreeCache:  subtreeCache,
		writeRevision: -1,
	}, nil
}

type treeTX struct {
	closed        bool
	tx            *sql.Tx
	ts            *pgTreeStorage
	treeID        int64
	treeType      trillian.TreeType
	hashSizeBytes int
	subtreeCache  *cache.SubtreeCache
	writeRevision int64
}

func (t *treeTX) getSubtree(ctx context.Context, treeRevision int64, id []byte) (*storagepb.SubtreeProto, error) {
	s, err := t.getSubtrees(ctx, treeRevision, [][]byte{id})
	if err != nil {
		return nil, err
	}

	switch len(s) {
	case 0:
		return nil, nil
	case 1:
		return s[0], nil
	default:
		return nil, fmt.Errorf("got %d subtrees, but expected 1", len(s))
	}
}

func (t *treeTX) getSubtrees(ctx context.Context, treeRevision int64, ids [][]byte) ([]*storagepb.SubtreeProto, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	tmpl, err := t.ts.getSubtreeStmt(ctx, len(ids))
	if err != nil {
		return nil, err
	}

	stx := t.tx.StmtContext(ctx, tmpl)
	defer stx.Close() // nolint: errcheck

	args := make([]interface{}, 0, len(ids)+3) // nolint: gomnd

	// Populate args with node IDs.
	for _, id := range ids {
		args = append(args, id)
	}

	args = append(args,
		interface{}(t.treeID),
		interface{}(treeRevision),
		interface{}(t.treeID),
	)

	rows, err := stx.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // nolint: errcheck

	ret := make([]*storagepb.SubtreeProto, 0, len(ids))

	for rows.Next() {
		var (
			subtreeIDBytes []byte
			subtreeRev     int64
			nodesRaw       []byte
			subtree        storagepb.SubtreeProto
		)

		if err := rows.Scan(&subtreeIDBytes, &subtreeRev, &nodesRaw); err != nil {
			return nil, err
		}

		if err := proto.Unmarshal(nodesRaw, &subtree); err != nil {
			return nil, err
		}

		if subtree.Prefix == nil {
			subtree.Prefix = []byte{}
		}

		ret = append(ret, &subtree)
	}

	// The InternalNodes cache is possibly nil here, but the SubtreeCache (which called
	// this method) will re-populate it.
	return ret, rows.Err()
}

func (t *treeTX) storeSubtrees(ctx context.Context, subtrees []*storagepb.SubtreeProto) error {
	if len(subtrees) == 0 {
		return nil
	}

	args := make([]interface{}, 0, len(subtrees))

	for _, s := range subtrees {
		st := s
		if st.Prefix == nil {
			panic(fmt.Errorf("nil prefix on %v", st))
		}

		subtreeBytes, err := proto.Marshal(st)
		if err != nil {
			return err
		}

		args = append(args,
			t.treeID,
			st.Prefix,
			subtreeBytes,
			t.writeRevision,
		)
	}

	tmpl, err := t.ts.setSubtreeStmt(ctx, len(subtrees))
	if err != nil {
		return err
	}

	stx := t.tx.StmtContext(ctx, tmpl)
	defer stx.Close() // nolint: errcheck

	_, err = stx.ExecContext(ctx, args...)

	return err
}

func (t *treeTX) Commit(ctx context.Context) error {
	if t.writeRevision > -1 {
		if err := t.subtreeCache.Flush(ctx, func(ctx context.Context, st []*storagepb.SubtreeProto) error {
			return t.storeSubtrees(ctx, st)
		}); err != nil {
			return err
		}
	}

	t.closed = true

	return t.tx.Commit()
}

func (t *treeTX) Rollback() error {
	t.closed = true

	return t.tx.Rollback()
}

func (t *treeTX) Close() error {
	if !t.closed {
		return t.Rollback()
	}

	return nil
}

func (t *treeTX) SetMerkleNodes(ctx context.Context, nodes []trilliantree.Node) error {
	for _, n := range nodes {
		err := t.subtreeCache.SetNodeHash(n.ID, n.Hash,
			func(id []byte) (*storagepb.SubtreeProto, error) {
				return t.getSubtree(ctx, t.writeRevision, id)
			})
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *treeTX) IsOpen() bool {
	return !t.closed
}

// getSubtreesAtRev returns a GetSubtreesFunc which reads at the passed in rev.
func (t *treeTX) getSubtreesAtRev(ctx context.Context, rev int64) cache.GetSubtreesFunc {
	return func(ids [][]byte) ([]*storagepb.SubtreeProto, error) {
		return t.getSubtrees(ctx, rev, ids)
	}
}

// SQLResult is used for mocking.
type SQLResult sql.Result

func checkResultOkAndRowCountIs(res SQLResult, err error, count int64) error {
	// The Exec() might have just failed
	if err != nil {
		return err
	}

	// Otherwise we have to look at the result of the operation
	rowsAffected, rowsError := res.RowsAffected()

	if rowsError != nil {
		return rowsError
	}

	if rowsAffected != count {
		return fmt.Errorf("expected %d row(s) to be affected but saw: %d", count,
			rowsAffected)
	}

	return nil
}
