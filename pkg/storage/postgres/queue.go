/*
Copyright and license information from original project:
Licence: https://github.com/google/trillian/blob/6127136b153156fc6becb74edd21259fe4260ddc/LICENSE
Source:  https://github.com/google/trillian/blob/09456fa3331789ba45a5edf1eedb8c1cdc98c3ff/storage/postgres/queue.go

Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/trillian"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// If this statement ORDER BY clause is changed refer to the comment in removeSequencedLeaves.
	selectQueuedLeavesSQL = `SELECT leaf_identity_hash,merkle_leaf_hash,queue_timestamp_nanos
                        FROM unsequenced
                        WHERE tree_id=$1
                        AND bucket=0
                        AND queue_timestamp_nanos<=$2
                        ORDER BY queue_timestamp_nanos,leaf_identity_hash ASC LIMIT $3`
	insertUnsequencedEntrySQL = "select insert_leaf_data_ignore_duplicates($1,$2,$3,$4)"
	deleteUnsequencedSQL      = `DELETE FROM unsequenced WHERE tree_id = $1 and bucket=0 and 
								queue_timestamp_nanos = $2 and leaf_identity_hash=$3`
)

type dequeuedLeaf struct {
	queueTimestampNanos int64
	leafIdentityHash    []byte
}

func dequeueInfo(leafIDHash []byte, queueTimestamp int64) dequeuedLeaf {
	return dequeuedLeaf{queueTimestampNanos: queueTimestamp, leafIdentityHash: leafIDHash}
}

func (t *logTreeTX) dequeueLeaf(rows *sql.Rows) (*trillian.LogLeaf, dequeuedLeaf, error) {
	var (
		leafIDHash     []byte
		merkleHash     []byte
		queueTimestamp int64
	)

	err := rows.Scan(&leafIDHash, &merkleHash, &queueTimestamp)
	if err != nil {
		return nil, dequeuedLeaf{}, err
	}

	// Note: the LeafData and ExtraData being nil here is OK as this is only used by the
	// sequencer. The sequencer only writes to the SequencedLeafData table and the client
	// supplied data was already written to LeafData as part of queueing the leaf.
	queueTimestampProto := timestamppb.New(time.Unix(0, queueTimestamp))
	if err := queueTimestampProto.CheckValid(); err != nil {
		return nil, dequeuedLeaf{}, fmt.Errorf("got invalid queue timestamp: %w", err)
	}

	leaf := &trillian.LogLeaf{
		LeafIdentityHash: leafIDHash,
		MerkleLeafHash:   merkleHash,
		QueueTimestamp:   queueTimestampProto,
	}

	return leaf, dequeueInfo(leafIDHash, queueTimestamp), nil
}

func queueArgs(_ int64, _ []byte, queueTimestamp time.Time) []interface{} {
	return []interface{}{queueTimestamp.UnixNano()}
}

func (t *logTreeTX) UpdateSequencedLeaves(ctx context.Context, leaves []*trillian.LogLeaf) error {
	for _, leaf := range leaves {
		// This should fail on insert but catch it early
		if len(leaf.LeafIdentityHash) != t.hashSizeBytes {
			return errors.New("sequenced leaf has incorrect hash size")
		}

		if err := leaf.IntegrateTimestamp.CheckValid(); err != nil {
			return fmt.Errorf("got invalid integrate timestamp: %w", err)
		}

		iTimestamp := leaf.IntegrateTimestamp.AsTime()

		_, err := t.tx.ExecContext(
			ctx,
			insertSequencedLeafSQL,
			t.treeID,
			leaf.LeafIndex,
			leaf.LeafIdentityHash,
			leaf.MerkleLeafHash,
			iTimestamp.UnixNano(),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// removeSequencedLeaves removes the passed in leaves slice (which may be
// modified as part of the operation).
func (t *logTreeTX) removeSequencedLeaves(ctx context.Context, leaves []dequeuedLeaf) error {
	// Don't need to re-sort because the query ordered by leaf hash. If that changes because
	// the query is expensive then the sort will need to be done here. See comment in
	// QueueLeaves.
	stx, err := t.tx.PrepareContext(ctx, deleteUnsequencedSQL)
	if err != nil {
		return err
	}

	defer stx.Close() // nolint: errcheck

	for _, dql := range leaves {
		result, err := stx.ExecContext(ctx, t.treeID, dql.queueTimestampNanos, dql.leafIdentityHash)

		err = checkResultOkAndRowCountIs(result, err, int64(1))
		if err != nil {
			return err
		}
	}

	return nil
}
