/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/trustbloc/vct/pkg/controller/command"
)

func TestGetEntriesRequest_Validate(t *testing.T) {
	require.NoError(t, (&GetEntriesRequest{}).Validate())
	require.EqualError(t, (*GetEntriesRequest)(nil).Validate(),
		"validation failed: validate on nil value",
	)
	require.EqualError(t, (&GetEntriesRequest{Start: -1}).Validate(),
		"validation failed: start -1 and end 0 values must be >= 0",
	)
	require.EqualError(t, (&GetEntriesRequest{End: -1}).Validate(),
		"validation failed: start 0 and end -1 values must be >= 0",
	)
	require.EqualError(t, (&GetEntriesRequest{Start: 2, End: 1}).Validate(),
		"validation failed: start 2 and end 1 values is not a valid range",
	)
}

func TestGetProofByHashRequest_Validate(t *testing.T) {
	require.NoError(t, (&GetProofByHashRequest{TreeSize: 1}).Validate())
	require.EqualError(t, (*GetProofByHashRequest)(nil).Validate(),
		"validation failed: validate on nil value",
	)
	require.EqualError(t, (&GetProofByHashRequest{}).Validate(),
		"validation failed: tree_size value must be greater than zero",
	)
}

func TestGetEntryAndProofRequest_Validate(t *testing.T) {
	require.NoError(t, (&GetEntryAndProofRequest{TreeSize: 1}).Validate())
	require.EqualError(t, (*GetEntryAndProofRequest)(nil).Validate(),
		"validation failed: validate on nil value",
	)
	require.EqualError(t, (&GetEntryAndProofRequest{}).Validate(),
		"validation failed: tree_size value must be greater than zero",
	)
	require.EqualError(t, (&GetEntryAndProofRequest{TreeSize: 1, LeafIndex: -1}).Validate(),
		"validation failed: leaf_index must be greater than or equal to zero",
	)
	require.EqualError(t, (&GetEntryAndProofRequest{TreeSize: 1, LeafIndex: 1}).Validate(),
		"validation failed: leaf_index must be less than tree_size",
	)
}

func TestGetSTHConsistencyRequest_Validate(t *testing.T) {
	require.NoError(t, (&GetSTHConsistencyRequest{}).Validate())
	require.EqualError(t, (*GetSTHConsistencyRequest)(nil).Validate(),
		"validation failed: validate on nil value",
	)
	require.EqualError(t, (&GetSTHConsistencyRequest{FirstTreeSize: -1}).Validate(),
		"validation failed: first_tree_size -1 and second_tree_size 0 values must be >= 0",
	)
	require.EqualError(t, (&GetSTHConsistencyRequest{SecondTreeSize: -1}).Validate(),
		"validation failed: first_tree_size 0 and second_tree_size -1 values must be >= 0",
	)
	require.EqualError(t, (&GetSTHConsistencyRequest{FirstTreeSize: 2, SecondTreeSize: 1}).Validate(),
		"validation failed: first_tree_size 2 and second_tree_size 1 values is not a valid range",
	)
}
