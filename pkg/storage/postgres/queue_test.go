/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"context"
	"testing"

	"github.com/google/trillian"
	"github.com/stretchr/testify/require"
)

func TestLogTreeTX_UpdateSequencedLeaves(t *testing.T) {
	t.Run("invalid timestamp", func(t *testing.T) {
		require.Contains(t,
			(&logTreeTX{}).UpdateSequencedLeaves(
				context.Background(), []*trillian.LogLeaf{{}},
			).Error(), "got invalid integrate timestamp",
		)
	})
	t.Run("invalid timestamp", func(t *testing.T) {
		leafs := []*trillian.LogLeaf{{LeafIdentityHash: []byte(`123`)}}

		require.EqualError(t,
			(&logTreeTX{}).UpdateSequencedLeaves(context.Background(), leafs),
			"sequenced leaf has incorrect hash size",
		)
	})
}
