/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"errors"
	"testing"

	"github.com/google/trillian/storage"
	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	PGConnStr = "user=postgres dbname=test sslmode=disable"

	require.NoError(t, storage.RegisterProvider("postgres", NewPGProvider))

	t.Run("success", func(t *testing.T) {
		p, err := storage.NewProvider("postgres", nil)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.NotNil(t, p.LogStorage())
		require.NotNil(t, p.AdminStorage())
		require.NoError(t, p.Close())
	})

	t.Run("Error", func(t *testing.T) {
		originalPgOnceErr := pgOnceErr
		pgOnceErr = errors.New("test")
		defer func() { pgOnceErr = originalPgOnceErr }()

		p, err := storage.NewProvider("postgres", nil)
		require.EqualError(t, err, "test")
		require.Nil(t, p)
	})
}
