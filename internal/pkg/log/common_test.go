/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommonLogs(t *testing.T) {
	const module = "test_module"

	t.Run("WriteResponseBodyError", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := New(module,
			WithStdErr(stdErr),
			WithFields(WithServiceName("myservice")),
		)

		WriteResponseBodyError(logger, errors.New("response body error"))

		require.Contains(t, stdErr.Buffer.String(), `Error writing response body`)
		require.Contains(t, stdErr.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdErr.Buffer.String(), `"error": "response body error"`)
		require.Contains(t, stdErr.Buffer.String(), "log/common_test.go")
	})
}
