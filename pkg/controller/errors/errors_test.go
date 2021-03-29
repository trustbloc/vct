/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	. "github.com/trustbloc/vct/pkg/controller/errors"
)

func TestStatusCodeFromError(t *testing.T) {
	const errMsg = "error"

	// http errors
	require.Equal(t, StatusCodeFromError(NewStatusInternalServerError(New(errMsg))), http.StatusInternalServerError)
	require.Equal(t, StatusCodeFromError(NewBadRequestError(New(errMsg))), http.StatusBadRequest)
	require.Equal(t, StatusCodeFromError(NewNotFoundError(New(errMsg))), http.StatusNotFound)

	// grpc errors
	require.Equal(t, StatusCodeFromError(status.Error(codes.OK, errMsg)), http.StatusOK)
	require.Equal(t, StatusCodeFromError(status.Error(codes.Canceled, errMsg)), http.StatusRequestTimeout)
	require.Equal(t, StatusCodeFromError(status.Error(codes.DeadlineExceeded, errMsg)), http.StatusRequestTimeout)
	require.Equal(t, StatusCodeFromError(status.Error(codes.InvalidArgument, errMsg)), http.StatusBadRequest)
	require.Equal(t, StatusCodeFromError(status.Error(codes.OutOfRange, errMsg)), http.StatusBadRequest)
	require.Equal(t, StatusCodeFromError(status.Error(codes.AlreadyExists, errMsg)), http.StatusBadRequest)
	require.Equal(t, StatusCodeFromError(status.Error(codes.NotFound, errMsg)), http.StatusNotFound)
	require.Equal(t, StatusCodeFromError(status.Error(codes.PermissionDenied, errMsg)), http.StatusForbidden)
	require.Equal(t, StatusCodeFromError(status.Error(codes.ResourceExhausted, errMsg)), http.StatusForbidden)
	require.Equal(t, StatusCodeFromError(status.Error(codes.Unauthenticated, errMsg)), http.StatusUnauthorized)
	require.Equal(t, StatusCodeFromError(status.Error(codes.FailedPrecondition, errMsg)), http.StatusPreconditionFailed)
	require.Equal(t, StatusCodeFromError(status.Error(codes.Aborted, errMsg)), http.StatusConflict)
	require.Equal(t, StatusCodeFromError(status.Error(codes.Unimplemented, errMsg)), http.StatusNotImplemented)
	require.Equal(t, StatusCodeFromError(status.Error(codes.Unavailable, errMsg)), http.StatusServiceUnavailable)
	require.Equal(t, StatusCodeFromError(status.Error(codes.Unknown, errMsg)), http.StatusInternalServerError)

	// by default error has status InternalServerError
	require.Equal(t, StatusCodeFromError(New(errMsg)), http.StatusInternalServerError)

	// wrapped error
	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrValidation)), http.StatusBadRequest)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrValidation), ErrValidation))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrValidation))), ErrValidation)

	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrBadRequest)), http.StatusBadRequest)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrBadRequest), ErrBadRequest))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrBadRequest))), ErrBadRequest)

	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrNotFound)), http.StatusNotFound)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrNotFound), ErrNotFound))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrNotFound))), ErrNotFound)

	require.Equal(t, StatusCodeFromError(fmt.Errorf("wrapped: %w", ErrInternal)), http.StatusInternalServerError)
	require.True(t, errors.Is(fmt.Errorf("wrapped: %w", ErrInternal), ErrInternal))
	require.Equal(t, errors.Unwrap(NewBadRequestError(fmt.Errorf("wrapped: %w", ErrInternal))), ErrInternal)
}
