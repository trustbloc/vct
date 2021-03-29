/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service errors.
var (
	ErrValidation = NewBadRequestError(New("validation failed"))
	ErrBadRequest = NewBadRequestError(New("bad request"))
	ErrNotFound   = NewNotFoundError(New("not found"))
	ErrInternal   = NewStatusInternalServerError(New("internal error"))
)

// StatusErr an error with status code.
type StatusErr struct {
	error
	status int
}

// Unwrap returns the result of calling the Unwrap method on err, if err's.
func (e *StatusErr) Unwrap() error {
	return errors.Unwrap(e.error)
}

// StatusCode returns HTTP status code.
func (e *StatusErr) StatusCode() int {
	return e.status
}

// New returns an error that formats as the given text.
func New(text string) error {
	return errors.New(text)
}

// NewStatusInternalServerError represents InternalServerError.
func NewStatusInternalServerError(err error) *StatusErr {
	return &StatusErr{error: err, status: http.StatusInternalServerError}
}

// NewBadRequestError represents BadRequestError.
func NewBadRequestError(err error) *StatusErr {
	return &StatusErr{error: err, status: http.StatusBadRequest}
}

// NewNotFoundError represents NotFoundError.
func NewNotFoundError(err error) *StatusErr {
	return &StatusErr{error: err, status: http.StatusNotFound}
}

// StatusCodeFromError returns status code if an error implements an interface the func supports rpc errors as well.
func StatusCodeFromError(e error) int {
	if err, ok := e.(interface{ StatusCode() int }); ok { // nolint: errorlint
		return err.StatusCode()
	}

	rpcStatus, ok := status.FromError(e)
	if ok {
		return statusCodeFromRPCError(rpcStatus.Code())
	}

	if err := errors.Unwrap(e); err != nil {
		return StatusCodeFromError(err)
	}

	return http.StatusInternalServerError
}

func statusCodeFromRPCError(rpcCode codes.Code) int {
	switch rpcCode { // nolint: exhaustive
	case codes.OK:
		return http.StatusOK
	case codes.Canceled, codes.DeadlineExceeded:
		return http.StatusRequestTimeout
	case codes.InvalidArgument, codes.OutOfRange, codes.AlreadyExists:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	case codes.PermissionDenied, codes.ResourceExhausted:
		return http.StatusForbidden
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.Aborted:
		return http.StatusConflict
	case codes.Unimplemented:
		return http.StatusNotImplemented
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
