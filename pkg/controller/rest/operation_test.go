/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -self_package mocks -package rest_test . Cmd

package rest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/errors"
	. "github.com/trustbloc/vct/pkg/controller/rest"
)

const alias = `maple2021`

func TestOperation_AddVC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const dummyVC = `{credentials}`

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().AddVC(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			payload, err := io.ReadAll(r)
			require.NoError(t, err)

			require.Equal(t, `{"alias":"maple2021","vc_entry":"e2NyZWRlbnRpYWxzfQ=="}`, string(payload))
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, AddVCPath),
			bytes.NewBufferString(dummyVC), strings.Replace(AddVCPath, "{alias}", alias, 1),
		)

		require.Equal(t, http.StatusOK, code)
	})

	t.Run("Bad request", func(t *testing.T) {
		operation := New(nil, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, AddVCPath),
			&readerMock{errors.New("EOF")}, AddVCPath,
		)

		require.Equal(t, http.StatusInternalServerError, code)
	})

	t.Run("Bad request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const dummyVC = `{credentials}`

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().AddVC(gomock.Any(), gomock.Any()).Return(errors.ErrBadRequest)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, AddVCPath),
			bytes.NewBufferString(dummyVC), AddVCPath,
		)

		require.Equal(t, http.StatusBadRequest, code)
	})
}

func TestOperation_GetSTH(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().GetSTH(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			payload, err := io.ReadAll(r)
			require.NoError(t, err)

			require.Equal(t, fmt.Sprintf("%q", alias), string(payload))
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t, handlerLookup(t, operation, GetSTHPath), nil,
			strings.Replace(GetSTHPath, "{alias}", alias, 1),
		)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_Metrics(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(NewMockCmd(ctrl), &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t, handlerLookup(t, operation, MetricsPath), nil, MetricsPath)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_GetIssuers(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().GetIssuers(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			payload, err := io.ReadAll(r)
			require.NoError(t, err)

			require.Equal(t, fmt.Sprintf("%q", alias), string(payload))
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t, handlerLookup(t, operation, GetIssuersPath), nil,
			strings.Replace(GetIssuersPath, "{alias}", alias, 1),
		)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_HealthCheck(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		operation := New(nil, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t, handlerLookup(t, operation, HealthCheckPath), nil, HealthCheckPath)

		require.Equal(t, http.StatusOK, code)
	})

	t.Run("failed to db check", func(t *testing.T) {
		operation := New(nil, &mockService{pingErr: fmt.Errorf("failed to ping")}, &mockService{}, nil)

		_, code := sendRequestToHandler(t, handlerLookup(t, operation, HealthCheckPath), nil, HealthCheckPath)

		require.Equal(t, http.StatusServiceUnavailable, code)
	})

	t.Run("failed to key manager check", func(t *testing.T) {
		operation := New(nil, &mockService{}, &mockService{healthCheckErr: fmt.Errorf("failed")}, nil)

		_, code := sendRequestToHandler(t, handlerLookup(t, operation, HealthCheckPath), nil, HealthCheckPath)

		require.Equal(t, http.StatusServiceUnavailable, code)
	})
}

func TestOperation_Webfinger(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		const resourceID = "https://vct.example.com/" + alias

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().Webfinger(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			payload, err := io.ReadAll(r)
			require.NoError(t, err)

			require.Equal(t, fmt.Sprintf("%q", resourceID), string(payload))
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, WebfingerPath), nil,
			WebfingerPath+"?resource="+resourceID,
		)

		require.Equal(t, http.StatusOK, code)
	})
}

func TestOperation_GetSTHConsistency(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().GetSTHConsistency(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			var req *command.GetSTHConsistencyRequest
			require.NoError(t, json.NewDecoder(r).Decode(&req))
			require.Equal(t, int64(1), req.FirstTreeSize)
			require.Equal(t, int64(2), req.SecondTreeSize)
			require.Equal(t, alias, req.Alias)
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetSTHConsistencyPath), nil,
			strings.Replace(GetSTHConsistencyPath, "{alias}", alias, 1)+"?first=1&second=2",
		)

		require.Equal(t, http.StatusOK, code)
	})

	t.Run("first parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetSTHConsistencyPath), nil,
			GetSTHConsistencyPath+"?first=one",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"first\\\" is not a number")
	})

	t.Run("second parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetSTHConsistencyPath), nil,
			GetSTHConsistencyPath+"?first=1&second=second",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"second\\\" is not a number")
	})
}

func TestOperation_GetEntries(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().GetEntries(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			var req *command.GetEntriesRequest
			require.NoError(t, json.NewDecoder(r).Decode(&req))
			require.Equal(t, int64(1), req.Start)
			require.Equal(t, int64(2), req.End)
			require.Equal(t, alias, req.Alias)
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetEntriesPath), nil,
			strings.Replace(GetEntriesPath, "{alias}", alias, 1)+"?start=1&end=2",
		)

		require.Equal(t, http.StatusOK, code)
	})

	t.Run("start parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetEntriesPath), nil,
			GetEntriesPath+"?start=one",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"start\\\" is not a number")
	})

	t.Run("end parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetEntriesPath), nil,
			GetEntriesPath+"?start=1&end=end",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"end\\\" is not a number")
	})
}

func TestOperation_GetProofByHash(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().GetProofByHash(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			var req *command.GetProofByHashRequest
			require.NoError(t, json.NewDecoder(r).Decode(&req))
			require.Equal(t, int64(1), req.TreeSize)
			require.Equal(t, "hash", req.Hash)
			require.Equal(t, alias, req.Alias)
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetProofByHashPath), nil,
			strings.Replace(GetProofByHashPath, "{alias}", alias, 1)+"?hash=hash&tree_size=1",
		)

		require.Equal(t, http.StatusOK, code)
	})

	t.Run("tree_size parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetProofByHashPath), nil,
			GetProofByHashPath+"?tree_size=one",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"tree_size\\\" is not a number")
	})
}

func TestOperation_GetEntryAndProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cmd := NewMockCmd(ctrl)
		cmd.EXPECT().GetEntryAndProof(gomock.Any(), gomock.Any()).Do(func(_ io.Writer, r io.Reader) {
			var req *command.GetEntryAndProofRequest
			require.NoError(t, json.NewDecoder(r).Decode(&req))
			require.Equal(t, int64(1), req.LeafIndex)
			require.Equal(t, int64(2), req.TreeSize)
			require.Equal(t, alias, req.Alias)
		}).Return(nil)

		operation := New(cmd, &mockService{}, &mockService{}, nil)

		_, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetEntryAndProofPath), nil,
			strings.Replace(GetEntryAndProofPath, "{alias}", alias, 1)+"?leaf_index=1&tree_size=2",
		)

		require.Equal(t, http.StatusOK, code)
	})

	t.Run("leaf_index parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetEntryAndProofPath), nil,
			GetEntryAndProofPath+"?leaf_index=one",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"leaf_index\\\" is not a number")
	})

	t.Run("tree_size parameter is not a number", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		operation := New(nil, &mockService{}, &mockService{}, nil)

		buf, code := sendRequestToHandler(t,
			handlerLookup(t, operation, GetEntryAndProofPath), nil,
			GetEntryAndProofPath+"?leaf_index=1&tree_size=tree_size",
		)

		require.Equal(t, http.StatusBadRequest, code)
		require.Contains(t, buf.String(), "validation failed: parameter \\\"tree_size\\\" is not a number")
	})
}

func handlerLookup(t *testing.T, op *Operation, lookup string) rest.Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(t *testing.T, handler rest.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int) {
	t.Helper()

	// prepare request
	req, err := http.NewRequestWithContext(context.Background(), handler.Method(), path, requestBody)
	require.NoError(t, err)

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code
}

type readerMock struct{ err error }

func (r *readerMock) Read(p []byte) (n int, err error) {
	return 0, r.err
}

type mockService struct {
	healthCheckErr error
	pingErr        error
}

func (m *mockService) HealthCheck() error {
	return m.healthCheckErr
}

func (m *mockService) Ping() error {
	return m.pingErr
}
