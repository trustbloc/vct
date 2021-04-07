/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -self_package mocks -package vct_test . HTTPClient

package vct_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
)

const endpoint = "http://example.com"

func TestClient_AddVC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.AddVCResponse{
			SVCTVersion: 1,
			ID:          []byte(`id`),
			Timestamp:   1234567889,
			Extensions:  "extensions",
			Signature:   []byte(`signature`),
		}

		expectedCredential := []byte(`{credential}`)

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Do(func(req *http.Request) {
			var credential []byte

			credential, err = ioutil.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, expectedCredential, credential)
		}).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.AddVC(context.Background(), expectedCredential)
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.AddVC(context.Background(), []byte{})
		require.EqualError(t, err, "add VC: error")
	})
}

func TestClient_GetIssuers(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := []string{"issuer_1", "issuer_2"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.GetIssuers(context.Background())
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.GetIssuers(context.Background())
		require.EqualError(t, err, "get issuers: error")
	})
}

func TestClient_GetSTH(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.GetSTHResponse{
			TreeSize:          1,
			Timestamp:         1234567889,
			SHA256RootHash:    []byte(`SHA256RootHash`),
			TreeHeadSignature: []byte(`TreeHeadSignature`),
		}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.GetSTH(context.Background())
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.GetSTH(context.Background())
		require.EqualError(t, err, "get STH: error")
	})
}

func TestClient_GetSTHConsistency(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.GetSTHConsistencyResponse{
			Consistency: [][]byte{[]byte("consistency")},
		}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Do(func(req *http.Request) {
			require.Equal(t, "1", req.URL.Query().Get("first"))
			require.Equal(t, "2", req.URL.Query().Get("second"))
		}).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.GetSTHConsistency(context.Background(), 1, 2)
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.GetSTHConsistency(context.Background(), 1, 2)
		require.EqualError(t, err, "get STH consistency: error")
	})
}

func TestClient_GetProofByHash(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.GetProofByHashResponse{
			LeafIndex: 1,
			AuditPath: [][]byte{[]byte("audit path")},
		}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Do(func(req *http.Request) {
			require.Equal(t, "hash", req.URL.Query().Get("hash"))
			require.Equal(t, "2", req.URL.Query().Get("tree_size"))
		}).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.GetProofByHash(context.Background(), "hash", 2)
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.GetProofByHash(context.Background(), "hash", 2)
		require.EqualError(t, err, "get proof by hash: error")
	})
}

func TestClient_GetEntries(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.GetEntriesResponse{
			Entries: []command.LeafEntry{{LeafInput: []byte(`leaf input`), ExtraData: []byte(`extra data`)}},
		}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Do(func(req *http.Request) {
			require.Equal(t, "1", req.URL.Query().Get("start"))
			require.Equal(t, "2", req.URL.Query().Get("end"))
		}).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.GetEntries(context.Background(), 1, 2)
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.GetEntries(context.Background(), 1, 2)
		require.EqualError(t, err, "get entries: error")
	})
}

func TestClient_GetEntryAndProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.GetEntryAndProofResponse{
			LeafInput: []byte(`leaf input`),
			ExtraData: []byte(`extra data`),
			AuditPath: [][]byte{[]byte(`audit path`)},
		}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Do(func(req *http.Request) {
			require.Equal(t, "1", req.URL.Query().Get("leaf_index"))
			require.Equal(t, "2", req.URL.Query().Get("tree_size"))
		}).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.GetEntryAndProof(context.Background(), 1, 2)
		require.NoError(t, err)

		bytesResp, err := json.Marshal(resp)
		require.NoError(t, err)

		require.Equal(t, fakeResp, bytesResp)
	})

	t.Run("Error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := rest.ErrorResponse{Message: "error"}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusInternalServerError,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		_, err = client.GetEntryAndProof(context.Background(), 1, 2)
		require.EqualError(t, err, "get entry and proof: error")
	})
}
