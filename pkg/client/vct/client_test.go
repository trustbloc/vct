/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -self_package mocks -package vct_test . HTTPClient

package vct_test

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/stretchr/testify/require"

	vctldcontext "github.com/trustbloc/vct/internal/pkg/ldcontext"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
	"github.com/trustbloc/vct/pkg/controller/rest"
)

const endpoint = "https://example.com"

//go:embed testdata/bachelor_degree.json
var vcBachelorDegree []byte // nolint: gochecknoglobals

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

func TestClient_Webfinger(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		expected := command.WebFingerResponse{
			Subject: "https://vct.com/maple2021",
			Properties: map[string]interface{}{
				"https://trustbloc.dev/ns/public-key": "cHVibGljIGtleQ==",
			},
			Links: []command.WebFingerLink{{
				Rel:  "self",
				Href: "https://vct.com/maple2021",
			}},
		}

		fakeResp, err := json.Marshal(expected)
		require.NoError(t, err)

		httpClient := NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
			Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
			StatusCode: http.StatusOK,
		}, nil)

		client := vct.New(endpoint, vct.WithHTTPClient(httpClient))
		resp, err := client.Webfinger(context.Background())
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
		_, err = client.Webfinger(context.Background())
		require.EqualError(t, err, "webfinger: error")
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

var simpleVC = &verifiable.Credential{ // nolint: gochecknoglobals // global vc
	Context: []string{"https://www.w3.org/2018/credentials/v1"},
	Subject: "did:key:123",
	Issuer:  verifiable.Issuer{ID: "did:key:123"},
	Issued: func() *util.TimeWrapper {
		res := &util.TimeWrapper{}

		json.Unmarshal([]byte("\"2020-03-10T04:24:12.164Z\""), &res) // nolint: errcheck, gosec

		return res
	}(),
	Types:  []string{"VerifiableCredential"},
	Proofs: []verifiable.Proof{{}, {}},
}

func TestCalculateLeafHash(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		hash, err := vct.CalculateLeafHash(12345, simpleVC)
		require.NoError(t, err)
		require.Equal(t, "IamzE8Fm5W3ToLgZWlqVHPqgBLiBompVIyGLWDo0SP8=", hash)
	})

	t.Run("Marshal credential", func(t *testing.T) {
		_, err := vct.CalculateLeafHash(12345, &verifiable.Credential{
			Subject: make(chan int),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal credential: json: error calling MarshalJSON")
	})
}

func TestVerifyVCTimestampSignature(t *testing.T) {
	bachelorDegree, err := verifiable.ParseCredential(vcBachelorDegree,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(getLoader(t)),
	)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		const signature = `{
		   "algorithm":{
			  "hash":"SHA256",
			  "signature":"ECDSA",
			  "type":"ECDSAP256IEEEP1363"
		   },
		   "signature":"l8NfxVChPH7fG4cId6iNIbgpbRzxov+rwozdL4r5lRNXGiOTy7iAn2+Zg84VwkJoeJWvLGyO2a3WZnQKtNu/Lg=="
		}`

		pubKey := []byte{
			4, 185, 70, 232, 62, 166, 17, 233, 172, 19, 143, 227, 170, 181, 184, 202, 177, 242, 247, 199, 73, 209,
			108, 207, 87, 26, 199, 162, 21, 140, 117, 0, 143, 48, 20, 118, 255, 221, 200, 185, 227, 42, 213, 124,
			156, 109, 160, 211, 29, 245, 44, 128, 46, 88, 117, 88, 240, 223, 241, 24, 209, 87, 214, 115, 101,
		}

		require.NoError(t, vct.VerifyVCTimestampSignature(
			[]byte(signature), pubKey, 1619006293939, bachelorDegree,
		))
	})

	t.Run("Unmarshal signature error", func(t *testing.T) {
		require.Contains(t, vct.VerifyVCTimestampSignature(
			[]byte(`[]`), []byte(`[]`), 1617977793917, bachelorDegree,
		).Error(), "unmarshal signature")
	})

	t.Run("Wrong public key", func(t *testing.T) {
		require.Contains(t, vct.VerifyVCTimestampSignature(
			[]byte(`{}`), []byte(`[]`), 1617977793917, bachelorDegree,
		).Error(), "pub key to handle: error")
	})

	t.Run("Marshal credential", func(t *testing.T) {
		require.Contains(t, vct.VerifyVCTimestampSignature(
			[]byte(`{}`), []byte(`[]`), 1617977793917, &verifiable.Credential{Subject: make(chan int)},
		).Error(), "marshal credential")
	})
}

type mockProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (m *mockProvider) JSONLDContextStore() ldstore.ContextStore {
	return m.ContextStore
}

func (m *mockProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return m.RemoteProviderStore
}

func getLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	p := &mockProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	documentLoader, err := ld.NewDocumentLoader(p, ld.WithExtraContexts(vctldcontext.MustGetAll()...))
	require.NoError(t, err)

	return documentLoader
}
