/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStandardFields(t *testing.T) {
	const module = "test_module"

	u1 := parseURL(t, "https://example1.com")

	t.Run("console error", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := New(module,
			WithStdErr(stdErr),
			WithFields(WithServiceName("myservice")),
		)

		logger.Error("Sample error", WithError(errors.New("some error")))

		require.Contains(t, stdErr.Buffer.String(), `Sample error	{"service": "myservice", "error": "some error"}`)
	})

	t.Run("json error", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := New(module,
			WithStdErr(stdErr), WithEncoding(JSON),
			WithFields(WithServiceName("myservice")),
		)

		logger.Error("Sample error", WithError(errors.New("some error")))

		l := unmarshalLogData(t, stdErr.Bytes())

		require.Equal(t, "myservice", l.Service)
		require.Equal(t, "test_module", l.Logger)
		require.Equal(t, "Sample error", l.Msg)
		require.Contains(t, l.Caller, "log/fields_test.go")
		require.Equal(t, "some error", l.Error)
		require.Equal(t, "error", l.Level)
	})

	t.Run("json fields", func(t *testing.T) {
		leaf := &mockObject{Field1: "leaf1", Field2: 32123}
		pubKey := &mockObject{Field1: "key1", Field2: 32432}

		stdOut := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithEncoding(JSON))

		logger.Info("Some message",
			WithServiceName("service1"), WithSize(1234), WithAddress(u1.String()),
			WithBackoff(time.Minute), WithServiceEndpoint(u1.String()), WithTreeID(1234),
			WithLeaf(leaf), WithStore("store1"), WithCommand("doit"),
			WithVerifiableCredential([]byte(`"id":"vc1"`)), WithSignature([]byte("my signature")),
			WithTimestamp(321232), WithPublicKey(pubKey),
		)

		t.Logf(stdOut.String())
		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, `service1`, l.Service)
		require.Equal(t, 1234, l.Size)
		require.Equal(t, u1.String(), l.Address)
		require.Equal(t, "1m0s", l.Backoff)
		require.Equal(t, u1.String(), l.ServiceEndpoint)
		require.Equal(t, 1234, l.TreeID)
		require.Equal(t, leaf, l.Leaf)
		require.Equal(t, "store1", l.Store)
		require.Equal(t, "doit", l.Command)
		require.Equal(t, `"id":"vc1"`, l.VerifiableCredential)
		require.Equal(t, "my signature", l.Signature)
		require.Equal(t, 321232, l.Timestamp)
		require.Equal(t, pubKey, l.PublicKey)
	})
}

type mockObject struct {
	Field1 string
	Field2 int
}

type logData struct {
	Level  string `json:"level"`
	Time   string `json:"time"`
	Logger string `json:"logger"`
	Caller string `json:"caller"`
	Msg    string `json:"msg"`
	Error  string `json:"error"`

	Service              string      `json:"service"`
	Size                 int         `json:"size"`
	Address              string      `json:"address"`
	Backoff              string      `json:"backoff"`
	ServiceEndpoint      string      `json:"serviceEndpoint"`
	TreeID               int         `json:"treeID"`
	Leaf                 *mockObject `json:"leaf"`
	Store                string      `json:"store"`
	Command              string      `json:"command"`
	VerifiableCredential string      `json:"vc"`
	Signature            string      `json:"signature"`
	Timestamp            int         `json:"timestamp"`
	PublicKey            *mockObject `json:"publicKey"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}
