/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler, certFile, keyFile string) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd, err := Cmd(&mockServer{})
	require.NoError(t, err)

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Starts vct service", startCmd.Short)
	require.Equal(t, "Starts verifiable credentials transparency service", startCmd.Long)
}

func TestCmd(t *testing.T) {
	t.Run("No api-host", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		startCmd.SetArgs(nil)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "api-host (command line flag) nor VCT_API_HOST (environment variable) have been set")
	})

	t.Run("No log-id", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, "",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "log-id (command line flag) nor VCT_LOG_ID (environment variable) have been set")
	})

	t.Run("No log-id is not valid", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, "",
			"--" + logIDFlagName, "oops",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "log ID is not a number")
	})

	t.Run("No log-endpoint", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, "",
			"--" + logIDFlagName, "11111",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "log-endpoint (command line flag) nor VCT_LOG_ENDPOINT (environment variable) have been set") // nolint: lll
	})

	t.Run("Success", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
		}
		startCmd.SetArgs(args)

		require.Nil(t, startCmd.Execute())
	})

	t.Run("KMS fails", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + kmsStoreEndpointFlagName, "http://vct.example.com",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "create kid: create: posting Create key failed")
	})

	t.Run("Create command (supported key)", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + keyTypeFlagName, "BLS12381G2",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "create command instance: key type BLS12381G2 is not supported")
	})

	t.Run("Key type unrecognized", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + keyTypeFlagName, "unknown",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "key type 'unknown' unrecognized")
	})

	t.Run("Wrong cert pool flag (TLS)", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + tlsSystemCertPoolFlagName, "invalid",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "get TLS (key-type or VCT_KEY_TYPE): parse cert pool")
	})

	t.Run("Unsupported driver (DSN)", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + datasourceNameFlagName, "mem1://test",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported storage driver: mem1")
	})

	t.Run("Invalid URL (DSN)", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + datasourceNameFlagName, "mem",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid dbURL mem")
	})

	t.Run("Bad timeout (DSN)", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + datasourceTimeoutFlagName, "w1",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout is not a number")
	})

	t.Run("No cert (TLS)", func(t *testing.T) {
		startCmd, err := Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logIDFlagName, "11111",
			"--" + logEndpointFlagName, "http://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + tlsCACertsFlagName, "invalid",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "get cert pool: failed to read cert: open invalid")
	})
}
