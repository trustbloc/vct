/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// nolint: lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package startcmd_test . TrillianLogServer,TrillianAdminServer

package startcmd_test

import (
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/trustbloc/vct/cmd/vct/startcmd"
)

const (
	agentHostFlagName         = "api-host"
	kmsEndpointFlagName       = "kms-endpoint"
	logsFlagName              = "logs"
	devModeFlagName           = "dev-mode"
	issuersFlagName           = "issuers"
	datasourceNameFlagName    = "dsn"
	tlsSystemCertPoolFlagName = "tls-systemcertpool"
	tlsCACertsFlagName        = "tls-cacerts"
	timeoutFlagName           = "timeout"
	syncTimeoutFlagName       = "sync-timeout"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler, certFile, keyFile string) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd, err := startcmd.Cmd(&mockServer{})
	require.NoError(t, err)

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Starts vct service", startCmd.Short)
	require.Equal(t, "Starts verifiable credentials transparency service", startCmd.Long)
}

func TestBuildKMSURL(t *testing.T) {
	require.Equal(t, startcmd.BuildKMSURL("https://kms.com", "/keys"), "https://kms.com/keys")
	require.Equal(t, startcmd.BuildKMSURL("oops", "https://kms.com/keys"), "https://kms.com/keys")
}

func TestCmd(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		lis, err := net.Listen("tcp", "localhost:50051")
		require.NoError(t, err)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		logServer := NewMockTrillianLogServer(ctrl)
		logServer.EXPECT().InitLog(gomock.Any(), gomock.Any()).Return(&trillian.InitLogResponse{}, nil)

		adminServer := NewMockTrillianAdminServer(ctrl)
		adminServer.EXPECT().CreateTree(gomock.Any(), gomock.Any()).Return(&trillian.Tree{}, nil)

		s := grpc.NewServer()

		trillian.RegisterTrillianLogServer(s, logServer)
		trillian.RegisterTrillianAdminServer(s, adminServer)

		go func() {
			require.NoError(t, s.Serve(lis))
		}()

		args := []string{
			"--" + agentHostFlagName, "",
			"--" + logsFlagName, "maple2021:rw@localhost:50051",
		}
		startCmd.SetArgs(args)
		require.NoError(t, startCmd.Execute())
	})

	t.Run("wrong dev mode flag", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, "",
			"--" + logsFlagName, "maple2021:rw@localhost:50051",
			"--" + devModeFlagName, "wrong",
		}
		startCmd.SetArgs(args)
		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "dev mode is not a bool")
	})

	t.Run("No logs", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, "",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "nor VCT_LOGS (environment variable) have been set")
	})

	t.Run("Create tree (unavailable)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, "",
			"--" + issuersFlagName, "maple2021@issuer",
			"--" + logsFlagName, "maple2021:rw@https://vct.example.com",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "create and init tree: init config value for \"tree-log-maple2021\"")
	})

	t.Run("KMS fails (web-key-store)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + kmsEndpointFlagName, "https://vct.example.com",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "get or init: init config value for \"web-key-store\"")
	})

	t.Run("Wrong cert pool flag (TLS)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + tlsSystemCertPoolFlagName, "invalid",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()

		require.Contains(t, err.Error(), "get TLS: parse cert pool")
	})

	t.Run("Unsupported driver (DSN)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem1://test",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported storage driver: mem1")
	})

	t.Run("Invalid URL (DSN)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid dbURL mem")
	})

	t.Run("Bad timeout", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + timeoutFlagName, "w1",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout is not a number")
	})

	t.Run("Bad sync-timeout", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + syncTimeoutFlagName, "w1",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout is not a number")
	})

	t.Run("Bad timeout (ENV)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)
		require.NoError(t, os.Setenv("VCT_TIMEOUT", "w1"))
		defer func() { require.NoError(t, os.Unsetenv("VCT_TIMEOUT")) }()

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout is not a number")
	})

	t.Run("Bad sync timeout (ENV)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)
		require.NoError(t, os.Setenv("VCT_SYNC_TIMEOUT", "w1"))
		defer func() { require.NoError(t, os.Unsetenv("VCT_SYNC_TIMEOUT")) }()

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout is not a number")
	})

	t.Run("No cert (TLS)", func(t *testing.T) {
		startCmd, err := startcmd.Cmd(&mockServer{})
		require.NoError(t, err)

		args := []string{
			"--" + agentHostFlagName, ":98989",
			"--" + logsFlagName, "11111:rw@https://vct.example.com",
			"--" + datasourceNameFlagName, "mem://test",
			"--" + tlsCACertsFlagName, "invalid",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "get cert pool: failed to read cert: open invalid")
	})
}
