/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package main Verifiable Credential Transparency Server.
//
//
// Terms Of Service:
//
//
//     Schemes: http
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//     Host: localhost:5678
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/spf13/cobra"

	"github.com/trustbloc/vct/cmd/vct/startcmd"
)

var logger = log.New("vct")

// This is an application which starts vct service.
func main() {
	rootCmd := &cobra.Command{
		Use: "vct",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	startCmd, err := startcmd.Cmd(&startcmd.HTTPServer{})
	if err != nil {
		logger.Fatalf(err.Error())
	}

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("failed to run vct: %v", err)
	}
}
